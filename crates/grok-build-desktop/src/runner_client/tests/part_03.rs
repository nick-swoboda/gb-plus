    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps initialization, command construction, pre-write refusal, and negative ledger assertions in one proof"
    )]
    fn generic_v11_send_effect_rejects_command_before_any_ledger_write() {
        let (harness, mut ledger) = TestHarness::new("legacy-send-effect-command");
        let exchange_count = Rc::new(Cell::new(0));
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("legacy-send-effect-command"),
            transport_with_exchange_count(
                unique_nonce("legacy-send-effect-command"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize legacy-command refusal client");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let command = CommandSpec {
            program: "true".into(),
            arguments: Vec::new(),
            working_directory: PathBuf::new(),
        };
        let request_bytes = serde_json::to_vec(&command).expect("encode exact command");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: Digest::sha256(b"legacy send-effect command")
                .as_str()
                .to_owned(),
            idempotency_key: "key-legacy-send-effect-command".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(harness.worker_lease.clone()),
            causation_event_id: None,
            correlation_id: "correlation-legacy-send-effect-command".into(),
            kind: EffectKind::RunCommand,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: harness.policy.contract().policy_hash.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            created_at_unix_ms: client.session().registered_at_unix_ms + 1,
        };
        let proposed = proposal(
            &intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next legacy-command proposal sequence"),
        );
        let capture_intent = fresh_command_output_capture_intent(
            &intent,
            &client.launch,
            &client.session,
            &harness.policy,
        )
        .expect("construct command capture intent without ledger admission");
        let store = CapabilityCommandOutputStore::open(&harness.private_state)
            .expect("open private command store");
        let dispatch_claim_id =
            grok_build_core::current_final_verification_dispatch_claim_id(&intent.effect_id)
                .expect("derive legacy-command dispatch claim");
        let acquired = store
            .reserve_anchored_capture(
                &capture_intent,
                &dispatch_claim_id,
                intent.created_at_unix_ms,
            )
            .expect("reserve request-only command capture")
            .into_acquired_anchor_for_handoff()
            .expect("synchronize request-only command capture");
        let wire_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired)
            .expect("construct exact wire capture");

        let failure = expect_effect_session_failure(
            client.send_effect(
                &mut ledger,
                &intent,
                &request_bytes,
                &proposed,
                RunnerRequest::WorkerRunCommand {
                    command: WireCommandSpec {
                        program: command.program,
                        arguments: command.arguments,
                        working_directory: String::new(),
                    },
                    output_capture: wire_capture,
                },
            ),
            "generic v11 command must fail before durable admission",
        );
        assert!(matches!(
            failure.error(),
            RunnerClientError::InvalidLifecycle(message)
                if message.contains("before any durable intent or claim write")
        ));
        assert_eq!(
            exchange_count.get(),
            1,
            "only initialization may cross transport"
        );
        assert!(matches!(
            ledger.load_effect(&intent.effect_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert!(
            ledger
                .load_command_output_capture_for_effect(&intent.effect_id)
                .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test keeps exact Verifying admission, v12 transport, claim authority, response custody, and durable readback contiguous"
    )]
    fn formal_check_claim_uses_no_running_boundary_and_exact_v12_exchange() {
        let command = CommandSpec {
            program: "true".into(),
            arguments: Vec::new(),
            working_directory: PathBuf::new(),
        };
        let (harness, mut ledger) = TestHarness::new_with_acceptance(
            "formal-check-zero-exchange",
            AcceptanceKind::Automated(command.clone()),
        );
        let exchange_count = Rc::new(Cell::new(0));
        let command_domain_backend =
            match ordinary_cleanup_backend(RunnerSessionPurpose::TaskWorker)
                .expect("formal-check compile target has an admitted ordinary backend")
            {
                WorkerCleanupBackend::MacOsDedicatedIdentity => {
                    RunnerCommandDomainCleanupBackend::MacOsDedicatedIdentity
                }
                WorkerCleanupBackend::LinuxCgroupV2 => {
                    RunnerCommandDomainCleanupBackend::LinuxCgroupV2
                }
                WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                    panic!("task formal checks cannot use the trusted-applier cleanup backend")
                }
            };
        let wire_backend = WireCommandBackendIdentity {
            command_domain_backend,
            backend_id: "formal-check-v12-native-contract-proof-box".into(),
            implementation_digest: Digest::sha256(b"formal-check-v12-native-contract-proof-box/v1"),
        };
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("formal-check-zero-exchange"),
            transport_with_clean_command_v12(
                unique_nonce("formal-check-zero-exchange"),
                harness.identity(),
                harness.private_state.clone(),
                wire_backend,
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize formal-check worker");
        let running = client
            .task_attempt_running_boundary()
            .expect("worker entered Running")
            .clone();
        let result_snapshot = Digest::sha256(b"formal-check sealed snapshot");
        let change_set = ChangeSet {
            change_set_id: "change-formal-check-zero-exchange".into(),
            base_snapshot: harness.base_snapshot.clone(),
            result_snapshot: result_snapshot.clone(),
            operations: vec![FileOperation::Create {
                path: PathBuf::from("src/formal.rs"),
                result_hash: Digest::sha256(b"formal"),
            }],
        };
        let phase_time = client.session().registered_at_unix_ms + 10;
        ledger
            .persist_workspace_snapshot(
                &harness.sprint_id,
                &WorkspaceSnapshot {
                    snapshot_id: result_snapshot.clone(),
                    grant_hash: harness.authority.contract().grant_hash.clone(),
                    created_at_unix_ms: phase_time - 1,
                },
            )
            .expect("persist formal-check result snapshot");
        ledger
            .persist_change_set(&harness.sprint_id, &change_set)
            .expect("persist formal-check change set");
        let verifying_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&harness.sprint_id)
                .expect("next Verifying event sequence"),
            event_id: "event-formal-check-zero-exchange-verifying".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            causation_id: Some(running.transition_event_id.clone()),
            correlation_id: "correlation-formal-check-zero-exchange".into(),
            policy_hash: Some(harness.policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: phase_time,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Verifying".into(),
            },
        };
        let verifying = TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "boundary-formal-check-zero-exchange".into(),
            attempt: running.attempt.clone(),
            runner_launch_id: client.launch.launch_id.clone(),
            runner_session_id: client.session.session_id.clone(),
            change_set_id: change_set.change_set_id,
            sealed_snapshot: result_snapshot.clone(),
            transition_event_id: verifying_event.event_id.clone(),
            terminal_non_cleanup_effects: Vec::new(),
            sealed_at_unix_ms: phase_time,
        };
        ledger
            .transition_task_attempt_to_verifying(&verifying, &verifying_event)
            .expect("enter exact Verifying phase");
        client.shadow_created = true;
        client.shadow_snapshot = Some(result_snapshot.clone());

        let request_bytes = serde_json::to_vec(&command).expect("encode formal command");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-formal-check-zero-exchange".into(),
            idempotency_key: "key-formal-check-zero-exchange".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(harness.worker_lease.clone()),
            causation_event_id: Some(verifying_event.event_id.clone()),
            correlation_id: "correlation-formal-check-zero-exchange".into(),
            kind: EffectKind::RunCommand,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: harness.policy.contract().policy_hash.clone(),
            input_snapshot: result_snapshot.clone(),
            created_at_unix_ms: phase_time + 1,
        };
        let proposal = proposal(
            &intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next formal proposal sequence"),
        );
        let admission = TaskAttemptFormalCheckAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: "admission-formal-check-zero-exchange".into(),
            attempt: running.attempt,
            criterion_ordinal: 0,
            criterion_id: "criterion-1".into(),
            effect_id: intent.effect_id.clone(),
            runner_session_id: client.session.session_id.clone(),
            sealed_snapshot: result_snapshot,
            command: command.clone(),
            admitted_at_unix_ms: intent.created_at_unix_ms,
        };
        assert_eq!(
            fs::metadata(&harness.private_state)
                .expect("inspect exact private output-store root")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the real command-output store root remains private"
        );
        assert_eq!(
            inspect_private_state_digest(&harness.private_state)
                .expect("reinspect exact private output-store authority"),
            client.session.private_state_digest
        );
        let output_capture_intent = fresh_command_output_capture_intent(
            &intent,
            &client.launch,
            &client.session,
            &harness.policy,
        )
        .expect("construct exact formal-check output-capture intent");
        let permit = match ledger
            .admit_task_attempt_formal_check_with_output_capture_for_dispatch(
                &admission,
                &intent,
                &proposal,
                &output_capture_intent,
            )
            .expect("admit exact formal check")
        {
            TaskFormalCheckDispatchAdmission::Fresh { permit, .. } => permit,
            TaskFormalCheckDispatchAdmission::Existing { .. } => {
                panic!("new formal check must retain fresh authority")
            }
        };
        let (_client, claimed) = client
            .send_precommitted_formal_check(&mut ledger, permit, &intent, &command)
            .expect("formal check crosses the exact policy-bound v12 command boundary");
        assert_eq!(
            exchange_count.get(),
            2,
            "initialization and one exact v12 formal command crossed transport"
        );
        let (exchange, request_frame, response_frame_digest, claimed_effect, authority) =
            claimed.into_parts();
        assert_eq!(
            request_frame,
            encode_request_frame_v12(&exchange.request)
                .expect("re-encode exact claimed v12 formal request")
        );
        assert_eq!(
            response_frame_digest,
            Digest::sha256(
                &encode_response_frame_v12(&exchange.response)
                    .expect("re-encode exact v12 formal response")
            )
        );
        assert_eq!(
            exchange.request.protocol_version,
            RUNNER_WIRE_PROTOCOL_VERSION_V12
        );
        assert_eq!(
            exchange.request.detector_policy(),
            &SensitiveOutputDetectionPolicyReferenceV1::core_v1()
        );
        assert!(matches!(
            &exchange.response.response,
            RunnerResponseV12::CommandCompleted { .. }
        ));
        exchange
            .response
            .validate_correlation(&exchange.request)
            .expect("revalidate exact formal-check response correlation");
        let claim = claimed_effect
            .dispatch_claim
            .as_ref()
            .expect("formal v12 exchange retains durable claim");
        assert!(claim.running_boundary_id.is_none());
        assert!(matches!(
            claim.authority,
            RunnerEffectRequestAuthority::TaskFormalCheck { .. }
        ));
        assert_eq!(
            ledger
                .load_effect(&intent.effect_id)
                .expect("reload formal claim"),
            claimed_effect
        );
        let capture = ledger
            .load_command_output_capture_for_effect(&intent.effect_id)
            .expect("reload exact claimed formal-check capture");
        assert_eq!(capture.intent, output_capture_intent);
        let acquired = capture
            .acquired
            .as_ref()
            .expect("claimed formal check retains its exact acquired anchor");
        assert_eq!(acquired.dispatch_claim_id, claim.dispatch_claim_id);
        assert_eq!(acquired.source.effect_id, claimed_effect.intent.effect_id);
        assert_eq!(acquired.source.request_digest, intent.request_digest);
        assert_eq!(
            acquired.private_state_digest,
            output_capture_intent.private_state_digest
        );
        assert!(capture.terminal.is_none());
        assert!(capture.reconciliation_obligation_closure.is_none());
        assert!(matches!(
            ledger
                .classify_command_output_capture_recovery(&capture.intent.capture_id)
                .expect("classify exact zero-byte capture authority"),
            grok_build_core::CommandOutputCaptureRecovery::ReconciliationRequired(ref stored)
                if stored == &capture
        ));
        let physical = CapabilityCommandOutputStore::open(&harness.private_state)
            .expect("reopen real private output store")
            .reopen_capture(&capture.intent.capture_id)
            .expect("reopen exact v12 terminal-prepared physical capture");
        assert_eq!(
            physical.state(),
            CommandOutputCaptureJournalStateV1::TerminalPrepared
        );
        assert_eq!(physical.acquired(), Some(acquired));
        drop(authority);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the lifecycle test keeps initialization, retained authority, read, shutdown, and cleanup assertions contiguous"
    )]
    fn happy_initialize_read_is_nonmutating_and_shutdown_is_non_authoritative() {
        let (harness, mut ledger) = TestHarness::new("happy");
        let before = fs::read(harness.workspace.join("README.md")).expect("read before");
        let nonce = unique_nonce("happy");
        let launch = harness.launch("happy");
        let prepared =
            prepare_launch(&harness.authority, &harness.policy, &launch).expect("prepare launch");
        let initialization = initialization_envelope(&launch, &prepared);
        let RunnerRequest::InitializeSession {
            sprint_spec,
            expected_sprint_spec_digest,
            ..
        } = &initialization.request
        else {
            unreachable!()
        };
        assert_eq!(**sprint_spec, harness.sprint_spec);
        assert_eq!(
            *expected_sprint_spec_digest,
            sprint_spec_digest(&harness.sprint_spec).expect("digest fake-contract sprint")
        );
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            launch,
            transport(
                nonce,
                harness.identity(),
                ScriptMode::Good,
                true,
                before.clone(),
            ),
        )
        .expect("initialize fake exact-framed runner");
        let running = client
            .task_attempt_running_boundary()
            .expect("worker launch atomically enters its exact attempt Running");
        assert_eq!(running.runner_launch_id, client.session().launch_id);
        assert_eq!(running.runner_session_id, client.session().session_id);
        assert_eq!(running.attempt.worker_lease, harness.worker_lease);
        let admitted = client
            .launch_cleanup_admission()
            .expect("ordinary client retains atomic cleanup admission")
            .clone();
        assert_eq!(admitted.launch, client.launch);
        assert_eq!(
            admitted.cleanup_request.platform_backend,
            ordinary_cleanup_backend(client.launch.purpose).expect("test backend")
        );
        assert!(client.expected_platform_launch_binding().is_some());
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let idempotency_key = "key-read-happy";
        let request_bytes =
            provider_read_request_bytes(&harness, idempotency_key, "README.md", 1_024);
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-read-happy".into(),
            idempotency_key: task_lease_provider_call_effect_key(
                &harness.worker_lease.lease_id,
                idempotency_key,
            ),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(harness.worker_lease.clone()),
            causation_event_id: None,
            correlation_id: "correlation-read-happy".into(),
            kind: EffectKind::ReadRelativeFile,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: harness.policy.contract().policy_hash.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            created_at_unix_ms: client.session().registered_at_unix_ms + 1,
        };
        let event = proposal(
            &intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next proposal sequence"),
        );
        let (client, exchange) = client
            .send_effect(
                &mut ledger,
                &intent,
                &request_bytes,
                &event,
                RunnerRequest::WorkerReadFile {
                    path: "README.md".into(),
                    max_bytes: 1_024,
                },
            )
            .expect("send durable read");
        assert_eq!(
            exchange
                .exchange()
                .request
                .effect
                .as_ref()
                .expect("worker wire effect")
                .worker_lease,
            Some(harness.worker_lease.clone())
        );
        assert!(matches!(
            exchange.exchange().response.response,
            RunnerResponse::FileRead { ref bytes, .. } if bytes == &before
        ));
        assert_eq!(
            fs::read(harness.workspace.join("README.md")).expect("read after"),
            before
        );
        let cleanup = client.shutdown().expect("strict shutdown exchange");
        assert_eq!(
            cleanup
                .launch_cleanup_admission()
                .expect("shutdown retains exact cleanup admission"),
            &admitted
        );
        assert!(cleanup.expected_platform_launch_binding().is_some());
        assert!(matches!(
            cleanup.session_registration(),
            RunnerSessionRegistrationState::Registered(session)
                if session == cleanup.session().expect("registered cleanup session")
        ));
        assert!(cleanup.shutdown_prepared().is_some());
        assert!(matches!(
            cleanup.direct_child_outcome(),
            DirectChildOutcome::Exited { success: true, .. }
        ));
    }

    #[test]
    fn exact_held_launch_prepares_and_releases_once_before_session_registration() {
        let (harness, mut ledger) = TestHarness::new("native-exact-release");
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            transport(
                unique_nonce("native-exact-release"),
                harness.identity(),
                ScriptMode::Good,
                false,
                Vec::new(),
            ),
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        );
        let client = RunnerLifecycleClient::launch_with_native_service(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("native-exact-release"),
            Box::new(service),
        )
        .expect("exact held launch must initialize");
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 1);
        let admission = client
            .launch_cleanup_admission()
            .expect("ordinary client retains admission")
            .clone();
        let binding = client
            .expected_platform_launch_binding()
            .expect("ordinary client retains expected binding")
            .clone();
        let preparation = ledger
            .load_runner_launch_preparation(
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
            )
            .expect("reload exact preparation");
        assert_eq!(
            preparation.attempt.expected_platform_binding_digest,
            *binding.binding_digest()
        );
        assert!(matches!(
            preparation.outcome,
            Some(ref outcome)
                if outcome.disposition
                    == RunnerLaunchPreparationDisposition::HeldChildPrepared
        ));

        let retry_attempt = runner_launch_preparation_attempt(&admission, &binding)
            .expect("derive exact retry IDs");
        let retry_callback_count = Cell::new(0_u64);
        assert!(
            ledger
                .with_runner_launch_preparation_claim(&admission, &retry_attempt, |_| {
                    retry_callback_count.set(retry_callback_count.get() + 1);
                    RunnerLaunchPreparationOutcome {
                        disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                        native_evidence_bytes: b"forbidden-second-preparation".to_vec(),
                        finished_at_unix_ms: retry_attempt.claimed_at_unix_ms,
                    }
                },)
                .is_err()
        );
        assert_eq!(retry_callback_count.get(), 0);
        assert_eq!(release_count.get(), 1);
        client
            .shutdown()
            .expect("shutdown exact released transport");
    }

    #[test]
    fn refused_and_ambiguous_preparation_never_release_or_register_and_never_retry() {
        for (label, disposition) in [
            (
                "native-refused",
                RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
            ),
            (
                "native-uncertain",
                RunnerLaunchPreparationDisposition::NativeEffectUncertain,
            ),
        ] {
            let (harness, mut ledger) = TestHarness::new(label);
            let prepare_count = Rc::new(Cell::new(0));
            let release_count = Rc::new(Cell::new(0));
            let service = AdversarialNativeLaunchService::new(
                disposition,
                NativeReleaseMutation::Exact,
                forbidden_native_prepare_spawn,
                Rc::clone(&prepare_count),
                Rc::clone(&release_count),
            );
            let failure = expect_launch_failure(
                RunnerLifecycleClient::launch_with_native_service(
                    &mut ledger,
                    &harness.authority,
                    &harness.policy,
                    harness.launch(label),
                    Box::new(service),
                ),
                "non-prepared native launch must fail",
            );
            assert_eq!(prepare_count.get(), 1);
            assert_eq!(release_count.get(), 0);
            let cleanup = failure
                .into_cleanup_required()
                .expect("refusal or ambiguity retains cleanup-only reconciliation");
            assert!(cleanup.session().is_none());
            let expected_direct_child = match disposition {
                RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect => {
                    DirectChildOutcome::LaunchRefusedBeforeSpawn
                }
                RunnerLaunchPreparationDisposition::NativeEffectUncertain => {
                    DirectChildOutcome::NativeChildStateUnknown
                }
                RunnerLaunchPreparationDisposition::HeldChildPrepared => {
                    unreachable!("fixture covers only closed non-release dispositions")
                }
            };
            assert_eq!(cleanup.direct_child_outcome(), &expected_direct_child);
            let admission = cleanup
                .launch_cleanup_admission()
                .expect("cleanup retains exact admission")
                .clone();
            let binding = cleanup
                .expected_platform_launch_binding()
                .expect("cleanup retains exact expected binding")
                .clone();
            let preparation = ledger
                .load_runner_launch_preparation(
                    &admission.launch.sprint_id,
                    &admission.launch.launch_id,
                )
                .expect("reload closed preparation attempt");
            assert_eq!(
                preparation
                    .outcome
                    .as_ref()
                    .expect("service response was durably closed")
                    .disposition,
                disposition
            );
            let retry_attempt = runner_launch_preparation_attempt(&admission, &binding)
                .expect("derive deterministic retry attempt");
            let retry_callback_count = Cell::new(0_u64);
            assert!(
                ledger
                    .with_runner_launch_preparation_claim(&admission, &retry_attempt, |_| {
                        retry_callback_count.set(retry_callback_count.get() + 1);
                        RunnerLaunchPreparationOutcome {
                            disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                            native_evidence_bytes: b"forbidden-retry".to_vec(),
                            finished_at_unix_ms: retry_attempt.claimed_at_unix_ms,
                        }
                    },)
                    .is_err()
            );
            assert_eq!(retry_callback_count.get(), 0);
            assert_eq!(release_count.get(), 0);
            assert!(matches!(
                ledger.load_runner_session(
                    &admission.launch.sprint_id,
                    &admission.launch.session_id,
                ),
                Err(LedgerError::ArtifactNotFound {
                    entity: "runner session policy",
                    ..
                })
            ));
        }
    }

    #[test]
    fn postcommit_preparation_ambiguity_hands_off_cleanup_without_release_or_retry() {
        let (harness, mut ledger) = TestHarness::new("native-preparation-postcommit");
        let hardlink = harness
            .root
            .join("native-preparation-postcommit-link.sqlite3");
        let database = harness.database.clone();
        let preparation_hardlink = hardlink.clone();
        let scripted = transport_with_preparation_hook(
            unique_nonce("native-preparation-postcommit"),
            harness.identity(),
            move || {
                fs::hard_link(&database, &preparation_hardlink)
                    .expect("create native preparation hardening fault");
            },
        );
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            scripted,
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        );
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_with_native_service(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                harness.launch("native-preparation-postcommit"),
                Box::new(service),
            ),
            "ambiguous preparation outcome persistence must abort before release",
        );
        fs::remove_file(&hardlink).expect("remove preparation hardlink fault");
        assert!(matches!(
            failure.error(),
            RunnerClientError::Ledger(LedgerError::PostCommitStateUncertain {
                operation: "runner launch preparation outcome",
                ..
            })
        ));
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 0);
        let cleanup = failure
            .into_cleanup_required()
            .expect("ambiguous native effect requires cleanup-only reconciliation");
        assert!(cleanup.session().is_none());
        assert_eq!(
            cleanup.direct_child_outcome(),
            &DirectChildOutcome::NativeChildStateUnknown
        );
        let admission = cleanup
            .launch_cleanup_admission()
            .expect("ambiguity retains exact launch authority")
            .clone();
        let binding = cleanup
            .expected_platform_launch_binding()
            .expect("ambiguity retains exact expected binding")
            .clone();
        let retry_attempt = runner_launch_preparation_attempt(&admission, &binding)
            .expect("derive deterministic no-retry attempt");
        let retry_callback_count = Cell::new(0_u64);
        assert!(
            ledger
                .with_runner_launch_preparation_claim(&admission, &retry_attempt, |_| {
                    retry_callback_count.set(retry_callback_count.get() + 1);
                    RunnerLaunchPreparationOutcome {
                        disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                        native_evidence_bytes: b"forbidden-postcommit-retry".to_vec(),
                        finished_at_unix_ms: retry_attempt.claimed_at_unix_ms,
                    }
                },)
                .is_err()
        );
        assert_eq!(retry_callback_count.get(), 0);
        assert_eq!(release_count.get(), 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps durable preparation, injected readback ambiguity, move-only custody, and live-claim cleanup contiguous"
    )]
    fn transient_preparation_readback_failure_retains_reconcilable_committed_authority() {
        let label = "native-preparation-transient-readback";
        let (harness, mut ledger) = TestHarness::new(label);
        let mut request = harness.launch(label);
        request.role = RunnerRole::FinalVerifier;
        request.worker_id = None;
        request.worker_lease = None;
        let policy = read_only_policy(&harness, label);
        let mut prepared =
            prepare_launch(&harness.authority, &policy, &request).expect("prepare exact launch");
        let cleanup = prepare_ordinary_launch_cleanup(
            &ledger,
            &prepared.intent,
            &request.expected_base_snapshot,
        )
        .expect("prepare exact cleanup");
        let admission = ledger
            .admit_runner_launch_with_cleanup(
                &prepared.intent,
                &policy,
                &cleanup.intent,
                &cleanup.request_bytes,
                &cleanup.event,
            )
            .expect("admit exact launch and cleanup");
        let binding =
            PlatformLaunchBinding::try_from_admission(&admission, &harness.authority, &policy)
                .expect("construct exact platform binding");
        let attempt = runner_launch_preparation_attempt(&admission, &binding)
            .expect("derive deterministic preparation attempt");
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let mut service: Box<dyn NativeLaunchService> = Box::new(
            AdversarialNativeLaunchService::new(
                RunnerLaunchPreparationDisposition::HeldChildPrepared,
                NativeReleaseMutation::Exact,
                transport(
                    unique_nonce(label),
                    harness.identity(),
                    ScriptMode::Good,
                    false,
                    Vec::new(),
                ),
                Rc::clone(&prepare_count),
                Rc::clone(&release_count),
            )
            .with_cleanup_script(
                Rc::clone(&native_cleanup_count),
                ScriptedNativeCleanupMutation::Exact,
            ),
        );
        let mut proposed_outcome = None;
        let preparation = ledger
            .with_runner_launch_preparation_claim(&admission, &attempt, |claim| {
                let outcome =
                    prepare_held_child(service.as_mut(), claim, &binding, &mut prepared.executable);
                proposed_outcome = Some(outcome.clone());
                outcome
            })
            .expect("commit exact held-child preparation");
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 0);
        assert_eq!(preparation.attempt, attempt);
        assert_eq!(preparation.outcome.as_ref(), proposed_outcome.as_ref());

        let cleanup_authority = cleanup_authority_after_preparation_error(
            &admission,
            &attempt,
            proposed_outcome.as_ref(),
            &binding,
            Err(LedgerError::Io(io::Error::other(
                "injected transient preparation readback failure",
            ))),
        );
        assert!(cleanup_authority.preparation_readback_is_uncertain());
        let requested_at_unix_ms = native_cleanup_requested_at_unix_ms(&ledger, &admission);

        let crossed_cleanup_count = Rc::new(Cell::new(0));
        let crossed_authority = cleanup_authority_after_preparation_error(
            &admission,
            &attempt,
            None,
            &binding,
            Err(LedgerError::Io(io::Error::other(
                "injected crossed callback-state readback failure",
            ))),
        );
        let mut crossed_custody = ScriptedNativeCleanupCustody::new(
            crossed_authority,
            None,
            Rc::clone(&crossed_cleanup_count),
            ScriptedNativeCleanupMutation::Exact,
        );
        assert!(
            ledger
                .with_runner_launch_cleanup_exclusion(
                    &admission.launch.sprint_id,
                    &admission.launch.launch_id,
                    |claim| cleanup_runner_domain(
                        &mut crossed_custody,
                        claim,
                        requested_at_unix_ms,
                    ),
                )
                .is_err(),
            "an uncertain pre-callback state cannot cross a committed outcome"
        );
        assert_eq!(crossed_cleanup_count.get(), 0);

        let mut custody = service.into_cleanup_custody(cleanup_authority);
        let persisted = ledger
            .with_runner_launch_cleanup_exclusion(
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
                |claim| cleanup_runner_domain(custody.as_mut(), claim, requested_at_unix_ms),
            )
            .expect("live cleanup claim reconciles the uncertain readback to its exact attempt");

        assert_eq!(native_cleanup_count.get(), 1);
        assert_eq!(
            persisted
                .observation
                .as_ref()
                .expect("cleanup is durably terminal")
                .effect_id,
            admission.cleanup_effect.intent.effect_id
        );
        assert_eq!(
            ledger
                .load_runner_launch_preparation(
                    &admission.launch.sprint_id,
                    &admission.launch.launch_id,
                )
                .expect("preparation remains exact after cleanup"),
            preparation
        );
    }

    #[test]
    fn crossed_preparation_binding_refuses_before_native_service_callback() {
        let (harness, mut ledger) = TestHarness::new("native-crossed-preflight");
        let request = harness.launch("native-crossed-preflight");
        let mut prepared =
            prepare_launch(&harness.authority, &harness.policy, &request).expect("prepare launch");
        let cleanup = prepare_ordinary_launch_cleanup(
            &ledger,
            &prepared.intent,
            &request.expected_base_snapshot,
        )
        .expect("prepare cleanup");
        let admission = ledger
            .admit_runner_launch_with_cleanup(
                &prepared.intent,
                &harness.policy,
                &cleanup.intent,
                &cleanup.request_bytes,
                &cleanup.event,
            )
            .expect("admit exact preparation candidate");
        let binding = PlatformLaunchBinding::try_from_admission(
            &admission,
            &harness.authority,
            &harness.policy,
        )
        .expect("construct exact preparation binding");
        let attempt = runner_launch_preparation_attempt(&admission, &binding)
            .expect("derive exact preparation attempt");

        let (crossed_harness, mut crossed_ledger) =
            TestHarness::new("native-crossed-preflight-substitute");
        let crossed_request = crossed_harness.launch("native-crossed-preflight-substitute");
        let crossed_prepared = prepare_launch(
            &crossed_harness.authority,
            &crossed_harness.policy,
            &crossed_request,
        )
        .expect("prepare crossed launch");
        let crossed_cleanup = prepare_ordinary_launch_cleanup(
            &crossed_ledger,
            &crossed_prepared.intent,
            &crossed_request.expected_base_snapshot,
        )
        .expect("prepare crossed cleanup");
        let crossed_admission = crossed_ledger
            .admit_runner_launch_with_cleanup(
                &crossed_prepared.intent,
                &crossed_harness.policy,
                &crossed_cleanup.intent,
                &crossed_cleanup.request_bytes,
                &crossed_cleanup.event,
            )
            .expect("admit crossed launch");
        let crossed_binding = PlatformLaunchBinding::try_from_admission(
            &crossed_admission,
            &crossed_harness.authority,
            &crossed_harness.policy,
        )
        .expect("construct crossed binding");

        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let mut service: Box<dyn NativeLaunchService> =
            Box::new(AdversarialNativeLaunchService::new(
                RunnerLaunchPreparationDisposition::HeldChildPrepared,
                NativeReleaseMutation::Exact,
                forbidden_native_prepare_spawn,
                Rc::clone(&prepare_count),
                Rc::clone(&release_count),
            ));
        let preparation = ledger
            .with_runner_launch_preparation_claim(&admission, &attempt, |claim| {
                let outcome = prepare_held_child(
                    service.as_mut(),
                    claim,
                    &crossed_binding,
                    &mut prepared.executable,
                );
                let canonical_refusal =
                    grok_build_runner::encode_native_launch_preparation_preflight_refusal(
                        claim,
                        b"crossed-live-claim-platform-binding",
                        claim.attempt().claimed_at_unix_ms,
                    )
                    .expect("encode canonical pre-effect refusal");
                assert_eq!(outcome, canonical_refusal);
                outcome
            })
            .expect("persist canonical pre-effect refusal");
        assert_eq!(prepare_count.get(), 0);
        assert_eq!(release_count.get(), 0);
        assert_eq!(
            preparation
                .outcome
                .expect("preflight refusal is durable")
                .disposition,
            RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect
        );
    }

    #[test]
    fn stale_cleanup_wins_before_preparation_and_service_callback_never_runs() {
        let (harness, mut ledger) = TestHarness::new("native-stale-cleanup");
        let mut request = harness.launch("native-stale-cleanup");
        request.role = RunnerRole::FinalVerifier;
        request.worker_id = None;
        request.worker_lease = None;
        let policy = read_only_policy(&harness, "native-stale-cleanup");
        let mut prepared =
            prepare_launch(&harness.authority, &policy, &request).expect("prepare launch");
        let cleanup = prepare_ordinary_launch_cleanup(
            &ledger,
            &prepared.intent,
            &request.expected_base_snapshot,
        )
        .expect("prepare cleanup");
        let admission = ledger
            .admit_runner_launch_with_cleanup(
                &prepared.intent,
                &policy,
                &cleanup.intent,
                &cleanup.request_bytes,
                &cleanup.event,
            )
            .expect("admit exact stale candidate");
        let binding =
            PlatformLaunchBinding::try_from_admission(&admission, &harness.authority, &policy)
                .expect("construct expected binding");
        terminalize_pre_spawn_cleanup(&mut ledger, &admission);

        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            forbidden_native_prepare_spawn,
            Rc::clone(&prepare_count),
            Rc::clone(&release_count),
        );
        let failure = match prepare_and_release_ordinary_launch(
            &mut ledger,
            &admission,
            &binding,
            &request.expected_base_snapshot,
            &mut prepared.executable,
            Box::new(service),
        ) {
            Err(failure) => failure,
            Ok(outcome) => {
                drop(outcome.process);
                panic!("stale cleanup must make native preparation impossible")
            }
        };
        assert_eq!(prepare_count.get(), 0);
        assert_eq!(release_count.get(), 0);
        assert!(!failure.cleanup_required);
        assert!(matches!(
            failure.direct_child,
            DirectChildOutcome::LaunchRefusedBeforeSpawn
        ));
        assert!(
            ledger
                .load_runner_launch_preparation(
                    &admission.launch.sprint_id,
                    &admission.launch.launch_id
                )
                .is_err()
        );
    }

    #[test]
    fn cleanup_winning_after_preparation_prevents_service_release_callback() {
        let (harness, mut ledger) = TestHarness::new("native-cleanup-before-release");
        let mut request = harness.launch("native-cleanup-before-release");
        request.role = RunnerRole::FinalVerifier;
        request.worker_id = None;
        request.worker_lease = None;
        let policy = read_only_policy(&harness, "native-cleanup-before-release");
        let mut prepared =
            prepare_launch(&harness.authority, &policy, &request).expect("prepare launch");
        let cleanup = prepare_ordinary_launch_cleanup(
            &ledger,
            &prepared.intent,
            &request.expected_base_snapshot,
        )
        .expect("prepare cleanup");
        let admission = ledger
            .admit_runner_launch_with_cleanup(
                &prepared.intent,
                &policy,
                &cleanup.intent,
                &cleanup.request_bytes,
                &cleanup.event,
            )
            .expect("admit release-race launch");
        let binding =
            PlatformLaunchBinding::try_from_admission(&admission, &harness.authority, &policy)
                .expect("construct release-race binding");
        let attempt = runner_launch_preparation_attempt(&admission, &binding)
            .expect("derive release-race attempt");
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let mut service: Box<dyn NativeLaunchService> = Box::new(
            AdversarialNativeLaunchService::new(
                RunnerLaunchPreparationDisposition::HeldChildPrepared,
                NativeReleaseMutation::Exact,
                transport(
                    unique_nonce("native-cleanup-before-release"),
                    harness.identity(),
                    ScriptMode::Good,
                    false,
                    Vec::new(),
                ),
                Rc::clone(&prepare_count),
                Rc::clone(&release_count),
            )
            .with_cleanup_script(
                Rc::clone(&native_cleanup_count),
                ScriptedNativeCleanupMutation::Exact,
            ),
        );
        let preparation = ledger
            .with_runner_launch_preparation_claim(&admission, &attempt, |claim| {
                prepare_held_child(service.as_mut(), claim, &binding, &mut prepared.executable)
            })
            .expect("durably prepare held fake child");
        assert_eq!(prepare_count.get(), 1);
        terminalize_pre_spawn_cleanup(&mut ledger, &admission);

        let mut service = Some(service);
        let release =
            ledger.with_runner_launch_release_exclusion(&admission, &preparation, |claim| {
                release_held_child(
                    service
                        .take()
                        .expect("native release service is still retained"),
                    claim,
                    &binding,
                )
            });
        assert!(release.is_err());
        assert_eq!(release_count.get(), 0);
        let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
            &admission,
            Some(&preparation),
            &binding,
        );
        let cleanup_custody = service
            .take()
            .expect("pre-release exclusion failure preserves the service")
            .into_cleanup_custody(cleanup_authority.clone());
        assert_eq!(cleanup_custody.authority(), &cleanup_authority);
        assert_eq!(native_cleanup_count.get(), 0);
        assert_eq!(
            direct_child_after_preparation_claim_error(
                &ledger,
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
            ),
            DirectChildOutcome::NativeChildStateUnknown
        );
    }

    #[test]
    fn release_rejects_substituted_journal_binding_and_process_before_initialization() {
        for (label, mutation) in [
            (
                "native-release-journal",
                NativeReleaseMutation::SubstitutedJournal,
            ),
            (
                "native-release-binding",
                NativeReleaseMutation::SubstitutedBinding,
            ),
            (
                "native-release-process",
                NativeReleaseMutation::SubstitutedProcess,
            ),
        ] {
            let (harness, mut ledger) = TestHarness::new(label);
            let prepare_count = Rc::new(Cell::new(0));
            let release_count = Rc::new(Cell::new(0));
            let native_cleanup_count = Rc::new(Cell::new(0));
            let service = AdversarialNativeLaunchService::new(
                RunnerLaunchPreparationDisposition::HeldChildPrepared,
                mutation,
                transport(
                    unique_nonce(label),
                    harness.identity(),
                    ScriptMode::Good,
                    false,
                    Vec::new(),
                ),
                Rc::clone(&prepare_count),
                Rc::clone(&release_count),
            )
            .with_cleanup_script(
                Rc::clone(&native_cleanup_count),
                ScriptedNativeCleanupMutation::Exact,
            );
            let mut request = harness.launch(label);
            request.role = RunnerRole::FinalVerifier;
            request.worker_id = None;
            request.worker_lease = None;
            let policy = read_only_policy(&harness, label);
            let failure = expect_launch_failure(
                RunnerLifecycleClient::launch_with_native_service(
                    &mut ledger,
                    &harness.authority,
                    &policy,
                    request,
                    Box::new(service),
                ),
                "substituted native release must fail closed",
            );
            assert!(matches!(
                failure.error(),
                RunnerClientError::InvalidLifecycle(message)
                    if message.contains("native release substituted")
            ));
            assert_eq!(prepare_count.get(), 1);
            assert_eq!(release_count.get(), 1);
            let mut cleanup = failure
                .into_cleanup_required()
                .expect("release substitution requires cleanup reconciliation");
            assert!(cleanup.session().is_none());
            assert!(matches!(
                cleanup.direct_child_outcome(),
                DirectChildOutcome::Exited { success: true, .. }
            ));
            assert!(cleanup.expected_platform_launch_binding().is_some());
            assert!(cleanup.native_cleanup_custody.is_some());

            let admission = cleanup
                .launch_cleanup_admission()
                .expect("ordinary release retains cleanup admission")
                .clone();
            let requested_at_unix_ms = native_cleanup_requested_at_unix_ms(&ledger, &admission);
            let persisted = ledger
                .with_runner_launch_cleanup_exclusion(
                    &admission.launch.sprint_id,
                    &admission.launch.launch_id,
                    |claim| cleanup.native_cleanup_terminal(claim, requested_at_unix_ms),
                )
                .expect("retained release-substitution custody performs exact cleanup");
            assert_eq!(native_cleanup_count.get(), 1);
            assert_eq!(
                persisted
                    .observation
                    .as_ref()
                    .expect("cleanup observation is durable")
                    .effect_id,
                admission.cleanup_effect.intent.effect_id
            );
        }
    }

    #[test]
    fn native_cleanup_reconciles_once_and_persisted_replay_skips_the_service() {
        let label = "native-cleanup-exact-replay";
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
        let mut request = harness.launch(label);
        request.role = RunnerRole::FinalVerifier;
        request.worker_id = None;
        request.worker_lease = None;
        let policy = read_only_policy(&harness, label);
        let client = RunnerLifecycleClient::launch_with_native_service(
            &mut ledger,
            &harness.authority,
            &policy,
            request,
            Box::new(service),
        )
        .expect("launch exact native final-verifier session");
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 1);
        let mut cleanup = client.shutdown().expect("prepare exact native shutdown");
        let admission = cleanup
            .launch_cleanup_admission()
            .expect("ordinary shutdown retains cleanup admission")
            .clone();
        let requested_at_unix_ms = native_cleanup_requested_at_unix_ms(&ledger, &admission);

        let persisted = ledger
            .with_runner_launch_cleanup_exclusion(
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
                |claim| {
                    let first = cleanup.native_cleanup_terminal(claim, requested_at_unix_ms)?;
                    let reconciled =
                        cleanup.native_cleanup_terminal(claim, requested_at_unix_ms)?;
                    assert_eq!(first, reconciled);
                    Ok(reconciled)
                },
            )
            .expect("persist exact zero-survivor native cleanup");
        assert_eq!(native_cleanup_count.get(), 1);

        let replay_callback_invoked = Cell::new(false);
        let replay = ledger.with_runner_launch_cleanup_exclusion(
            &admission.launch.sprint_id,
            &admission.launch.launch_id,
            |claim| {
                replay_callback_invoked.set(true);
                cleanup.native_cleanup_terminal(claim, requested_at_unix_ms)
            },
        );
        assert!(replay.is_err());
        assert!(!replay_callback_invoked.get());
        assert_eq!(native_cleanup_count.get(), 1);
        assert_eq!(
            ledger
                .load_effect(&admission.cleanup_effect.intent.effect_id)
                .expect("read exact persisted cleanup"),
            persisted
        );
    }

    #[test]
    fn pre_preparation_cleanup_rejects_a_digest_substituted_custody_before_native_callback() {
        let label = "native-cleanup-pre-preparation-crossed-binding";
        let (harness, mut ledger) = TestHarness::new(label);
        let mut request = harness.launch(label);
        request.role = RunnerRole::FinalVerifier;
        request.worker_id = None;
        request.worker_lease = None;
        let policy = read_only_policy(&harness, label);
        let prepared = prepare_launch(&harness.authority, &policy, &request)
            .expect("prepare no-attempt launch");
        let cleanup = prepare_ordinary_launch_cleanup(
            &ledger,
            &prepared.intent,
            &request.expected_base_snapshot,
        )
        .expect("prepare no-attempt cleanup");
        let admission = ledger
            .admit_runner_launch_with_cleanup(
                &prepared.intent,
                &policy,
                &cleanup.intent,
                &cleanup.request_bytes,
                &cleanup.event,
            )
            .expect("admit no-attempt launch");
        let binding =
            PlatformLaunchBinding::try_from_admission(&admission, &harness.authority, &policy)
                .expect("construct exact no-attempt binding");
        let mut crossed =
            NativeLaunchCleanupAuthority::from_expected_state(&admission, None, &binding);
        crossed.expected_platform_binding_digest =
            Digest::sha256(b"crossed-pre-preparation-cleanup-binding");
        let native_cleanup_count = Rc::new(Cell::new(0));
        let custody = ScriptedNativeCleanupCustody::new(
            crossed,
            None,
            Rc::clone(&native_cleanup_count),
            ScriptedNativeCleanupMutation::Exact,
        );
        let mut cleanup_required = RunnerCleanupRequired {
            launch: admission.launch.clone(),
            launch_cleanup_admission: Some(Box::new(admission.clone())),
            platform_launch_binding: Some(Box::new(binding)),
            native_cleanup_custody: Some(Box::new(custody)),
            session_registration: RunnerSessionRegistrationState::NotRegistered,
            direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
            shutdown_prepared: None,
        };
        let requested_at_unix_ms = native_cleanup_requested_at_unix_ms(&ledger, &admission);

        let rejected = ledger.with_runner_launch_cleanup_exclusion(
            &admission.launch.sprint_id,
            &admission.launch.launch_id,
            |claim| cleanup_required.native_cleanup_terminal(claim, requested_at_unix_ms),
        );
        assert!(rejected.is_err());
        assert_eq!(native_cleanup_count.get(), 0);
        let pending = ledger
            .load_effect(&admission.cleanup_effect.intent.effect_id)
            .expect("crossed custody leaves cleanup pending");
        assert!(pending.observation.is_none());
        assert!(pending.evidence_bytes.is_none());
        assert!(pending.terminal_event.is_none());
    }

    #[test]
    fn invalid_native_cleanup_observation_never_writes_and_reconciles_without_a_second_native_call()
    {
        for (label, mutation) in [
            (
                "native-cleanup-crossed-observation",
                ScriptedNativeCleanupMutation::CrossedObservation,
            ),
            (
                "native-cleanup-survivors-remain",
                ScriptedNativeCleanupMutation::SurvivorsRemain,
            ),
        ] {
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
                prepare_count,
                release_count,
            )
            .with_cleanup_script(Rc::clone(&native_cleanup_count), mutation);
            let mut request = harness.launch(label);
            request.role = RunnerRole::FinalVerifier;
            request.worker_id = None;
            request.worker_lease = None;
            let policy = read_only_policy(&harness, label);
            let client = RunnerLifecycleClient::launch_with_native_service(
                &mut ledger,
                &harness.authority,
                &policy,
                request,
                Box::new(service),
            )
            .expect("launch adversarial cleanup final-verifier session");
            let mut cleanup = client.shutdown().expect("prepare adversarial shutdown");
            let admission = cleanup
                .launch_cleanup_admission()
                .expect("ordinary shutdown retains cleanup admission")
                .clone();
            let requested_at_unix_ms = native_cleanup_requested_at_unix_ms(&ledger, &admission);
            let callback_count = Cell::new(0_u64);

            for _ in 0..2 {
                let rejected = ledger.with_runner_launch_cleanup_exclusion(
                    &admission.launch.sprint_id,
                    &admission.launch.launch_id,
                    |claim| {
                        callback_count.set(callback_count.get() + 1);
                        cleanup.native_cleanup_terminal(claim, requested_at_unix_ms)
                    },
                );
                assert!(rejected.is_err());
            }
            assert_eq!(callback_count.get(), 2);
            assert_eq!(native_cleanup_count.get(), 1);
            let pending = ledger
                .load_effect(&admission.cleanup_effect.intent.effect_id)
                .expect("invalid cleanup leaves the admitted effect pending");
            assert!(pending.observation.is_none());
            assert!(pending.evidence_bytes.is_none());
            assert!(pending.terminal_event.is_none());
            assert_eq!(pending.finish_receipt, PersistedFinishReceipt::NotRequired);
        }
    }

    #[test]
    fn bad_binary_and_private_state_fail_before_spawn() {
        let (harness, mut ledger) = TestHarness::new("bad-preflight");
        let attempted = Cell::new(false);
        let mut bad_binary = harness.launch("bad-binary");
        bad_binary.runner_binary = harness.root.join("missing-runner");
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                bad_binary,
                |_, _| {
                    attempted.set(true);
                    unreachable!("preflight must reject before spawn")
                },
            ),
            "missing binary must fail",
        );
        assert!(!attempted.get());
        assert!(failure.into_cleanup_required().is_none());

        let attempted = Cell::new(false);
        let mut bad_state = harness.launch("bad-state");
        bad_state.private_state_root = harness.root.join("missing-private-state");
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                bad_state,
                |_, _| {
                    attempted.set(true);
                    unreachable!("preflight must reject before spawn")
                },
            ),
            "missing private state must fail",
        );
        assert!(!attempted.get());
        assert!(failure.into_cleanup_required().is_none());
    }

    #[test]
    fn sprint_substitution_fails_before_launch_persistence_or_spawn() {
        let (harness, mut ledger) = TestHarness::new("sprint-preflight");
        let mut assert_pre_persistence_refusal =
            |launch: RunnerClientLaunch, expected_message: &str| {
                let launch_id = launch.launch_id.clone();
                let attempted = Cell::new(false);
                let failure = expect_launch_failure(
                    RunnerLifecycleClient::launch_with_spawner(
                        &mut ledger,
                        &harness.authority,
                        &harness.policy,
                        launch,
                        |_, _| {
                            attempted.set(true);
                            unreachable!("sprint preflight must reject before spawn")
                        },
                    ),
                    "crossed sprint authority must fail",
                );
                assert!(!attempted.get());
                assert!(matches!(
                    failure.error(),
                    RunnerClientError::InvalidLifecycle(message)
                        if message.contains(expected_message)
                ));
                assert!(failure.into_cleanup_required().is_none());
                assert!(
                    ledger
                        .load_runner_launch_cleanup_admission(&harness.sprint_id, &launch_id)
                        .is_err(),
                    "preflight sprint refusal must not write a launch admission"
                );
            };

        let mut changed_objective = harness.launch("changed-objective");
        changed_objective.sprint_spec.objective = "substituted objective".into();
        assert_pre_persistence_refusal(changed_objective, "durable sprint contract");

        let mut crossed_outer_id = harness.launch("crossed-outer-id");
        crossed_outer_id.sprint_id = "sprint-substituted".into();
        assert_pre_persistence_refusal(crossed_outer_id, "differs from sprint");

        let mut crossed_grant = harness.launch("crossed-grant");
        crossed_grant.sprint_spec.workspace_grant.grant_id = "grant-substituted".into();
        assert_pre_persistence_refusal(crossed_grant, "durable sprint contract");

        let mut crossed_base = harness.launch("crossed-base");
        crossed_base.sprint_spec.base_snapshot = Digest::sha256(b"substituted base");
        assert_pre_persistence_refusal(crossed_base, "durable sprint contract");

        let mut crossed_role_input = harness.launch("crossed-role-input");
        crossed_role_input.expected_base_snapshot = Digest::sha256(b"substituted role input");
        assert_pre_persistence_refusal(crossed_role_input, "role input snapshot");

        let mut ordinary_applier_with_result_authority =
            harness.launch("ordinary-applier-result-authority");
        ordinary_applier_with_result_authority.role = RunnerRole::Applier;
        ordinary_applier_with_result_authority.worker_id = None;
        ordinary_applier_with_result_authority.worker_lease = None;
        ordinary_applier_with_result_authority.shadow_root = None;
        ordinary_applier_with_result_authority.expected_base_snapshot =
            Digest::sha256(b"unadmitted applied result");
        assert_pre_persistence_refusal(
            ordinary_applier_with_result_authority,
            "role input snapshot",
        );

        let mut crossed_origin = harness.launch("crossed-origin");
        crossed_origin.sprint_spec.provider.execution_origin = ExecutionOrigin::VendorManaged;
        assert_pre_persistence_refusal(crossed_origin, "durable sprint contract");

        let mut crossed_budget = harness.launch("crossed-budget");
        crossed_budget.sprint_spec.budget.max_duration_ms = 1;
        assert_pre_persistence_refusal(crossed_budget, "durable sprint contract");
    }

    #[test]
    fn dependent_worker_uses_contiguous_integration_head_not_planning_base() {
        let (harness, mut ledger) = TestHarness::new("dependent-worker-head");
        let result_snapshot = Digest::sha256(b"ordinal-zero-integration-result");
        ledger
            .persist_workspace_snapshot(
                &harness.sprint_id,
                &WorkspaceSnapshot {
                    snapshot_id: result_snapshot.clone(),
                    grant_hash: harness.authority.contract().grant_hash.clone(),
                    created_at_unix_ms: 1_050,
                },
            )
            .expect("persist dependent-worker integration result");
        let mut persisted = ledger
            .load_sprint(&harness.sprint_id)
            .expect("load exact sprint fixture");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "dependent-integration-effect".into(),
            idempotency_key: "dependent-integration-key".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(harness.worker_lease.clone()),
            causation_event_id: None,
            correlation_id: "dependent-integration-correlation".into(),
            kind: EffectKind::IntegrateChangeSet,
            request_digest: Digest::sha256(b"dependent-integration-request"),
            policy_hash: harness.policy.contract().policy_hash.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            created_at_unix_ms: 1_060,
        };
        let receipt = TaskIntegrationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "dependent-integration-receipt".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: "task-1".into(),
            worker_id: "worker-1".into(),
            worker_lease: Some(harness.worker_lease.clone()),
            worker_launch_id: "dependent-worker-launch".into(),
            worker_session_id: "dependent-worker-session".into(),
            worker_policy_hash: harness.policy.contract().policy_hash.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: "dependent-integration-observation".into(),
            change_set_id: "dependent-integration-change-set".into(),
            input_snapshot: harness.base_snapshot.clone(),
            result_snapshot: result_snapshot.clone(),
            task_verification_receipt_ids: Vec::new(),
            integration_ordinal: 0,
            integrated_at_unix_ms: 1_070,
        };
        receipt.validate().expect("valid ordinal-zero receipt");
        let proposed = proposal(&intent, 3);
        let evidence_bytes = serde_json::to_vec(&receipt).expect("encode integration receipt");
        let observed = observation(
            &intent,
            receipt.observation_id.clone(),
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            receipt.integrated_at_unix_ms,
        );
        let terminal = terminal_event_at_sequence(4, &intent, &proposed.event_id, &observed);
        persisted.effects.push(PersistedEffect {
            intent,
            request_bytes: b"dependent-integration-request".to_vec(),
            proposed_event: proposed,
            dispatch_claim: None,
            observation: Some(observed),
            evidence_bytes: Some(evidence_bytes),
            terminal_event: Some(terminal),
            mutation_artifact: PersistedMutationArtifact::NotRequired,
            finish_receipt: PersistedFinishReceipt::TaskIntegration(receipt),
        });

        let mut dependent = harness.launch("dependent-result");
        dependent.expected_base_snapshot = result_snapshot.clone();
        validate_durable_role_input(&ledger, &persisted, &dependent)
            .expect("dependent worker admits the exact ordinal-zero integration result");

        let mut predated_launch = dependent.clone();
        predated_launch.created_at_unix_ms = 1_049;
        assert!(matches!(
            validate_durable_role_input(&ledger, &persisted, &predated_launch),
            Err(RunnerClientError::InvalidLifecycle(message))
                if message.contains("postdates launch intent")
        ));

        dependent.expected_base_snapshot = harness.base_snapshot.clone();
        assert!(matches!(
            validate_durable_role_input(&ledger, &persisted, &dependent),
            Err(RunnerClientError::InvalidLifecycle(message))
                if message.contains("integration head")
        ));
        assert_ne!(result_snapshot, harness.base_snapshot);
    }

    #[test]
    fn non_utf8_authority_and_policy_scope_fail_before_wire_or_spawn() {
        let (harness, _ledger) = TestHarness::new("non-utf8");
        let non_utf8_workspace = PathBuf::from(OsString::from_vec(b"/workspace-\xff".to_vec()));
        let malformed_authority = WorkspaceGrant {
            grant_id: "grant-non-utf8".into(),
            canonical_root: non_utf8_workspace,
            permissions: WorkspacePermissions::read_only(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: Digest::sha256(b"malformed-authority"),
        };
        assert!(WireWorkspaceGrant::try_from(&malformed_authority).is_err());

        let non_utf8_scope = PathBuf::from(OsString::from_vec(b"src/\xfe".to_vec()));
        assert!(wire_scope(&PathScope::Relative(non_utf8_scope.clone())).is_err());
        assert!(
            ExecutionPolicyCompiler::compile(
                &harness.authority,
                ExecutionPolicyRequest {
                    policy_id: "policy-non-utf8".into(),
                    read_scopes: vec![PathScope::Workspace],
                    write_scopes: vec![PathScope::Relative(non_utf8_scope)],
                    environment: Vec::new(),
                    network: ExecutionNetwork::None,
                    mutation_mode: MutationMode::ShadowWorkspace,
                    resource_limits: ResourceLimits {
                        wall_time_ms: 1,
                        max_output_bytes: 1,
                        max_processes: 1,
                        max_memory_bytes: None,
                    },
                    approval_id: None,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn bad_receipt_and_eof_consume_launch_into_cleanup() {
        for (label, mode) in [
            ("bad-receipt", ScriptMode::BadReceipt),
            ("bad-sprint-receipt", ScriptMode::BadSprintReceipt),
            ("bad-role-input-receipt", ScriptMode::BadRoleInputReceipt),
            ("eof", ScriptMode::EofAt(0)),
        ] {
            let (harness, mut ledger) = TestHarness::new(label);
            let failure = expect_launch_failure(
                RunnerLifecycleClient::launch_with_spawner(
                    &mut ledger,
                    &harness.authority,
                    &harness.policy,
                    harness.launch(label),
                    transport(
                        unique_nonce(label),
                        harness.identity(),
                        mode,
                        false,
                        Vec::new(),
                    ),
                ),
                "adversarial initialization must fail",
            );
            let cleanup = failure
                .into_cleanup_required()
                .expect("spawned ambiguity requires cleanup");
            assert!(cleanup.session().is_none());
            assert!(matches!(
                cleanup.direct_child_outcome(),
                DirectChildOutcome::Exited { .. }
            ));
        }
    }

    #[test]
    fn runner_nonce_replay_is_rejected_across_sessions() {
        let replayed = unique_nonce("replay");
        let (first, mut first_ledger) = TestHarness::new("replay-first");
        let first_client = RunnerLifecycleClient::launch_with_spawner(
            &mut first_ledger,
            &first.authority,
            &first.policy,
            first.launch("replay-first"),
            transport(
                replayed.clone(),
                first.identity(),
                ScriptMode::Good,
                false,
                Vec::new(),
            ),
        )
        .expect("first nonce admission");
        first_client.shutdown().expect("first shutdown");

        let (second, mut second_ledger) = TestHarness::new("replay-second");
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_with_spawner(
                &mut second_ledger,
                &second.authority,
                &second.policy,
                second.launch("replay-second"),
                transport(
                    replayed,
                    second.identity(),
                    ScriptMode::Good,
                    false,
                    Vec::new(),
                ),
            ),
            "replayed nonce must fail closed",
        );
        assert!(matches!(
            failure.error(),
            RunnerClientError::InvalidLifecycle(message) if message.contains("already observed")
        ));
        assert!(failure.into_cleanup_required().is_some());
    }

    #[test]
    fn failed_spawn_occurs_only_after_durable_launch_intent() {
        let (harness, mut ledger) = TestHarness::new("spawn-failure");
        let launch = harness.launch("spawn-failure");
        let missing_after_preflight = harness.root.join("runner-disappeared-before-spawn");
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                launch,
                move |_, expected_binding| {
                    let error = Command::new(&missing_after_preflight)
                        .spawn()
                        .expect_err("injected spawn path must be absent");
                    Err(RunnerProcessSpawnError {
                        error,
                        direct_child: DirectChildOutcome::SpawnFailed,
                        platform_binding: expected_binding.cloned().map(Box::new),
                    })
                },
            ),
            "spawn must fail",
        );
        let cleanup = failure
            .into_cleanup_required()
            .expect("attempted spawn has cleanup obligation");
        assert!(matches!(
            cleanup.direct_child_outcome(),
            DirectChildOutcome::SpawnFailed
        ));
        let carried_admission = cleanup
            .launch_cleanup_admission()
            .expect("spawn failure carries exact atomic cleanup admission")
            .clone();
        drop(ledger);
        let reopened = EventLedger::open(&harness.database).expect("reopen durable ledger");
        assert_eq!(
            reopened
                .load_runner_launch_cleanup_admission(
                    &cleanup.launch().sprint_id,
                    &cleanup.launch().launch_id,
                )
                .expect("reload exact atomic cleanup admission"),
            carried_admission
        );
    }

    #[test]
    fn postcommit_launch_uncertainty_never_spawns_and_preserves_exact_admission() {
        let (harness, mut ledger) = TestHarness::new("launch-postcommit-uncertain");
        let hardlink = harness.root.join("launch-postcommit-hardlink.sqlite3");
        fs::hard_link(&harness.database, &hardlink)
            .expect("create launch post-commit hardening fault");
        let attempted = Cell::new(false);
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                harness.launch("launch-postcommit-uncertain"),
                |_, _| {
                    attempted.set(true);
                    unreachable!("uncertain atomic admission must never enter spawn")
                },
            ),
            "post-commit launch uncertainty must abort",
        );
        fs::remove_file(&hardlink).expect("remove launch hardlink fault");
        assert!(!attempted.get());
        assert!(matches!(
            failure.error(),
            RunnerClientError::Ledger(LedgerError::PostCommitStateUncertain {
                operation: "runner launch cleanup admission",
                ..
            })
        ));
        let cleanup = failure
            .into_cleanup_required()
            .expect("exact readback returns a no-spawn cleanup handoff");
        assert!(matches!(
            cleanup.direct_child_outcome(),
            DirectChildOutcome::LaunchRefusedBeforeSpawn
        ));
        assert!(
            cleanup.expected_platform_launch_binding().is_some(),
            "exact post-commit admission reconstructs immutable cleanup comparison state"
        );
        assert!(matches!(
            cleanup.session_registration(),
            RunnerSessionRegistrationState::NotRegistered
        ));
        let carried = cleanup
            .launch_cleanup_admission()
            .expect("uncertain commit readback retained exact authority");
        assert_eq!(
            ledger
                .load_runner_launch_cleanup_admission(
                    &cleanup.launch().sprint_id,
                    &cleanup.launch().launch_id,
                )
                .expect("reload exact post-commit admission"),
            *carried
        );
    }

    #[test]
    fn lifecycle_owner_restart_closes_sessionless_launch_and_exhausts_exact_attempt() {
        let (harness, mut ledger) = TestHarness::new("pre-session-restart-exhaustion");
        let admission = admit_sessionless_lifecycle_worker_launch(&harness, &mut ledger);
        let persisted = ledger
            .load_sprint(&harness.sprint_id)
            .expect("reload exact sprint");
        let task = persisted
            .graph
            .expect("fixture graph is attached")
            .tasks
            .into_iter()
            .next()
            .expect("fixture has one task");
        let attempt = ledger
            .load_task_attempt_history(&harness.sprint_id, &task.task_id)
            .expect("reload active attempt")
            .active_attempt()
            .expect("sessionless launch retains active attempt")
            .attempt
            .clone();
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            Box::new(ClaimDerivedPreSessionCleanupReopener {
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                cross_authority_before_cleanup: false,
            }),
        )
        .expect("construct restart cleanup owner");

        let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_pre_session_task_attempt(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonPreSessionTaskCleanup {
                sprint_spec: &harness.sprint_spec,
                task: &task,
                attempt: &attempt,
                authority: &harness.authority,
                policy: &harness.policy,
                input_snapshot: &harness.base_snapshot,
                requested_at_unix_ms: 1_300,
            },
        )
        .expect("atomically clean and exhaust exact sessionless launch");
        let crate::WalkingSkeletonPreSessionTaskCleanupOutcome::Completed(disposition) = outcome
        else {
            panic!("attempt limit one must produce exact AttemptsExhausted disposition");
        };
        let TaskAttemptDisposition::AttemptsExhausted(disposition) = *disposition else {
            panic!("attempt limit one must produce exact AttemptsExhausted disposition");
        };
        assert_eq!(disposition.metadata.attempt, attempt);
        assert_eq!(reopen_count.get(), 1);
        assert_eq!(cleanup_count.get(), 1);
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
        let preparation = ledger
            .load_runner_launch_preparation(&harness.sprint_id, &admission.launch.launch_id)
            .expect("reload durable refusal preparation");
        assert!(matches!(
            preparation.outcome,
            Some(RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
                ..
            })
        ));
        let history = ledger
            .load_task_attempt_history(&harness.sprint_id, &task.task_id)
            .expect("reload exhausted attempt history");
        assert_eq!(history.task_state, TaskState::Failed);
        assert!(history.active_attempt().is_none());
        assert!(matches!(
            history.attempts.last().and_then(|entry| entry.disposition.as_ref()),
            Some(TaskAttemptDisposition::AttemptsExhausted(exact))
                if exact == &disposition
        ));
        assert!(
            ledger
                .load_runner_session(&harness.sprint_id, &admission.launch.session_id)
                .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression proves first-call retention and exact same-claim retry without hiding either durable readback"
    )]
    fn lifecycle_owner_crossed_pre_session_authority_stops_before_native_cleanup_callback() {
        let (harness, mut ledger) = TestHarness::new("pre-session-crossed-authority");
        let admission = admit_sessionless_lifecycle_worker_launch(&harness, &mut ledger);
        let persisted = ledger
            .load_sprint(&harness.sprint_id)
            .expect("reload exact sprint");
        let task = persisted
            .graph
            .expect("fixture graph is attached")
            .tasks
            .into_iter()
            .next()
            .expect("fixture has one task");
        let attempt = ledger
            .load_task_attempt_history(&harness.sprint_id, &task.task_id)
            .expect("reload active attempt")
            .active_attempt()
            .expect("sessionless launch retains active attempt")
            .attempt
            .clone();
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let mut owner = DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            Box::new(ClaimDerivedPreSessionCleanupReopener {
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                cross_authority_before_cleanup: true,
            }),
        )
        .expect("construct crossed-authority cleanup owner");

        let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_pre_session_task_attempt(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonPreSessionTaskCleanup {
                sprint_spec: &harness.sprint_spec,
                task: &task,
                attempt: &attempt,
                authority: &harness.authority,
                policy: &harness.policy,
                input_snapshot: &harness.base_snapshot,
                requested_at_unix_ms: 1_300,
            },
        )
        .expect("crossed native authority returns cleanup-pending status");
        assert!(matches!(
            outcome,
            crate::WalkingSkeletonPreSessionTaskCleanupOutcome::CleanupRequired {
                ref attempt_id,
                ref launch_id,
                ..
            } if attempt_id == &attempt.attempt_id
                && launch_id == &admission.launch.launch_id
        ));
        assert_eq!(reopen_count.get(), 1);
        assert_eq!(
            cleanup_count.get(),
            0,
            "crossed authority must reject before the native cleanup callback"
        );
        let history = ledger
            .load_task_attempt_history(&harness.sprint_id, &task.task_id)
            .expect("reload still-open attempt");
        assert_eq!(history.task_state, TaskState::Leased);
        assert!(
            history
                .active_attempt()
                .is_some_and(|entry| entry.attempt == attempt && entry.disposition.is_none())
        );
        let cleanup_effect = ledger
            .load_effect(&admission.cleanup_effect.intent.effect_id)
            .expect("reload pending cleanup effect");
        assert!(cleanup_effect.observation.is_none());
        assert!(cleanup_effect.evidence_bytes.is_none());
        assert!(cleanup_effect.terminal_event.is_none());
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::CleanupRequired { cleanup, .. }
                if cleanup.has_native_cleanup_custody()
                    && cleanup.direct_child_outcome()
                        == &DirectChildOutcome::NativeChildStateUnknown
        ));

        let retry = crate::WalkingSkeletonRunnerLifecycle::cleanup_pre_session_task_attempt(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonPreSessionTaskCleanup {
                sprint_spec: &harness.sprint_spec,
                task: &task,
                attempt: &attempt,
                authority: &harness.authority,
                policy: &harness.policy,
                input_snapshot: &harness.base_snapshot,
                requested_at_unix_ms: 1_301,
            },
        )
        .expect("crossed custody remains retained on exact same-claim retry");
        assert!(matches!(
            retry,
            crate::WalkingSkeletonPreSessionTaskCleanupOutcome::CleanupRequired {
                ref attempt_id,
                ref launch_id,
                ..
            } if attempt_id == &attempt.attempt_id
                && launch_id == &admission.launch.launch_id
        ));
        assert_eq!(reopen_count.get(), 1, "same claim must not reopen");
        assert_eq!(
            cleanup_count.get(),
            0,
            "crossed custody must stay pre-native"
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::CleanupRequired { cleanup, .. }
                if cleanup.has_native_cleanup_custody()
        ));
    }

    #[test]
    fn lifecycle_owner_without_reopener_returns_exact_pre_session_cleanup_required() {
        let (harness, mut ledger) = TestHarness::new("pre-session-no-reopener");
        let admission = admit_sessionless_lifecycle_worker_launch(&harness, &mut ledger);
        let persisted = ledger
            .load_sprint(&harness.sprint_id)
            .expect("reload exact sprint");
        let task = persisted
            .graph
            .expect("fixture graph is attached")
            .tasks
            .into_iter()
            .next()
            .expect("fixture has one task");
        let attempt = ledger
            .load_task_attempt_history(&harness.sprint_id, &task.task_id)
            .expect("reload active attempt")
            .active_attempt()
            .expect("sessionless launch retains active attempt")
            .attempt
            .clone();
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct owner without cleanup reopener");

        let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_pre_session_task_attempt(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonPreSessionTaskCleanup {
                sprint_spec: &harness.sprint_spec,
                task: &task,
                attempt: &attempt,
                authority: &harness.authority,
                policy: &harness.policy,
                input_snapshot: &harness.base_snapshot,
                requested_at_unix_ms: 1_300,
            },
        )
        .expect("missing reopener is an exact cleanup-required stop");
        assert!(matches!(
            outcome,
            crate::WalkingSkeletonPreSessionTaskCleanupOutcome::CleanupRequired {
                ref attempt_id,
                ref launch_id,
                ref reason,
            } if attempt_id == &attempt.attempt_id
                && launch_id == &admission.launch.launch_id
                && reason.contains("no admitted cleanup-only native journal reopener")
        ));
        let preparation = ledger
            .load_runner_launch_preparation(&harness.sprint_id, &admission.launch.launch_id)
            .expect("refusal is durable before reporting missing cleanup authority");
        assert!(matches!(
            preparation.outcome,
            Some(RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
                ..
            })
        ));
        let history = ledger
            .load_task_attempt_history(&harness.sprint_id, &task.task_id)
            .expect("reload still-active attempt");
        assert_eq!(history.task_state, TaskState::Leased);
        assert!(history.active_attempt().is_some_and(|entry| {
            entry.attempt == attempt
                && entry.disposition.is_none()
                && matches!(
                    entry.lease_state,
                    grok_build_core::TaskAttemptLeaseState::Active
                )
        }));
        let cleanup_effect = ledger
            .load_effect(&admission.cleanup_effect.intent.effect_id)
            .expect("reload pending cleanup effect");
        assert!(cleanup_effect.observation.is_none());
        assert!(cleanup_effect.evidence_bytes.is_none());
        assert!(cleanup_effect.terminal_event.is_none());
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn postcommit_session_registration_exact_readback_aborts_as_registered() {
        let (harness, mut ledger) = TestHarness::new("session-postcommit-uncertain");
        let hardlink = harness.root.join("session-postcommit-hardlink.sqlite3");
        let spawn_hardlink = hardlink.clone();
        let database = harness.database.clone();
        let scripted = transport_with_first_exchange_hook(
            unique_nonce("session-postcommit-uncertain"),
            harness.identity(),
            move || {
                fs::hard_link(&database, &spawn_hardlink)
                    .expect("create session post-commit hardening fault");
            },
        );
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                harness.launch("session-postcommit-uncertain"),
                scripted,
            ),
            "post-commit session uncertainty must abort the initialized launch",
        );
        fs::remove_file(&hardlink).expect("remove session hardlink fault");
        assert!(matches!(
            failure.error(),
            RunnerClientError::Ledger(LedgerError::PostCommitStateUncertain {
                operation: "runner session registration",
                ..
            })
        ));
        let cleanup = failure
            .into_cleanup_required()
            .expect("initialized uncertainty always carries cleanup");
        let session = cleanup
            .session()
            .expect("exact readback classifies the candidate as registered");
        assert!(matches!(
            cleanup.session_registration(),
            RunnerSessionRegistrationState::Registered(registered) if registered == session
        ));
        assert_eq!(
            ledger
                .load_runner_session(&session.sprint_id, &session.session_id)
                .expect("reload exact registered session"),
            *session
        );
        assert!(cleanup.launch_cleanup_admission().is_some());
        assert!(cleanup.expected_platform_launch_binding().is_some());
    }

    #[test]
    fn spawn_boundary_rejects_existing_child_without_exact_platform_binding() {
        let (harness, mut ledger) = TestHarness::new("spawn-binding-missing");
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                harness.launch("spawn-binding-missing"),
                |_, expected_binding| {
                    assert!(expected_binding.is_some());
                    Err(RunnerProcessSpawnError {
                        error: io::Error::other("synthetic post-child launch failure"),
                        direct_child: DirectChildOutcome::Exited {
                            code: Some(1),
                            success: false,
                        },
                        platform_binding: None,
                    })
                },
            ),
            "a child outcome without the exact platform binding must fail closed",
        );
        assert!(matches!(
            failure.error(),
            RunnerClientError::InvalidLifecycle(message)
                if message.contains("exact expected platform launch state")
        ));
        let cleanup = failure
            .into_cleanup_required()
            .expect("durable admission survives substituted spawn output");
        assert!(matches!(
            cleanup.direct_child_outcome(),
            DirectChildOutcome::Exited {
                code: Some(1),
                success: false,
            }
        ));
        assert!(cleanup.launch_cleanup_admission().is_some());
        assert!(cleanup.expected_platform_launch_binding().is_some());
    }

    #[test]
    fn poll_deadline_eof_and_blocked_write_are_bounded() {
        let (mut reader, writer) = UnixStream::pair().expect("create EOF pair");
        set_nonblocking(&reader).expect("nonblocking reader");
        drop(writer);
        assert!(matches!(
            read_frame_until(&mut reader, Instant::now() + Duration::from_millis(100)),
            Err(RunnerClientError::Wire(WireProtocolError::TruncatedPrefix))
        ));

        let (primary, _primary_peer) = UnixStream::pair().expect("create pending primary pair");
        let (mut diagnostic, diagnostic_peer) =
            UnixStream::pair().expect("create diagnostic HUP pair");
        set_nonblocking(&primary).expect("nonblocking primary");
        set_nonblocking(&diagnostic).expect("nonblocking diagnostic");
        drop(diagnostic_peer);
        let mut diagnostics = Vec::new();
        let mut diagnostic_eof = false;
        let started = Instant::now();
        assert!(matches!(
            wait_for_fd_with_stderr(
                &primary,
                PollFlags::IN,
                &mut diagnostic,
                &mut diagnostics,
                &mut diagnostic_eof,
                started + Duration::from_millis(30),
            ),
            Err(error) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(diagnostic_eof);
        assert!(started.elapsed() < Duration::from_secs(1));

        let mut bounded_reader = io::Cursor::new(vec![b'x'; MAX_RUNNER_STDERR_BYTES + 1_024]);
        let mut retained = Vec::new();
        assert!(
            drain_runner_stderr(&mut bounded_reader, &mut retained)
                .expect("drain bounded diagnostic")
        );
        assert_eq!(retained.len(), MAX_RUNNER_STDERR_BYTES);

        let (mut writer, _reader) = UnixStream::pair().expect("create blocked pair");
        set_nonblocking(&writer).expect("nonblocking writer");
        let fill = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            match writer.write(&fill) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill peer buffer: {error}"),
            }
        }
        let started = Instant::now();
        assert!(matches!(
            write_all_until(
                &mut writer,
                b"blocked",
                started + Duration::from_millis(30)
            ),
            Err(RunnerClientError::Io(error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn retained_descriptor_streaming_digest_matches_contract_sha256_boundaries() {
        let unique = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let temporary = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let path = temporary.join(format!(
            "grok-build-runner-digest-{}-{unique}",
            std::process::id()
        ));
        for length in [1_usize, 19, 20, 63, 64, 65, 65_535, 65_536, 65_537] {
            let bytes: Vec<u8> = (0..length)
                .map(|index| u8::try_from(index % 251).expect("bounded fixture byte"))
                .collect();
            fs::write(&path, &bytes).expect("write digest fixture");
            let mut file = fs::File::open(&path).expect("open digest fixture");
            let (digest, header) = digest_retained_binary(
                &mut file,
                u64::try_from(length).expect("fixture length fits u64"),
            )
            .expect("stream retained descriptor digest");
            assert_eq!(digest, Digest::sha256(&bytes));
            let copied = length.min(header.len());
            assert_eq!(&header[..copied], &bytes[..copied]);
            assert_eq!(
                file.stream_position().expect("descriptor rewind"),
                0,
                "streaming digest must rewind the retained descriptor"
            );
        }
        fs::remove_file(path).expect("remove digest fixture");
    }

    #[test]
    fn defensive_drop_and_post_kill_observation_are_bounded() {
        let sleep = if Path::new("/bin/sleep").exists() {
            "/bin/sleep"
        } else {
            "/usr/bin/sleep"
        };
        let child = Command::new(sleep)
            .arg("10")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn direct sleep fixture");
        let process = RunnerProcess {
            child: Some(child),
            stdin: None,
            stdout: None,
            stderr: None,
            stderr_diagnostics: Vec::new(),
            stderr_eof: false,
        };
        let started = Instant::now();
        drop(process);
        assert!(started.elapsed() < PROCESS_KILL_GRACE + Duration::from_secs(1));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn real_descriptor_spawn_fails_closed_on_unsupported_targets() {
        let unique = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let temporary = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let root = temporary.join(format!(
            "grok-build-runner-descriptor-unsupported-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create descriptor fixture root");
        let fixture = root.join("descriptor-fixture");
        fs::write(&fixture, b"#!/bin/sh\nexit 0\n").expect("write descriptor fixture");
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o700))
            .expect("make descriptor fixture executable");

        let mut executable =
            RetainedRunnerExecutable::inspect(&fixture).expect("inspect retained fixture");
        let error = match RunnerProcess::spawn(&mut executable) {
            Err(error) => error,
            Ok(process) => {
                drop(process);
                panic!("unsupported targets must not fall back to path execution");
            }
        };
        assert_eq!(error.error.kind(), io::ErrorKind::Unsupported);
        assert!(matches!(
            error.direct_child,
            DirectChildOutcome::LaunchRefusedBeforeSpawn
        ));
        fs::remove_dir_all(root).expect("remove stderr fixture root");
    }

    /// Widening the Linux descriptor-exec gate past x86-64 must not widen the
    /// image check behind it. `/proc/self/fd` execution is a procfs property
    /// and is architecture-independent, but the bytes the kernel loads must
    /// still be a native image for *this* host, so `e_machine` is compared
    /// against the host's own code and every other value is refused.
    #[test]
    fn native_elf_admission_accepts_only_this_host_architecture() {
        const EM_X86_64: u16 = 62;
        const EM_AARCH64: u16 = 183;

        fn header(machine: u16, executable_type: u16) -> [u8; 20] {
            let mut bytes = [0_u8; 20];
            bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            bytes[16..18].copy_from_slice(&executable_type.to_le_bytes());
            bytes[18..20].copy_from_slice(&machine.to_le_bytes());
            bytes
        }

        let Some(native) = NATIVE_ELF_MACHINE else {
            for machine in [EM_X86_64, EM_AARCH64] {
                assert_eq!(
                    validate_native_linux_elf(&header(machine, 2))
                        .expect_err("an architecture with no admitted machine code admits nothing")
                        .kind(),
                    io::ErrorKind::Unsupported
                );
            }
            return;
        };
        assert!(
            native == EM_X86_64 || native == EM_AARCH64,
            "only EM_X86_64 and EM_AARCH64 are admitted machine codes"
        );
        let foreign = if native == EM_X86_64 {
            EM_AARCH64
        } else {
            EM_X86_64
        };

        validate_native_linux_elf(&header(native, 2)).expect("native ET_EXEC image is admitted");
        validate_native_linux_elf(&header(native, 3)).expect("native ET_DYN image is admitted");

        // The other 64-bit little-endian architecture this build knows about is
        // refused, so a cross-architecture image can never reach an exec.
        assert_eq!(
            validate_native_linux_elf(&header(foreign, 2))
                .expect_err("a foreign-architecture ELF64 image must be refused")
                .kind(),
            io::ErrorKind::InvalidData
        );
        for refused in [
            header(0, 2),         // EM_NONE
            header(native, 1),    // ET_REL, not an executable
            header(native, 4),    // ET_CORE
        ] {
            assert!(validate_native_linux_elf(&refused).is_err());
        }
        let mut wrong_class = header(native, 2);
        wrong_class[4] = 1; // ELFCLASS32
        assert!(validate_native_linux_elf(&wrong_class).is_err());
        let mut big_endian = header(native, 2);
        big_endian[5] = 2; // ELFDATA2MSB
        assert!(validate_native_linux_elf(&big_endian).is_err());
        assert!(
            validate_native_linux_elf(&header(native, 2)[..19]).is_err(),
            "a header truncated inside e_machine must be refused, never accepted"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn macos_public_launch_refuses_missing_native_binding_before_persisting_admission() {
        let (harness, mut ledger) = TestHarness::new("macos-descriptor-refusal");
        let launch = harness.launch("macos-descriptor-refusal");
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                launch.clone(),
            ),
            "macOS must reject a production launch without descriptor exec",
        );
        let RunnerClientError::PlatformLaunchBindingUnavailable {
            target,
            backend,
            reason,
        } = failure.error()
        else {
            panic!("macOS must refuse with the typed platform-binding error");
        };
        assert_eq!(*target, "macos-aarch64");
        assert_eq!(*backend, WorkerCleanupBackend::MacOsDedicatedIdentity);
        assert_eq!(
            reason,
            "macOS 15 exposes neither fexecve nor execveat, and /dev/fd execution is not admitted",
            "the macOS refusal must carry the exact measured ADR-0011 reason"
        );
        assert!(failure.into_cleanup_required().is_none());
        let prepared = prepare_launch(&harness.authority, &harness.policy, &launch)
            .expect("prepare the same launch after typed refusal");
        let cleanup = prepare_ordinary_launch_cleanup(
            &ledger,
            &prepared.intent,
            &launch.expected_base_snapshot,
        )
        .expect("prepare atomic admission after public refusal");
        let admitted = ledger
            .admit_runner_launch_with_cleanup(
                &prepared.intent,
                &harness.policy,
                &cleanup.intent,
                &cleanup.request_bytes,
                &cleanup.event,
            )
            .expect("typed public refusal left every atomic admission identity unused");
        assert_eq!(admitted.launch, prepared.intent);
    }

    #[cfg(target_os = "linux")]
    fn copy_linux_fixture(source_candidates: &[&str], destination: &Path) {
        let source = source_candidates
            .iter()
            .map(Path::new)
            .find(|candidate| candidate.is_file())
            .expect("installed Linux fixture executable");
        fs::copy(source, destination).expect("copy Linux executable fixture");
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700))
            .expect("secure Linux executable fixture");
    }

    #[cfg(target_os = "linux")]
    fn child_descriptor_numbers(child: &Child) -> io::Result<BTreeSet<u32>> {
        fs::read_dir(format!("/proc/{}/fd", child.id()))?
            .map(|entry| {
                let name = entry?.file_name();
                name.to_string_lossy()
                    .parse::<u32>()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sealed_spawn_resists_source_mutation_and_closes_the_exec_fd() {
        use std::os::unix::fs::MetadataExt as _;

        let unique = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let temporary = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let root = temporary.join(format!(
            "grok-build-runner-procfd-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create procfd fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure procfd fixture root");

        let configured = root.join("configured-runner");
        copy_linux_fixture(&["/usr/bin/true", "/bin/true"], &configured);
        let source_before = fs::symlink_metadata(&configured).expect("inspect original source");
        let mut retained =
            RetainedRunnerExecutable::inspect(&configured).expect("seal original true image");
        assert_eq!(
            rustix::fs::fcntl_get_seals(&retained.file).expect("read sealed image seals"),
            crate::runner_client::launch::required_executable_memfd_seals()
        );
        let mut write_attempt = retained
            .file
            .try_clone()
            .expect("clone sealed image handle");
        write_attempt
            .seek(SeekFrom::Start(0))
            .expect("seek sealed write attempt");
        assert_eq!(
            write_attempt
                .write_all(b"mutate")
                .expect_err("sealed image must reject content writes")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            write_attempt
                .set_len(0)
                .expect_err("sealed image must reject truncation")
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        copy_linux_fixture(&["/usr/bin/false", "/bin/false"], &configured);
        let source_after_mutation =
            fs::symlink_metadata(&configured).expect("inspect in-place mutated source");
        assert_eq!(source_before.dev(), source_after_mutation.dev());
        assert_eq!(source_before.ino(), source_after_mutation.ino());
        let renamed_original = root.join("mutated-original");
        fs::rename(&configured, &renamed_original).expect("replace configured runner name");
        copy_linux_fixture(&["/usr/bin/false", "/bin/false"], &configured);
        let process = RunnerProcess::spawn(&mut retained)
            .expect("spawn sealed image after adversarial source mutation and path replacement");
        let outcome = Box::new(process).finish_direct();
        assert!(matches!(
            outcome,
            DirectChildOutcome::Exited { success: true, .. }
        ));

        let cat = root.join("blocking-runner");
        copy_linux_fixture(&["/usr/bin/cat", "/bin/cat"], &cat);
        let mut retained_cat =
            RetainedRunnerExecutable::inspect(&cat).expect("retain blocking image");
        let mut process =
            RunnerProcess::spawn(&mut retained_cat).expect("spawn retained blocking image");
        let stderr = process.stderr.as_ref().expect("retained child stderr");
        let flags = rustix::fs::fcntl_getfl(stderr).expect("inspect stderr flags");
        assert!(flags.contains(rustix::fs::OFlags::NONBLOCK));

        let deadline = Instant::now() + Duration::from_secs(1);
        let sealed = loop {
            let descriptors = child_descriptor_numbers(process.child.as_ref().expect("child"))
                .expect("inspect child descriptors");
            if descriptors == BTreeSet::from([0, 1, 2]) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(
            sealed,
            "successful descriptor exec must expose only 0, 1, and 2"
        );
        drop(process.stdin.take());
        let outcome = Box::new(process).finish_direct();
        assert!(matches!(
            outcome,
            DirectChildOutcome::Exited { success: true, .. }
        ));
        fs::remove_dir_all(root).expect("remove procfd fixture root");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_descriptor_spawn_rejects_scripts_and_never_falls_back_after_exec_failure() {
        let unique = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let temporary = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let root = temporary.join(format!(
            "grok-build-runner-procfd-failure-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create procfd failure root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure procfd failure root");

        let script = root.join("script-runner");
        fs::write(&script, b"#!/bin/sh\nexit 0\n").expect("write script fixture");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .expect("secure script fixture");
        assert!(matches!(
            RetainedRunnerExecutable::inspect(&script),
            Err(error) if error.kind() == io::ErrorKind::InvalidData
        ));

        let native_machine =
            NATIVE_ELF_MACHINE.expect("Linux descriptor exec requires an admitted machine code");
        let malformed = root.join("malformed-elf-runner");
        let mut header = [0_u8; 20];
        header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        header[16..18].copy_from_slice(&2_u16.to_le_bytes());
        header[18..20].copy_from_slice(&native_machine.to_le_bytes());
        fs::write(&malformed, header).expect("write malformed ELF fixture");
        fs::set_permissions(&malformed, fs::Permissions::from_mode(0o700))
            .expect("secure malformed ELF fixture");
        let mut executable = RetainedRunnerExecutable::inspect(&malformed)
            .expect("minimal native header passes pre-exec format admission");

        // The same header carrying the other architecture's machine code is
        // refused before any sealed image exists, so widening the gate to every
        // architecture with a procfs bridge did not widen the image check.
        let foreign_machine = if native_machine == 62 { 183 } else { 62_u16 };
        let foreign = root.join("foreign-elf-runner");
        let mut foreign_header = header;
        foreign_header[18..20].copy_from_slice(&foreign_machine.to_le_bytes());
        fs::write(&foreign, foreign_header).expect("write foreign ELF fixture");
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o700))
            .expect("secure foreign ELF fixture");
        assert!(matches!(
            RetainedRunnerExecutable::inspect(&foreign),
            Err(error) if error.kind() == io::ErrorKind::InvalidData
        ));

        let failure = match RunnerProcess::spawn(&mut executable) {
            Err(failure) => failure,
            Ok(process) => {
                drop(process);
                panic!("kernel exec failure must not fall back to any path or interpreter");
            }
        };
        assert!(matches!(
            failure.direct_child,
            DirectChildOutcome::SpawnFailed
        ));
        assert_ne!(failure.error.kind(), io::ErrorKind::NotFound);
        fs::remove_dir_all(root).expect("remove procfd failure root");
    }
