    #[allow(clippy::fn_params_excessive_bools, clippy::too_many_lines)]
    fn prepare_v15_candidate_fixture_with_graph_options(
        automated: bool,
        verified_no_op: bool,
        include_bound_read: bool,
        include_retry: bool,
        candidate_requirement: CandidateTaskRequirement,
        additional_task: Option<crate::TaskSpec>,
    ) -> V15CandidateFixture {
        prepare_v15_candidate_fixture_with_graph_options_at_generation(
            automated,
            verified_no_op,
            include_bound_read,
            include_retry,
            candidate_requirement,
            additional_task,
            false,
        )
    }

    #[allow(clippy::fn_params_excessive_bools, clippy::too_many_lines)]
    fn prepare_v15_candidate_fixture_with_graph_options_at_generation(
        automated: bool,
        verified_no_op: bool,
        include_bound_read: bool,
        include_retry: bool,
        candidate_requirement: CandidateTaskRequirement,
        additional_task: Option<crate::TaskSpec>,
        historical_v21: bool,
    ) -> V15CandidateFixture {
        prepare_v15_candidate_fixture_with_graph_options_at_generation_and_snapshot_overrides(
            automated,
            verified_no_op,
            include_bound_read,
            include_retry,
            candidate_requirement,
            additional_task,
            historical_v21,
            None,
            false,
        )
    }

    #[allow(
        clippy::fn_params_excessive_bools,
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the historical fixture exposes every schema generation, graph, retry, and snapshot dimension explicitly"
    )]
    fn prepare_v15_candidate_fixture_with_graph_options_at_generation_and_snapshot_overrides(
        automated: bool,
        verified_no_op: bool,
        include_bound_read: bool,
        include_retry: bool,
        candidate_requirement: CandidateTaskRequirement,
        additional_task: Option<crate::TaskSpec>,
        historical_v21: bool,
        snapshot_overrides: Option<V15SnapshotOverrides>,
        historical_v23: bool,
    ) -> V15CandidateFixture {
        let database = TestDatabase::new();
        let mut ledger = if historical_v21 {
            open_v21_test_ledger(&database)
        } else if historical_v23 {
            open_v23_test_ledger(&database)
        } else {
            EventLedger::open(&database.path).expect("open v15 phase ledger")
        };
        let (mut spec, mut graph) = sprint_fixture();
        let (mut base, mut result_snapshot, mut change_set, _, _, _, _, _) = completion_artifacts();
        if let Some(overrides) = snapshot_overrides {
            spec.base_snapshot = overrides.base_snapshot_id.clone();
            graph.tasks[0].base_snapshot = overrides.base_snapshot_id.clone();
            base.snapshot_id = overrides.base_snapshot_id.clone();
            result_snapshot.snapshot_id = overrides.result_snapshot_id.clone();
            change_set.base_snapshot = overrides.base_snapshot_id;
            change_set.result_snapshot = overrides.result_snapshot_id;
        }
        let candidate_required =
            matches!(candidate_requirement, CandidateTaskRequirement::Required);
        graph.tasks[0].required = candidate_required;
        if let Some(task) = additional_task {
            graph.tasks.push(task);
        }
        if !automated {
            spec.acceptance_criteria[0].kind = AcceptanceKind::HumanJudgment;
        }
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist v15 phase sprint");
        if verified_no_op {
            result_snapshot = base.clone();
            change_set.base_snapshot = base.snapshot_id.clone();
            change_set.result_snapshot = base.snapshot_id.clone();
            change_set.operations.clear();
        }
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &base)
            .expect("persist v15 base snapshot");
        if result_snapshot.snapshot_id != base.snapshot_id {
            ledger
                .persist_workspace_snapshot(&spec.sprint_id, &result_snapshot)
                .expect("persist v15 result snapshot");
        }
        ledger
            .persist_change_set(&spec.sprint_id, &change_set)
            .expect("persist v15 candidate change set");

        let mut prior_attempt = None;
        let mut prior_disposition = None;
        let mut prior_launch = None;
        if include_retry {
            let prior_policy = compiled_shadow_test_policy("v15-prior-retry-policy");
            let launch = runner_launch(
                "launch-v15-prior-retry",
                "session-v15-prior-retry",
                RunnerSessionPurpose::TaskWorker,
                Some("worker-prior"),
                &prior_policy,
                1_100,
            );
            acquire_test_launch_lease(&mut ledger, &launch)
                .expect("acquire prior retry attempt lease");
            let (cleanup_intent, _, cleanup_request_bytes, cleanup_proposal) =
                test_runner_launch_cleanup_contracts(
                    &ledger,
                    &launch,
                    WorkerCleanupBackend::LinuxCgroupV2,
                )
                .expect("build prior retry cleanup admission");
            let _admission = ledger
                .admit_runner_launch_with_cleanup(
                    &launch,
                    &prior_policy,
                    &cleanup_intent,
                    &cleanup_request_bytes,
                    &cleanup_proposal,
                )
                .expect("admit prior retry launch");
            let session = runner_session(&launch, 1_105);
            ledger
                .register_runner_session(&session, &prior_policy)
                .expect("register prior retry session");
            let attempt = ledger
                .load_task_attempt(
                    &launch
                        .worker_lease
                        .as_ref()
                        .expect("prior retry lease")
                        .lease_id,
                )
                .expect("load prior retry attempt");
            let running_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger
                    .next_sequence(&spec.sprint_id)
                    .expect("prior retry Running sequence"),
                event_id: "event-v15-prior-retry-running".into(),
                sprint_id: spec.sprint_id.clone(),
                task_id: Some(attempt.worker_lease.task_id.clone()),
                worker_id: Some(attempt.worker_lease.worker_id.clone()),
                causation_id: Some(attempt.opening_event_id.clone()),
                correlation_id: "v15-prior-retry".into(),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms: 1_110,
                payload: AgentEventKind::TaskStateChanged {
                    from: "Leased".into(),
                    to: "Running".into(),
                },
            };
            let running = TaskAttemptRunningBoundary {
                contract_version: CONTRACT_VERSION,
                boundary_id: "boundary-v15-prior-retry-running".into(),
                attempt: attempt.clone(),
                runner_launch_id: launch.launch_id.clone(),
                runner_session_id: launch.session_id.clone(),
                transition_event_id: running_event.event_id.clone(),
                started_at_unix_ms: running_event.occurred_at_unix_ms,
            };
            ledger
                .start_task_attempt(&running, &running_event)
                .expect("start prior retry attempt");

            let provider_request = b"prior attempt provider request".to_vec();
            let provider_intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: "effect-v15-prior-retry-provider".into(),
                idempotency_key: "key-v15-prior-retry-provider".into(),
                sprint_id: spec.sprint_id.clone(),
                task_id: Some(attempt.worker_lease.task_id.clone()),
                worker_id: Some(attempt.worker_lease.worker_id.clone()),
                worker_lease: Some(attempt.worker_lease.clone()),
                causation_event_id: Some(running_event.event_id.clone()),
                correlation_id: "v15-prior-retry-provider".into(),
                kind: EffectKind::ProviderRequest,
                request_digest: Digest::sha256(&provider_request),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: spec.base_snapshot.clone(),
                created_at_unix_ms: 1_120,
            };
            let provider_proposal = effect_proposal_event(
                &provider_intent,
                ledger
                    .next_sequence(&spec.sprint_id)
                    .expect("prior provider proposal sequence"),
                "event-v15-prior-retry-provider-proposed",
            );
            ledger
                .record_effect_intent(&provider_intent, &provider_request, &provider_proposal)
                .expect("persist prior attempt provider effect");
            let provider_evidence = b"prior attempt provider result".to_vec();
            let provider_observation = effect_observation(
                &provider_intent,
                "observation-v15-prior-retry-provider",
                EffectOutcome::Succeeded {
                    evidence_digest: Digest::sha256(&provider_evidence),
                },
                1_130,
            );
            let provider_terminal = effect_terminal_event(
                &provider_intent,
                &provider_proposal.event_id,
                &provider_observation,
                ledger
                    .next_sequence(&spec.sprint_id)
                    .expect("prior provider terminal sequence"),
                "event-v15-prior-retry-provider-finished",
            );
            ledger
                .record_effect_observation(
                    &provider_observation,
                    &provider_evidence,
                    &provider_terminal,
                )
                .expect("terminalize prior attempt provider effect");

            let outcome = TaskAttemptKnownCleanupOutcome::Retryable(
                crate::TaskAttemptRetryableCause::KnownWorkerExit {
                    launch_id: launch.launch_id.clone(),
                    session_id: launch.session_id.clone(),
                    evidence: crate::TaskAttemptEvidence::new(
                        "evidence-v15-prior-retry-worker-exit".into(),
                        crate::TaskAttemptEvidenceKind::KnownWorkerExit,
                        b"prior worker exited with a known result".to_vec(),
                    )
                    .expect("construct prior retry worker-exit evidence"),
                },
            );
            ledger
                .record_task_attempt_cleanup_outcome_authority(&attempt, &outcome, 1_140)
                .expect("persist prior retry worker-exit authority");
            let metadata = TaskAttemptDispositionMetadata {
                contract_version: CONTRACT_VERSION,
                disposition_id: "disposition-v15-prior-retry".into(),
                attempt: attempt.clone(),
                from_state: TaskState::Running,
                state_transition_event_id: "event-v15-prior-retry-ready".into(),
                disposed_at_unix_ms: 1_170,
            };
            let transition_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger
                    .next_sequence(&spec.sprint_id)
                    .expect("prior retry cleanup sequence")
                    + 1,
                event_id: metadata.state_transition_event_id.clone(),
                sprint_id: spec.sprint_id.clone(),
                task_id: Some(attempt.worker_lease.task_id.clone()),
                worker_id: Some(attempt.worker_lease.worker_id.clone()),
                causation_id: Some(provider_terminal.event_id),
                correlation_id: "v15-prior-retry".into(),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms: metadata.disposed_at_unix_ms,
                payload: AgentEventKind::TaskStateChanged {
                    from: "Running".into(),
                    to: "Ready".into(),
                },
            };
            let disposition = ledger
                .with_task_attempt_cleanup_disposition_exclusion(
                    &metadata,
                    &outcome,
                    "release-v15-prior-retry",
                    &transition_event,
                    |claim| {
                        Ok(cleanup_terminal_from_live_claim(
                            claim,
                            "v15-prior-retry",
                            1_160,
                        ))
                    },
                )
                .expect("close prior launched retry");
            assert!(matches!(disposition, TaskAttemptDisposition::Retryable(_)));
            prior_attempt = Some(attempt);
            prior_disposition = Some(disposition);
            prior_launch = Some(launch);
        }

        let policy = compiled_shadow_test_policy(if automated {
            "v15-automated-worker-policy"
        } else {
            "v15-human-worker-policy"
        });
        let mut launch = runner_launch(
            if automated {
                "launch-v15-automated"
            } else {
                "launch-v15-human"
            },
            if automated {
                "session-v15-automated"
            } else {
                "session-v15-human"
            },
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &policy,
            1_210,
        );
        if include_retry {
            let second_lease = WorkerLease::new(
                spec.sprint_id.clone(),
                2,
                "task-1".into(),
                "worker-1".into(),
                vec![PathScope::Workspace],
                1_209,
            )
            .expect("construct second-attempt lease");
            launch.worker_lease = Some(second_lease.clone());
            let prior_event_id = prior_disposition
                .as_ref()
                .expect("prior retry disposition")
                .metadata()
                .state_transition_event_id
                .clone();
            let acquisition_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger
                    .next_sequence(&spec.sprint_id)
                    .expect("second-attempt acquisition sequence"),
                event_id: "event-v15-second-attempt-acquired".into(),
                sprint_id: spec.sprint_id.clone(),
                task_id: Some("task-1".into()),
                worker_id: Some("worker-1".into()),
                causation_id: Some(prior_event_id),
                correlation_id: "v15-second-attempt".into(),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms: second_lease.acquired_at_unix_ms,
                payload: AgentEventKind::TaskStateChanged {
                    from: "Ready".into(),
                    to: "Leased".into(),
                },
            };
            ledger
                .acquire_task_attempt(&second_lease, &acquisition_event)
                .expect("acquire second task attempt");
        }
        admit_test_runner_launch(&mut ledger, &launch, &policy);
        let session = runner_session(&launch, 1_220);
        ledger
            .register_runner_session(&session, &policy)
            .expect("register v15 task-worker session");
        let attempt = ledger
            .load_task_attempt(
                &launch
                    .worker_lease
                    .as_ref()
                    .expect("task-worker lease")
                    .lease_id,
            )
            .expect("load acquired v15 attempt");
        let running_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&spec.sprint_id)
                .expect("running sequence"),
            event_id: format!("{}-running", launch.launch_id),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(attempt.worker_lease.task_id.clone()),
            worker_id: Some(attempt.worker_lease.worker_id.clone()),
            causation_id: Some(attempt.opening_event_id.clone()),
            correlation_id: format!("{}-attempt", launch.launch_id),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: 1_230,
            payload: AgentEventKind::TaskStateChanged {
                from: "Leased".into(),
                to: "Running".into(),
            },
        };
        let running = TaskAttemptRunningBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("{}-running-boundary", launch.launch_id),
            attempt: attempt.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            transition_event_id: running_event.event_id.clone(),
            started_at_unix_ms: running_event.occurred_at_unix_ms,
        };
        ledger
            .start_task_attempt(&running, &running_event)
            .expect("enter v15 Running");

        let mut terminal_non_cleanup_effects = Vec::new();
        if include_bound_read {
            let request_bytes = b"README.md".to_vec();
            let intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: "effect-v15-bound-read".into(),
                idempotency_key: "key-v15-bound-read".into(),
                sprint_id: spec.sprint_id.clone(),
                task_id: Some(attempt.worker_lease.task_id.clone()),
                worker_id: Some(attempt.worker_lease.worker_id.clone()),
                worker_lease: Some(attempt.worker_lease.clone()),
                causation_event_id: Some(running_event.event_id.clone()),
                correlation_id: "v15-bound-read".into(),
                kind: EffectKind::ReadRelativeFile,
                request_digest: Digest::sha256(&request_bytes),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: base.snapshot_id.clone(),
                created_at_unix_ms: 1_232,
            };
            let proposal = effect_proposal_event(
                &intent,
                ledger
                    .next_sequence(&spec.sprint_id)
                    .expect("bound-read proposal sequence"),
                "event-v15-bound-read-proposed",
            );
            ledger
                .record_runner_effect_intent(&intent, &request_bytes, &proposal, &launch.session_id)
                .expect("persist bound read intent");
            let evidence = b"bound read result".to_vec();
            let observation = effect_observation(
                &intent,
                "observation-v15-bound-read",
                EffectOutcome::Succeeded {
                    evidence_digest: Digest::sha256(&evidence),
                },
                1_234,
            );
            let terminal = effect_terminal_event(
                &intent,
                &proposal.event_id,
                &observation,
                ledger
                    .next_sequence(&spec.sprint_id)
                    .expect("bound-read terminal sequence"),
                "event-v15-bound-read-finished",
            );
            ledger
                .record_effect_observation(&observation, &evidence, &terminal)
                .expect("persist bound read observation");
            terminal_non_cleanup_effects.push(TaskAttemptTerminalEffect {
                effect_id: intent.effect_id,
                observation_id: observation.observation_id,
            });
        }

        let verification_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&spec.sprint_id)
                .expect("verification sequence"),
            event_id: format!("{}-verifying", launch.launch_id),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(attempt.worker_lease.task_id.clone()),
            worker_id: Some(attempt.worker_lease.worker_id.clone()),
            causation_id: Some(running_event.event_id),
            correlation_id: format!("{}-attempt", launch.launch_id),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: 1_240,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Verifying".into(),
            },
        };
        let verification = TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("{}-verification-boundary", launch.launch_id),
            attempt: attempt.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
            sealed_snapshot: result_snapshot.snapshot_id.clone(),
            transition_event_id: verification_event.event_id.clone(),
            terminal_non_cleanup_effects,
            sealed_at_unix_ms: verification_event.occurred_at_unix_ms,
        };
        ledger
            .transition_task_attempt_to_verifying(&verification, &verification_event)
            .expect("enter v15 Verifying");
        assert_eq!(
            ledger
                .transition_task_attempt_to_verifying(&verification, &verification_event)
                .expect("verification boundary exact replay"),
            verification
        );

        let mut formal_check_ids = Vec::new();
        let mut verification_receipt_ids = Vec::new();
        let mut formal_checks = Vec::new();
        if automated {
            let command = match &spec.acceptance_criteria[0].kind {
                AcceptanceKind::Automated(command) => command.clone(),
                AcceptanceKind::HumanJudgment => unreachable!("automated fixture"),
            };
            let command_bytes = encode("formal-check command", &command).expect("encode command");
            let intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: "effect-v15-formal".into(),
                idempotency_key: "key-v15-formal".into(),
                sprint_id: spec.sprint_id.clone(),
                task_id: Some(attempt.worker_lease.task_id.clone()),
                worker_id: Some(attempt.worker_lease.worker_id.clone()),
                worker_lease: Some(attempt.worker_lease.clone()),
                causation_event_id: Some(verification_event.event_id.clone()),
                correlation_id: "v15-formal".into(),
                kind: EffectKind::RunCommand,
                request_digest: Digest::sha256(&command_bytes),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: result_snapshot.snapshot_id.clone(),
                created_at_unix_ms: 1_250,
            };
            let proposal = effect_proposal_event(
                &intent,
                ledger
                    .next_sequence(&spec.sprint_id)
                    .expect("formal proposal sequence"),
                "event-v15-formal-proposed",
            );
            let admission = TaskAttemptFormalCheckAdmission {
                contract_version: CONTRACT_VERSION,
                admission_id: "admission-v15-formal".into(),
                attempt: attempt.clone(),
                criterion_ordinal: 0,
                criterion_id: "tests".into(),
                effect_id: intent.effect_id.clone(),
                runner_session_id: launch.session_id.clone(),
                sealed_snapshot: result_snapshot.snapshot_id.clone(),
                command: command.clone(),
                admitted_at_unix_ms: 1_250,
            };
            let capture_intent = (ledger
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("read formal fixture schema version")
                >= 27)
                .then(|| v27_test_capture_intent(&intent, &launch, &session, "v15-formal"));
            let first_admission = match capture_intent.as_ref() {
                Some(capture) => ledger
                    .admit_task_attempt_formal_check_with_output_capture_for_dispatch(
                        &admission, &intent, &proposal, capture,
                    ),
                None => ledger
                    .admit_task_attempt_formal_check_for_dispatch(&admission, &intent, &proposal),
            }
            .expect("admit serialized formal check for dispatch");
            let permit = match first_admission {
                TaskFormalCheckDispatchAdmission::Fresh { permit, .. } => permit,
                TaskFormalCheckDispatchAdmission::Existing { .. } => {
                    panic!("new serialized formal admission must be Fresh")
                }
            };
            let replay = match capture_intent.as_ref() {
                Some(capture) => ledger
                    .admit_task_attempt_formal_check_with_output_capture_for_dispatch(
                        &admission, &intent, &proposal, capture,
                    ),
                None => ledger
                    .admit_task_attempt_formal_check_for_dispatch(&admission, &intent, &proposal),
            };
            assert!(matches!(
                replay.expect("formal admission exact replay"),
                TaskFormalCheckDispatchAdmission::Existing { admission: stored, .. }
                    if stored == admission
            ));
            let mut conflict = admission.clone();
            conflict.admission_id = "conflicting-formal-admission".into();
            let conflict_result = match capture_intent.as_ref() {
                Some(capture) => ledger
                    .admit_task_attempt_formal_check_with_output_capture_for_dispatch(
                        &conflict, &intent, &proposal, capture,
                    ),
                None => ledger
                    .admit_task_attempt_formal_check_for_dispatch(&conflict, &intent, &proposal),
            };
            assert!(matches!(
                conflict_result,
                Err(LedgerError::ReferenceMismatch { .. })
            ));

            let output = b"v15 formal output".to_vec();
            let mut receipt = VerificationReceipt {
                receipt_id: "receipt-v15-formal".into(),
                sprint_id: spec.sprint_id.clone(),
                task_id: Some(attempt.worker_lease.task_id.clone()),
                snapshot_id: result_snapshot.snapshot_id.clone(),
                command,
                policy_hash: launch.policy_hash.clone(),
                exit_status: Some(0),
                termination: Some(CommandTerminationV1::Exited { code: 0 }),
                output_digest: Digest::sha256(&output),
                duration_ms: 10,
                finished_at_unix_ms: 1_300,
            };
            let (output_artifacts, output_evidence_bytes) = bind_complete_output_artifacts(
                &ledger,
                &mut receipt,
                &intent.effect_id,
                &launch.launch_id,
                &launch.session_id,
                output,
            );
            let formal_evidence = VerificationEffectEvidence {
                contract_version: CONTRACT_VERSION,
                effect_id: intent.effect_id.clone(),
                observation_id: "observation-v15-formal".into(),
                runner_launch_id: launch.launch_id.clone(),
                runner_session_id: launch.session_id.clone(),
                verification: receipt.clone(),
                output_artifacts,
                output_evidence_bytes,
            };
            let formal_evidence_bytes =
                encode("verification effect evidence", &formal_evidence).expect("encode evidence");
            let observation = effect_observation(
                &intent,
                &formal_evidence.observation_id,
                EffectOutcome::Succeeded {
                    evidence_digest: Digest::sha256(&formal_evidence_bytes),
                },
                receipt.finished_at_unix_ms,
            );
            let terminal = effect_terminal_event(
                &intent,
                &proposal.event_id,
                &observation,
                ledger
                    .next_sequence(&spec.sprint_id)
                    .expect("formal terminal sequence"),
                "event-v15-formal-finished",
            );
            let check = TaskAttemptFormalCheck {
                contract_version: CONTRACT_VERSION,
                formal_check_id: "formal-check-v15".into(),
                attempt: attempt.clone(),
                criterion_ordinal: 0,
                criterion_id: "tests".into(),
                effect_id: intent.effect_id.clone(),
                observation_id: observation.observation_id.clone(),
                verification_receipt: receipt.clone(),
                runner_session_id: launch.session_id.clone(),
                sealed_snapshot: result_snapshot.snapshot_id.clone(),
            };
            let session = ledger
                .load_runner_session(&spec.sprint_id, &launch.session_id)
                .expect("load serialized formal runner session");
            let dispatch_permit = FreshRunnerEffectDispatchPermit::TaskFormalCheck(permit);
            let (transport, capture_acquired) = if let Some(capture) = capture_intent.as_ref() {
                let acquired = v27_test_capture_acquired(
                    capture,
                    dispatch_permit
                        .expected_output_capture_dispatch_claim_id()
                        .expect("fresh v15 formal capture claim identity"),
                    "v15-formal",
                    1_260,
                );
                let (_, transport) = ledger
                    .claim_command_output_capture_dispatch(
                        dispatch_permit,
                        acquired.clone(),
                        OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                    )
                    .expect("claim serialized formal capture dispatch");
                (transport, Some(acquired))
            } else {
                let (_, transport) = ledger
                    .claim_runner_effect_dispatch(
                        dispatch_permit,
                        OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                    )
                    .expect("claim historical serialized formal dispatch");
                (transport, None)
            };
            let authority = transport
                .validate_transport_request(
                    &intent,
                    &command_bytes,
                    &launch,
                    &session,
                    None,
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                )
                .expect("validate serialized formal transport");
            if let (Some(capture), Some(acquired)) =
                (capture_intent.as_ref(), capture_acquired.as_ref())
            {
                let capture_terminal = v27_test_published_capture_terminal(
                    capture,
                    acquired,
                    &observation,
                    formal_evidence
                        .output_artifacts
                        .clone()
                        .expect("current formal evidence carries artifacts"),
                    "v15-formal",
                    1_310,
                );
                let cleanup = v27_test_command_cleanup(
                    &intent,
                    &observation,
                    &launch,
                    &session,
                    "v15-formal",
                    1_305,
                );
                let clean_scan = v29_test_clean_scan_receipt(
                    capture,
                    acquired,
                    &capture_terminal,
                    formal_evidence
                        .verification
                        .termination
                        .expect("current formal receipt has typed termination"),
                    "v15-formal",
                );
                ledger
                    .complete_claimed_task_attempt_formal_check_with_output_capture(
                        authority,
                        &check,
                        &observation,
                        &terminal,
                        &formal_evidence,
                        &capture_terminal,
                        &clean_scan,
                        &cleanup,
                    )
                    .expect("complete claimed serialized formal check with v27 capture");
            } else {
                ledger
                    .complete_claimed_task_attempt_formal_check(
                        authority,
                        &check,
                        &observation,
                        &terminal,
                        &formal_evidence,
                    )
                    .expect("complete historical claimed serialized formal check");
            }
            assert_eq!(
                ledger
                    .load_task_attempt_formal_check(&check.formal_check_id)
                    .expect("formal check exact readback"),
                check
            );
            formal_check_ids.push(check.formal_check_id.clone());
            verification_receipt_ids.push(receipt.receipt_id);
            formal_checks.push(check);
        }

        let candidate_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&spec.sprint_id)
                .expect("candidate sequence"),
            event_id: format!("{}-candidate", launch.launch_id),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(attempt.worker_lease.task_id.clone()),
            worker_id: Some(attempt.worker_lease.worker_id.clone()),
            causation_id: Some(verification_event.event_id),
            correlation_id: format!("{}-attempt", launch.launch_id),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: if automated { 1_320 } else { 1_260 },
            payload: AgentEventKind::TaskStateChanged {
                from: "Verifying".into(),
                to: "Candidate".into(),
            },
        };
        let candidate = TaskAttemptCandidateBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("{}-candidate-boundary", launch.launch_id),
            attempt: attempt.clone(),
            verification_boundary_id: verification.boundary_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
            sealed_snapshot: result_snapshot.snapshot_id.clone(),
            formal_check_ids,
            verification_receipt_ids,
            transition_event_id: candidate_event.event_id.clone(),
            admitted_at_unix_ms: candidate_event.occurred_at_unix_ms,
        };
        ledger
            .transition_task_attempt_to_candidate(&candidate, &candidate_event)
            .expect("enter v15 Candidate");
        assert_eq!(
            ledger
                .transition_task_attempt_to_candidate(&candidate, &candidate_event)
                .expect("candidate boundary exact replay"),
            candidate
        );

        V15CandidateFixture {
            database,
            ledger,
            spec,
            result_snapshot,
            change_set,
            launch,
            attempt,
            running,
            verification,
            formal_checks,
            candidate,
            prior_attempt,
            prior_disposition,
            prior_launch,
            candidate_required,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn integrate_v15_candidate(
        fixture: &mut V15CandidateFixture,
        suffix: &str,
        exercise_sql_attacks: bool,
    ) -> (
        TaskAttemptIntegrationAdmission,
        TaskIntegrationEvidence,
        TaskAttemptDisposition,
    ) {
        let artifact = TaskIntegrationArtifactReference {
            format_version: 1,
            artifact_digest: Digest::sha256(format!("v15-artifact-{suffix}").as_bytes()),
            change_set_id: fixture.change_set.change_set_id.clone(),
            base_snapshot: fixture.change_set.base_snapshot.clone(),
            result_snapshot: fixture.change_set.result_snapshot.clone(),
        };
        let request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: fixture.change_set.clone(),
            artifact: artifact.clone(),
        };
        let request_bytes = encode("task integration request", &request).expect("encode request");
        let admitted_at = fixture.candidate.admitted_at_unix_ms + 20;
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("effect-v15-integration-{suffix}"),
            idempotency_key: format!("key-v15-integration-{suffix}"),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: Some(fixture.attempt.worker_lease.task_id.clone()),
            worker_id: Some(fixture.attempt.worker_lease.worker_id.clone()),
            worker_lease: Some(fixture.attempt.worker_lease.clone()),
            causation_event_id: Some(fixture.candidate.transition_event_id.clone()),
            correlation_id: format!("v15-integration-{suffix}"),
            kind: EffectKind::IntegrateChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: fixture.launch.policy_hash.clone(),
            input_snapshot: fixture.change_set.base_snapshot.clone(),
            created_at_unix_ms: admitted_at,
        };
        let proposal = effect_proposal_event(
            &intent,
            fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("integration proposal sequence"),
            &format!("event-v15-integration-{suffix}-proposed"),
        );
        let admission = TaskAttemptIntegrationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("admission-v15-integration-{suffix}"),
            candidate_boundary: fixture.candidate.clone(),
            effect_id: intent.effect_id.clone(),
            runner_launch_id: fixture.launch.launch_id.clone(),
            runner_session_id: fixture.launch.session_id.clone(),
            input_snapshot: fixture.change_set.base_snapshot.clone(),
            result_snapshot: fixture.result_snapshot.snapshot_id.clone(),
            admitted_at_unix_ms: admitted_at,
        };
        if exercise_sql_attacks {
            let mut malicious = serde_json::to_value(&request).expect("request value");
            malicious
                .as_object_mut()
                .expect("request object")
                .insert("unknown_authority".into(), serde_json::Value::Bool(true));
            let malicious = serde_json::to_vec(&malicious).expect("encode malicious request");
            let transaction = fixture
                .ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start malicious admission transaction");
            let error = task_attempt_authority::insert_integration_admission(
                &transaction,
                &admission,
                &malicious,
            )
            .expect_err("unknown integration request field must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("integration admission requires exact active Candidate")
            );
            transaction.rollback().expect("roll back malicious request");
        }
        let permit = match fixture
            .ledger
            .admit_task_attempt_integration_for_dispatch(&admission, &intent, &request, &proposal)
            .expect("admit v15 integration for dispatch")
        {
            TaskIntegrationDispatchAdmission::Fresh { permit, .. } => permit,
            TaskIntegrationDispatchAdmission::Existing { .. } => {
                panic!("new v15 integration admission must be Fresh")
            }
        };
        assert!(matches!(
            fixture
                .ledger
                .admit_task_attempt_integration_for_dispatch(
                    &admission,
                    &intent,
                    &request,
                    &proposal,
                )
                .expect("integration admission exact replay"),
            TaskIntegrationDispatchAdmission::Existing { admission: stored, .. }
                if stored == admission
        ));
        let mut conflicting_request = request.clone();
        conflicting_request.artifact.artifact_digest = digest('f');
        assert!(
            fixture
                .ledger
                .admit_task_attempt_integration_for_dispatch(
                    &admission,
                    &intent,
                    &conflicting_request,
                    &proposal,
                )
                .is_err()
        );

        let integrated_at = admitted_at + 40;
        let integration_ordinal = fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM task_integration_receipts WHERE sprint_id = ?1",
                [&fixture.spec.sprint_id],
                |row| row.get::<_, u32>(0),
            )
            .expect("derive next fixture integration ordinal");
        let receipt = TaskIntegrationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: format!("receipt-v15-integration-{suffix}"),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: fixture.attempt.worker_lease.task_id.clone(),
            worker_id: fixture.attempt.worker_lease.worker_id.clone(),
            worker_lease: Some(fixture.attempt.worker_lease.clone()),
            worker_launch_id: fixture.launch.launch_id.clone(),
            worker_session_id: fixture.launch.session_id.clone(),
            worker_policy_hash: fixture.launch.policy_hash.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: format!("observation-v15-integration-{suffix}"),
            change_set_id: fixture.change_set.change_set_id.clone(),
            input_snapshot: fixture.change_set.base_snapshot.clone(),
            result_snapshot: fixture.change_set.result_snapshot.clone(),
            task_verification_receipt_ids: fixture.candidate.verification_receipt_ids.clone(),
            integration_ordinal,
            integrated_at_unix_ms: integrated_at,
        };
        let evidence = TaskIntegrationEvidence {
            contract_version: CONTRACT_VERSION,
            receipt: receipt.clone(),
            artifact,
            validation: crate::TaskIntegrationValidationEvidence {
                mode: TaskIntegrationValidationMode::WorkerPublication,
                runner_launch_id: fixture.launch.launch_id.clone(),
                runner_session_id: fixture.launch.session_id.clone(),
                policy_hash: fixture.launch.policy_hash.clone(),
                grant_hash: fixture.launch.grant_hash.clone(),
                private_state_digest: fixture.launch.private_state_digest.clone(),
            },
        };
        let evidence_bytes =
            encode("task integration evidence", &evidence).expect("encode integration evidence");
        let observation = effect_observation(
            &intent,
            &receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            integrated_at,
        );
        let effect_terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("integration terminal sequence"),
            &format!("event-v15-integration-{suffix}-finished"),
        );
        let disposed_at = integrated_at + 10;
        let transition_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: effect_terminal.sequence + 1,
            event_id: format!("event-v15-integration-{suffix}-integrated"),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: Some(fixture.attempt.worker_lease.task_id.clone()),
            worker_id: Some(fixture.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(effect_terminal.event_id.clone()),
            correlation_id: format!("v15-integration-{suffix}"),
            policy_hash: Some(fixture.launch.policy_hash.clone()),
            occurred_at_unix_ms: disposed_at,
            payload: AgentEventKind::TaskStateChanged {
                from: "Candidate".into(),
                to: "Integrated".into(),
            },
        };
        let disposition =
            TaskAttemptDisposition::Integrated(crate::TaskAttemptIntegratedDisposition {
                metadata: TaskAttemptDispositionMetadata {
                    contract_version: CONTRACT_VERSION,
                    disposition_id: format!("disposition-v15-integration-{suffix}"),
                    attempt: fixture.attempt.clone(),
                    from_state: TaskState::Candidate,
                    state_transition_event_id: transition_event.event_id.clone(),
                    disposed_at_unix_ms: disposed_at,
                },
                candidate_boundary: fixture.candidate.clone(),
                integration_receipt: receipt.clone(),
                evidence: crate::TaskAttemptEvidence::new(
                    format!("evidence-v15-integration-{suffix}"),
                    crate::TaskAttemptEvidenceKind::Integrated,
                    evidence_bytes,
                )
                .expect("typed integration disposition evidence"),
            });

        if exercise_sql_attacks {
            let transaction = fixture
                .ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start uncovered receipt transaction");
            insert_finish_receipt_id(
                &transaction,
                &receipt.receipt_id,
                &receipt.sprint_id,
                "TaskIntegration",
            )
            .expect("stage finish receipt identity");
            let error = insert_task_integration_receipt(&transaction, &receipt)
                .expect_err("standalone current integration receipt must fail");
            assert!(
                error
                    .to_string()
                    .contains("requires deferred Integrated disposition coverage")
            );
            transaction.rollback().expect("roll back uncovered receipt");
        }

        let session = fixture
            .ledger
            .load_runner_session(&fixture.spec.sprint_id, &fixture.launch.session_id)
            .expect("load v15 integration runner session");
        let (_, transport) = fixture
            .ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::TaskIntegration(permit),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim v15 integration dispatch");
        let authority = transport
            .validate_transport_request(
                &intent,
                &request_bytes,
                &fixture.launch,
                &session,
                None,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate v15 integration transport");
        fixture
            .ledger
            .integrate_claimed_task_attempt(
                authority,
                &disposition,
                &observation,
                &effect_terminal,
                &evidence,
                &transition_event,
            )
            .expect("atomically integrate claimed v15 attempt");
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_disposition(&disposition.metadata().disposition_id)
                .expect("Integrated disposition exact readback"),
            disposition
        );
        let mut conflict = transition_event;
        conflict.event_id.push_str("-conflict");
        assert!(matches!(
            fixture.ledger.integrate_task_attempt(
                &disposition,
                &observation,
                &effect_terminal,
                &evidence,
                &conflict,
            ),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        (admission, evidence, disposition)
    }

    struct ClaimedFormalTerminalFixture {
        database: TestDatabase,
        ledger: EventLedger,
        authority: Option<RunnerEffectObservationAuthority>,
        capture_terminal: Option<CommandOutputCaptureTerminalAnchorV1>,
        clean_scan_receipt: Option<CommandOutputCleanScanPublicationReceiptV1>,
        command_cleanup: Option<CommandDomainCleanupProof>,
        intent: EffectIntent,
        proposal: AgentEvent,
        admission: TaskAttemptFormalCheckAdmission,
        check: TaskAttemptFormalCheck,
        observation: EffectObservation,
        terminal: AgentEvent,
        evidence: VerificationEffectEvidence,
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_claimed_formal_terminal_fixture(
        claim_dispatch: bool,
    ) -> ClaimedFormalTerminalFixture {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open claimed formal ledger");
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist claimed formal sprint");
        let (base, result, change_set, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &base)
            .expect("persist claimed formal base");
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &result)
            .expect("persist claimed formal result");
        ledger
            .persist_change_set(&spec.sprint_id, &change_set)
            .expect("persist claimed formal change set");

        let policy = compiled_shadow_test_policy("claimed-formal-policy");
        let launch = runner_launch(
            "launch-claimed-formal",
            "session-claimed-formal",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            &policy,
            1_210,
        );
        admit_test_runner_launch(&mut ledger, &launch, &policy);
        let session = runner_session(&launch, 1_220);
        ledger
            .register_runner_session(&session, &policy)
            .expect("register claimed formal session");
        let running = enter_test_task_attempt_running(&mut ledger, &launch, 1_230);
        let verifying_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&spec.sprint_id)
                .expect("claimed formal Verifying sequence"),
            event_id: "event-claimed-formal-verifying".into(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(running.attempt.worker_lease.task_id.clone()),
            worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(running.transition_event_id.clone()),
            correlation_id: "correlation-claimed-formal".into(),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: 1_240,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Verifying".into(),
            },
        };
        let verification = TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "boundary-claimed-formal-verifying".into(),
            attempt: running.attempt.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            change_set_id: change_set.change_set_id,
            sealed_snapshot: result.snapshot_id.clone(),
            transition_event_id: verifying_event.event_id.clone(),
            terminal_non_cleanup_effects: Vec::new(),
            sealed_at_unix_ms: verifying_event.occurred_at_unix_ms,
        };
        ledger
            .transition_task_attempt_to_verifying(&verification, &verifying_event)
            .expect("enter claimed formal Verifying");

        let command = match &spec.acceptance_criteria[0].kind {
            AcceptanceKind::Automated(command) => command.clone(),
            AcceptanceKind::HumanJudgment => unreachable!("fixture has automated criterion"),
        };
        let request_bytes = encode("formal-check command", &command).expect("encode command");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-claimed-formal".into(),
            idempotency_key: "key-claimed-formal".into(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(running.attempt.worker_lease.task_id.clone()),
            worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
            worker_lease: Some(running.attempt.worker_lease.clone()),
            causation_event_id: Some(verifying_event.event_id),
            correlation_id: "correlation-claimed-formal".into(),
            kind: EffectKind::RunCommand,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot: result.snapshot_id.clone(),
            created_at_unix_ms: 1_250,
        };
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&spec.sprint_id)
                .expect("claimed formal proposal sequence"),
            "event-claimed-formal-proposed",
        );
        let admission = TaskAttemptFormalCheckAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: "admission-claimed-formal".into(),
            attempt: running.attempt.clone(),
            criterion_ordinal: 0,
            criterion_id: "tests".into(),
            effect_id: intent.effect_id.clone(),
            runner_session_id: session.session_id.clone(),
            sealed_snapshot: result.snapshot_id.clone(),
            command: command.clone(),
            admitted_at_unix_ms: intent.created_at_unix_ms,
        };
        let capture_intent = v27_test_capture_intent(&intent, &launch, &session, "claimed-formal");
        let permit = match ledger
            .admit_task_attempt_formal_check_with_output_capture_for_dispatch(
                &admission,
                &intent,
                &proposal,
                &capture_intent,
            )
            .expect("fresh claimed formal admission")
        {
            TaskFormalCheckDispatchAdmission::Fresh { permit, .. } => permit,
            TaskFormalCheckDispatchAdmission::Existing { .. } => {
                panic!("new formal admission cannot be Existing")
            }
        };
        let (authority, capture_acquired) = if claim_dispatch {
            let dispatch_permit = FreshRunnerEffectDispatchPermit::TaskFormalCheck(permit);
            let acquired = v27_test_capture_acquired(
                &capture_intent,
                dispatch_permit
                    .expected_output_capture_dispatch_claim_id()
                    .expect("fresh formal capture exposes exact claim identity"),
                "claimed-formal",
                1_260,
            );
            let (_, transport) = ledger
                .claim_command_output_capture_dispatch(
                    dispatch_permit,
                    acquired.clone(),
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                )
                .expect("claim formal transport");
            (
                Some(
                    transport
                        .validate_transport_request(
                            &intent,
                            &request_bytes,
                            &launch,
                            &session,
                            None,
                            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                        )
                        .expect("validate formal transport"),
                ),
                Some(acquired),
            )
        } else {
            drop(permit);
            (None, None)
        };

        let output = b"claimed formal output".to_vec();
        let mut receipt = VerificationReceipt {
            receipt_id: "receipt-claimed-formal".into(),
            sprint_id: spec.sprint_id,
            task_id: Some(running.attempt.worker_lease.task_id.clone()),
            snapshot_id: result.snapshot_id.clone(),
            command,
            policy_hash: launch.policy_hash.clone(),
            exit_status: Some(0),
            termination: Some(CommandTerminationV1::Exited { code: 0 }),
            output_digest: Digest::sha256(&output),
            duration_ms: 10,
            finished_at_unix_ms: 1_300,
        };
        let (output_artifacts, output_evidence_bytes) = bind_complete_output_artifacts(
            &ledger,
            &mut receipt,
            &intent.effect_id,
            &launch.launch_id,
            &session.session_id,
            output,
        );
        let evidence = VerificationEffectEvidence {
            contract_version: CONTRACT_VERSION,
            verification: receipt.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: "observation-claimed-formal".into(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            output_artifacts,
            output_evidence_bytes,
        };
        let evidence_bytes =
            encode("verification effect evidence", &evidence).expect("encode formal evidence");
        let observation = effect_observation(
            &intent,
            &evidence.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            receipt.finished_at_unix_ms,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("claimed formal terminal sequence"),
            "event-claimed-formal-finished",
        );
        let check = TaskAttemptFormalCheck {
            contract_version: CONTRACT_VERSION,
            formal_check_id: "formal-check-claimed".into(),
            attempt: running.attempt,
            criterion_ordinal: admission.criterion_ordinal,
            criterion_id: admission.criterion_id.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: observation.observation_id.clone(),
            verification_receipt: receipt,
            runner_session_id: session.session_id.clone(),
            sealed_snapshot: result.snapshot_id,
        };
        let capture_terminal = capture_acquired.as_ref().map(|acquired| {
            v27_test_published_capture_terminal(
                &capture_intent,
                acquired,
                &observation,
                evidence
                    .output_artifacts
                    .clone()
                    .expect("current formal evidence carries complete artifacts"),
                "claimed-formal",
                1_310,
            )
        });
        let command_cleanup = capture_acquired.as_ref().map(|_| {
            v27_test_command_cleanup(
                &intent,
                &observation,
                &launch,
                &session,
                "claimed-formal",
                1_305,
            )
        });
        let clean_scan_receipt = capture_acquired
            .as_ref()
            .zip(capture_terminal.as_ref())
            .map(|(acquired, terminal)| {
                v29_test_clean_scan_receipt(
                    &capture_intent,
                    acquired,
                    terminal,
                    CommandTerminationV1::Exited { code: 0 },
                    "claimed-formal",
                )
            });
        ClaimedFormalTerminalFixture {
            database,
            ledger,
            authority,
            capture_terminal,
            clean_scan_receipt,
            command_cleanup,
            intent,
            proposal,
            admission,
            check,
            observation,
            terminal,
            evidence,
        }
    }

    struct ClaimedIntegrationTerminalFixture {
        candidate: V15CandidateFixture,
        authority: Option<RunnerEffectObservationAuthority>,
        intent: EffectIntent,
        proposal: AgentEvent,
        admission: TaskAttemptIntegrationAdmission,
        disposition: TaskAttemptDisposition,
        observation: EffectObservation,
        terminal: AgentEvent,
        evidence: TaskIntegrationEvidence,
        transition: AgentEvent,
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_claimed_integration_terminal_fixture(
        claim_dispatch: bool,
    ) -> ClaimedIntegrationTerminalFixture {
        let mut candidate = prepare_v15_candidate_fixture(false);
        let artifact = TaskIntegrationArtifactReference {
            format_version: 1,
            artifact_digest: Digest::sha256(b"claimed-integration-artifact"),
            change_set_id: candidate.change_set.change_set_id.clone(),
            base_snapshot: candidate.change_set.base_snapshot.clone(),
            result_snapshot: candidate.change_set.result_snapshot.clone(),
        };
        let request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: candidate.change_set.clone(),
            artifact: artifact.clone(),
        };
        let request_bytes =
            encode("task integration request", &request).expect("encode claimed integration");
        let admitted_at = candidate.candidate.admitted_at_unix_ms + 20;
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-claimed-integration".into(),
            idempotency_key: "key-claimed-integration".into(),
            sprint_id: candidate.spec.sprint_id.clone(),
            task_id: Some(candidate.attempt.worker_lease.task_id.clone()),
            worker_id: Some(candidate.attempt.worker_lease.worker_id.clone()),
            worker_lease: Some(candidate.attempt.worker_lease.clone()),
            causation_event_id: Some(candidate.candidate.transition_event_id.clone()),
            correlation_id: "correlation-claimed-integration".into(),
            kind: EffectKind::IntegrateChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: candidate.launch.policy_hash.clone(),
            input_snapshot: candidate.change_set.base_snapshot.clone(),
            created_at_unix_ms: admitted_at,
        };
        let proposal = effect_proposal_event(
            &intent,
            candidate
                .ledger
                .next_sequence(&candidate.spec.sprint_id)
                .expect("claimed integration proposal sequence"),
            "event-claimed-integration-proposed",
        );
        let admission = TaskAttemptIntegrationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: "admission-claimed-integration".into(),
            candidate_boundary: candidate.candidate.clone(),
            effect_id: intent.effect_id.clone(),
            runner_launch_id: candidate.launch.launch_id.clone(),
            runner_session_id: candidate.launch.session_id.clone(),
            input_snapshot: candidate.change_set.base_snapshot.clone(),
            result_snapshot: candidate.result_snapshot.snapshot_id.clone(),
            admitted_at_unix_ms: admitted_at,
        };
        let permit = match candidate
            .ledger
            .admit_task_attempt_integration_for_dispatch(&admission, &intent, &request, &proposal)
            .expect("fresh claimed integration admission")
        {
            TaskIntegrationDispatchAdmission::Fresh { permit, .. } => permit,
            TaskIntegrationDispatchAdmission::Existing { .. } => {
                panic!("new integration admission cannot be Existing")
            }
        };
        let session = candidate
            .ledger
            .load_runner_session(&candidate.spec.sprint_id, &candidate.launch.session_id)
            .expect("load claimed integration session");
        let authority = if claim_dispatch {
            let (_, transport) = candidate
                .ledger
                .claim_runner_effect_dispatch(
                    FreshRunnerEffectDispatchPermit::TaskIntegration(permit),
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                )
                .expect("claim integration transport");
            Some(
                transport
                    .validate_transport_request(
                        &intent,
                        &request_bytes,
                        &candidate.launch,
                        &session,
                        None,
                        OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                    )
                    .expect("validate integration transport"),
            )
        } else {
            drop(permit);
            None
        };

        let integrated_at = admitted_at + 40;
        let receipt = TaskIntegrationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "receipt-claimed-integration".into(),
            sprint_id: candidate.spec.sprint_id.clone(),
            task_id: candidate.attempt.worker_lease.task_id.clone(),
            worker_id: candidate.attempt.worker_lease.worker_id.clone(),
            worker_lease: Some(candidate.attempt.worker_lease.clone()),
            worker_launch_id: candidate.launch.launch_id.clone(),
            worker_session_id: candidate.launch.session_id.clone(),
            worker_policy_hash: candidate.launch.policy_hash.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: "observation-claimed-integration".into(),
            change_set_id: candidate.change_set.change_set_id.clone(),
            input_snapshot: candidate.change_set.base_snapshot.clone(),
            result_snapshot: candidate.change_set.result_snapshot.clone(),
            task_verification_receipt_ids: candidate.candidate.verification_receipt_ids.clone(),
            integration_ordinal: 0,
            integrated_at_unix_ms: integrated_at,
        };
        let evidence = TaskIntegrationEvidence {
            contract_version: CONTRACT_VERSION,
            receipt: receipt.clone(),
            artifact,
            validation: crate::TaskIntegrationValidationEvidence {
                mode: TaskIntegrationValidationMode::WorkerPublication,
                runner_launch_id: candidate.launch.launch_id.clone(),
                runner_session_id: candidate.launch.session_id.clone(),
                policy_hash: candidate.launch.policy_hash.clone(),
                grant_hash: candidate.launch.grant_hash.clone(),
                private_state_digest: candidate.launch.private_state_digest.clone(),
            },
        };
        let evidence_bytes =
            encode("task integration evidence", &evidence).expect("encode integration evidence");
        let observation = effect_observation(
            &intent,
            &receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            integrated_at,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            candidate
                .ledger
                .next_sequence(&candidate.spec.sprint_id)
                .expect("claimed integration terminal sequence"),
            "event-claimed-integration-finished",
        );
        let disposed_at = integrated_at + 10;
        let transition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: terminal.sequence + 1,
            event_id: "event-claimed-integration-integrated".into(),
            sprint_id: candidate.spec.sprint_id.clone(),
            task_id: Some(candidate.attempt.worker_lease.task_id.clone()),
            worker_id: Some(candidate.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(terminal.event_id.clone()),
            correlation_id: intent.correlation_id.clone(),
            policy_hash: Some(candidate.launch.policy_hash.clone()),
            occurred_at_unix_ms: disposed_at,
            payload: AgentEventKind::TaskStateChanged {
                from: "Candidate".into(),
                to: "Integrated".into(),
            },
        };
        let disposition =
            TaskAttemptDisposition::Integrated(crate::TaskAttemptIntegratedDisposition {
                metadata: TaskAttemptDispositionMetadata {
                    contract_version: CONTRACT_VERSION,
                    disposition_id: "disposition-claimed-integration".into(),
                    attempt: candidate.attempt.clone(),
                    from_state: TaskState::Candidate,
                    state_transition_event_id: transition.event_id.clone(),
                    disposed_at_unix_ms: disposed_at,
                },
                candidate_boundary: candidate.candidate.clone(),
                integration_receipt: receipt,
                evidence: crate::TaskAttemptEvidence::new(
                    "evidence-claimed-integration".into(),
                    crate::TaskAttemptEvidenceKind::Integrated,
                    evidence_bytes,
                )
                .expect("typed claimed integration disposition evidence"),
            });

        ClaimedIntegrationTerminalFixture {
            candidate,
            authority,
            intent,
            proposal,
            admission,
            disposition,
            observation,
            terminal,
            evidence,
            transition,
        }
    }

    fn unclaimed_task_phase_dispatch_claim(
        ledger: &EventLedger,
        intent: &EffectIntent,
        authority: RunnerEffectRequestAuthority,
    ) -> PersistedRunnerEffectDispatchClaim {
        let binding = load_effect_runner_binding(&ledger.connection, intent)
            .expect("load unclaimed task-phase runner binding");
        let session = binding
            .session
            .expect("unclaimed task-phase effect has an initialized session");
        PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&intent.effect_id),
            effect_id: intent.effect_id.clone(),
            sprint_id: intent.sprint_id.clone(),
            launch_id: binding.launch.launch_id,
            session_id: session.session_id,
            running_boundary_id: None,
            authority,
            request_digest: intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES),
            policy_hash: intent.policy_hash.clone(),
            input_snapshot: intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        }
    }

    fn insert_raw_v20_task_phase_claim(
        transaction: &Transaction<'_>,
        claim: &PersistedRunnerEffectDispatchClaim,
        companion: &RunnerEffectRequestAuthority,
    ) -> Result<(), LedgerError> {
        if let Some(capture) =
            command_output_capture_authority::load_from_effect(transaction, &claim.effect_id)?
            && capture.acquired.is_none()
        {
            let acquired = v27_test_capture_acquired(
                &capture.intent,
                claim.dispatch_claim_id.clone(),
                &format!("raw-v20:{}", claim.effect_id),
                capture.intent.created_at_unix_ms + 1,
            );
            command_output_capture_authority::insert_acquired(
                transaction,
                &capture.intent,
                &acquired,
            )?;
        }
        let (authority_class, running, formal, integration) = match companion {
            RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id,
            } => (
                "TaskRunning",
                Some(running_boundary_id.as_str()),
                None,
                None,
            ),
            RunnerEffectRequestAuthority::TaskFormalCheck {
                formal_check_admission_id,
            } => (
                "TaskFormalCheck",
                None,
                Some(formal_check_admission_id.as_str()),
                None,
            ),
            RunnerEffectRequestAuthority::TaskIntegration {
                integration_admission_id,
            } => (
                "TaskIntegration",
                None,
                None,
                Some(integration_admission_id.as_str()),
            ),
            _ => unreachable!("raw v20 test helper accepts only implemented task phases"),
        };
        transaction.execute(
            "INSERT INTO runner_effect_dispatch_claim_authorities (
                dispatch_claim_id, authority_class, running_boundary_id,
                formal_check_admission_id, integration_admission_id,
                sprint_phase_event_id, rollback_reference_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6)",
            params![
                claim.dispatch_claim_id,
                authority_class,
                running,
                formal,
                integration,
                i64::from(claim.contract_version),
            ],
        )?;
        transaction.execute(
            "INSERT INTO runner_effect_dispatch_claims (
                dispatch_claim_id, effect_id, sprint_id, launch_id, session_id,
                running_boundary_id, request_digest,
                opaque_transport_request_digest, policy_hash, input_snapshot,
                contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                claim.dispatch_claim_id,
                claim.effect_id,
                claim.sprint_id,
                claim.launch_id,
                claim.session_id,
                claim.running_boundary_id,
                claim.request_digest.as_str(),
                claim.opaque_transport_request_digest.as_str(),
                claim.policy_hash.as_str(),
                claim.input_snapshot.as_str(),
                i64::from(claim.contract_version),
            ],
        )?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Raw insert, crossed companion, rollback, and corrupt readback form one adversarial proof.
    fn v20_raw_formal_claim_requires_exact_companion_and_missing_readback_is_corrupt() {
        let mut fixture = prepare_claimed_formal_terminal_fixture(false);
        let claim = unclaimed_task_phase_dispatch_claim(
            &fixture.ledger,
            &fixture.intent,
            RunnerEffectRequestAuthority::TaskFormalCheck {
                formal_check_admission_id: fixture.admission.admission_id.clone(),
            },
        );
        let transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start exact raw formal claim");
        insert_raw_v20_task_phase_claim(&transaction, &claim, &claim.authority)
            .expect("insert exact raw formal companion and parent");
        transaction.commit().expect("commit exact raw formal claim");
        let effect = fixture
            .ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("read exact raw formal claim");
        assert!(matches!(
            effect.dispatch_claim.as_ref().map(|claim| &claim.authority),
            Some(RunnerEffectRequestAuthority::TaskFormalCheck {
                formal_check_admission_id
            }) if formal_check_admission_id == &fixture.admission.admission_id
        ));

        fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER runner_effect_dispatch_claim_authorities_no_delete;")
            .expect("open only the immutable companion delete fence for corruption injection");
        fixture
            .ledger
            .connection
            .execute(
                "DELETE FROM runner_effect_dispatch_claim_authorities
                 WHERE dispatch_claim_id = ?1",
                [&claim.dispatch_claim_id],
            )
            .expect("delete exact formal companion");
        assert!(matches!(
            fixture.ledger.load_effect(&fixture.intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "runner effect dispatch claim authority",
                ..
            })
        ));

        let mut crossed = prepare_claimed_formal_terminal_fixture(false);
        let crossed_claim = unclaimed_task_phase_dispatch_claim(
            &crossed.ledger,
            &crossed.intent,
            RunnerEffectRequestAuthority::TaskFormalCheck {
                formal_check_admission_id: crossed.admission.admission_id.clone(),
            },
        );
        let running_boundary_id = crossed
            .ledger
            .connection
            .query_row(
                "SELECT boundary_id FROM task_attempt_running_boundaries
                 WHERE attempt_id = ?1",
                [&crossed.admission.attempt.attempt_id],
                |row| row.get::<_, String>(0),
            )
            .expect("load crossed formal Running boundary");
        let crossed_companion = RunnerEffectRequestAuthority::TaskRunning {
            running_boundary_id,
        };
        let transaction = crossed
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start crossed raw formal claim");
        let error =
            insert_raw_v20_task_phase_claim(&transaction, &crossed_claim, &crossed_companion)
                .expect_err("TaskRunning companion cannot authorize a formal parent");
        assert!(matches!(&error, LedgerError::Sql(_)), "{error:?}");
        assert_eq!(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM runner_effect_dispatch_claim_authorities",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count staged crossed formal companion"),
            1,
            "the valid but crossed companion must be staged before parent rejection"
        );
        assert_eq!(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM runner_effect_dispatch_claims",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count rejected crossed formal parent"),
            0
        );
        transaction
            .rollback()
            .expect("roll back crossed raw formal claim");
        assert_eq!(
            row_count(&crossed.ledger, "runner_effect_dispatch_claims"),
            0
        );
        assert_eq!(
            row_count(&crossed.ledger, "runner_effect_dispatch_claim_authorities"),
            0
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Raw insert, crossed companion, rollback, and corrupt readback form one adversarial proof.
    fn v20_raw_integration_claim_requires_exact_companion_and_corrupt_readback_fails() {
        let mut fixture = prepare_claimed_integration_terminal_fixture(false);
        let claim = unclaimed_task_phase_dispatch_claim(
            &fixture.candidate.ledger,
            &fixture.intent,
            RunnerEffectRequestAuthority::TaskIntegration {
                integration_admission_id: fixture.admission.admission_id.clone(),
            },
        );
        let transaction = fixture
            .candidate
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start exact raw integration claim");
        insert_raw_v20_task_phase_claim(&transaction, &claim, &claim.authority)
            .expect("insert exact raw integration companion and parent");
        transaction
            .commit()
            .expect("commit exact raw integration claim");
        let effect = fixture
            .candidate
            .ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("read exact raw integration claim");
        assert!(matches!(
            effect.dispatch_claim.as_ref().map(|claim| &claim.authority),
            Some(RunnerEffectRequestAuthority::TaskIntegration {
                integration_admission_id
            }) if integration_admission_id == &fixture.admission.admission_id
        ));

        fixture
            .candidate
            .ledger
            .connection
            .execute_batch("DROP TRIGGER runner_effect_dispatch_claim_authorities_no_update;")
            .expect("open only the immutable companion update fence for corruption injection");
        fixture
            .candidate
            .ledger
            .connection
            .execute(
                "UPDATE runner_effect_dispatch_claim_authorities
                 SET contract_version = contract_version + 1
                 WHERE dispatch_claim_id = ?1",
                [&claim.dispatch_claim_id],
            )
            .expect("cross integration companion version");
        assert!(matches!(
            fixture
                .candidate
                .ledger
                .load_effect(&fixture.intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "runner effect dispatch claim authority",
                ..
            })
        ));

        let mut crossed = prepare_claimed_integration_terminal_fixture(false);
        let crossed_claim = unclaimed_task_phase_dispatch_claim(
            &crossed.candidate.ledger,
            &crossed.intent,
            RunnerEffectRequestAuthority::TaskIntegration {
                integration_admission_id: crossed.admission.admission_id.clone(),
            },
        );
        let crossed_companion = RunnerEffectRequestAuthority::TaskRunning {
            running_boundary_id: crossed.candidate.running.boundary_id.clone(),
        };
        let transaction = crossed
            .candidate
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start crossed raw integration claim");
        let error =
            insert_raw_v20_task_phase_claim(&transaction, &crossed_claim, &crossed_companion)
                .expect_err("TaskRunning companion cannot authorize an integration parent");
        assert!(matches!(&error, LedgerError::Sql(_)), "{error:?}");
        assert_eq!(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM runner_effect_dispatch_claim_authorities",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count staged crossed integration companion"),
            1,
            "the valid but crossed companion must be staged before parent rejection"
        );
        assert_eq!(
            transaction
                .query_row(
                    "SELECT COUNT(*) FROM runner_effect_dispatch_claims",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count rejected crossed integration parent"),
            0
        );
        transaction
            .rollback()
            .expect("roll back crossed raw integration claim");
        assert_eq!(
            row_count(&crossed.candidate.ledger, "runner_effect_dispatch_claims"),
            0
        );
        assert_eq!(
            row_count(
                &crossed.candidate.ledger,
                "runner_effect_dispatch_claim_authorities"
            ),
            0
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn claimed_formal_terminal_is_atomic_retryable_and_claim_bound() {
        let mut fixture = prepare_claimed_formal_terminal_fixture(true);
        let claim_id = fixture
            .authority
            .as_ref()
            .expect("claimed formal authority")
            .claim
            .dispatch_claim_id
            .clone();

        match fixture
            .ledger
            .admit_task_attempt_formal_check_for_dispatch(
                &fixture.admission,
                &fixture.intent,
                &fixture.proposal,
            )
            .expect("claimed formal admission exact replay")
        {
            TaskFormalCheckDispatchAdmission::Existing { admission, effect } => {
                assert_eq!(admission, fixture.admission);
                assert_eq!(
                    effect
                        .dispatch_claim
                        .as_ref()
                        .map(|claim| claim.dispatch_claim_id.as_str()),
                    Some(claim_id.as_str())
                );
            }
            TaskFormalCheckDispatchAdmission::Fresh { .. } => {
                panic!("claimed formal admission cannot remint fresh authority")
            }
        }

        assert!(matches!(
            fixture.ledger.complete_task_attempt_formal_check(
                &fixture.check,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "task attempt formal check",
                ..
            })
        ));
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
        assert_eq!(row_count(&fixture.ledger, "task_attempt_formal_checks"), 0);

        let premature_transition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("premature formal transition sequence"),
            event_id: "event-claimed-formal-premature-candidate".into(),
            sprint_id: fixture.intent.sprint_id.clone(),
            task_id: fixture.intent.task_id.clone(),
            worker_id: fixture.intent.worker_id.clone(),
            causation_id: fixture.intent.causation_event_id.clone(),
            correlation_id: fixture.intent.correlation_id.clone(),
            policy_hash: Some(fixture.intent.policy_hash.clone()),
            occurred_at_unix_ms: fixture.intent.created_at_unix_ms + 1,
            payload: AgentEventKind::TaskStateChanged {
                from: "Verifying".into(),
                to: "Candidate".into(),
            },
        };
        let transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start premature formal transition");
        let error = insert_agent_event(&transaction, &premature_transition)
            .expect_err("unobserved formal claim must fence Candidate transition");
        assert!(
            error
                .to_string()
                .contains("unobserved task dispatch claim blocks known task phase transition")
        );
        transaction
            .rollback()
            .expect("roll back premature formal transition");

        let authority = fixture.authority.take().expect("take formal authority");
        let mut crossed_evidence = fixture.evidence.clone();
        crossed_evidence.runner_session_id = "crossed-formal-session".into();
        let failure = fixture
            .ledger
            .complete_claimed_task_attempt_formal_check_with_output_capture(
                authority,
                &fixture.check,
                &fixture.observation,
                &fixture.terminal,
                &crossed_evidence,
                fixture
                    .capture_terminal
                    .as_ref()
                    .expect("claimed formal capture terminal"),
                fixture
                    .clean_scan_receipt
                    .as_ref()
                    .expect("claimed formal clean-scan receipt"),
                fixture
                    .command_cleanup
                    .as_ref()
                    .expect("claimed formal command cleanup"),
            )
            .expect_err("crossed formal evidence must fail before commit");
        assert!(failure.has_retry_authority());
        let (_, retry_authority) = failure.into_parts();
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
        assert_eq!(row_count(&fixture.ledger, "task_attempt_formal_checks"), 0);

        assert_eq!(
            fixture
                .ledger
                .complete_claimed_task_attempt_formal_check_with_output_capture(
                    retry_authority.expect("precommit failure returns exact formal authority"),
                    &fixture.check,
                    &fixture.observation,
                    &fixture.terminal,
                    &fixture.evidence,
                    fixture
                        .capture_terminal
                        .as_ref()
                        .expect("claimed formal capture terminal"),
                    fixture
                        .clean_scan_receipt
                        .as_ref()
                        .expect("claimed formal clean-scan receipt"),
                    fixture
                        .command_cleanup
                        .as_ref()
                        .expect("claimed formal command cleanup"),
                )
                .expect("commit claimed formal terminal boundary"),
            fixture.check
        );
        assert_eq!(
            fixture.terminal.causation_id.as_deref(),
            Some(fixture.proposal.event_id.as_str())
        );
        let effect = fixture
            .ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("load claimed formal effect");
        assert_eq!(effect.observation.as_ref(), Some(&fixture.observation));
        assert_eq!(
            effect
                .dispatch_claim
                .as_ref()
                .map(|claim| claim.dispatch_claim_id.as_str()),
            Some(claim_id.as_str())
        );
        match fixture
            .ledger
            .admit_task_attempt_formal_check_for_dispatch(
                &fixture.admission,
                &fixture.intent,
                &fixture.proposal,
            )
            .expect("observed formal admission exact replay")
        {
            TaskFormalCheckDispatchAdmission::Existing { admission, effect } => {
                assert_eq!(admission, fixture.admission);
                assert_eq!(effect.observation.as_ref(), Some(&fixture.observation));
            }
            TaskFormalCheckDispatchAdmission::Fresh { .. } => {
                panic!("observed formal admission cannot remint fresh authority")
            }
        }
        assert_eq!(row_count(&fixture.ledger, "task_attempt_formal_checks"), 1);
    }

    #[test]
    fn command_output_artifact_set_is_atomic_canonical_immutable_and_restart_safe() {
        let mut fixture = prepare_claimed_formal_terminal_fixture(true);
        let expected = fixture
            .evidence
            .output_artifacts
            .clone()
            .expect("current formal evidence has complete-output artifacts");
        fixture
            .ledger
            .complete_claimed_task_attempt_formal_check_with_output_capture(
                fixture.authority.take().expect("take formal authority"),
                &fixture.check,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
                fixture
                    .capture_terminal
                    .as_ref()
                    .expect("claimed formal capture terminal"),
                fixture
                    .clean_scan_receipt
                    .as_ref()
                    .expect("claimed formal clean-scan receipt"),
                fixture
                    .command_cleanup
                    .as_ref()
                    .expect("claimed formal command cleanup"),
            )
            .expect("atomically persist current formal output artifacts");
        assert_eq!(
            row_count(&fixture.ledger, "command_output_artifact_sets"),
            1
        );
        assert_eq!(
            fixture
                .ledger
                .load_command_output_artifact_set(&fixture.intent.effect_id)
                .expect("exactly read back command output artifacts"),
            expected
        );

        let reference_json =
            encode("command output artifact reference", &expected).expect("encode reference");
        assert!(
            fixture
                .ledger
                .connection
                .query_row(
                    "SELECT grok_command_output_artifact_reference_matches(
                         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
                     )",
                    params![
                        reference_json,
                        i64::from(expected.format_version),
                        expected.source.sprint_id,
                        expected.source.runner_launch_id,
                        expected.source.runner_session_id,
                        expected.source.effect_id,
                        expected.source.request_digest.as_str(),
                        expected.manifest_digest.as_str(),
                        sqlite_integer("test.stdout_byte_length", expected.stdout.byte_length + 1,)
                            .expect("crossed length fits SQLite"),
                        expected.stdout.content_digest.as_str(),
                        sqlite_integer("test.stderr_byte_length", expected.stderr.byte_length)
                            .expect("stderr length fits SQLite"),
                        expected.stderr.content_digest.as_str(),
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .is_err(),
            "raw SQL must reject a canonical reference crossed with indexed length"
        );
        for statement in [
            "UPDATE command_output_artifact_sets SET effect_id = effect_id",
            "DELETE FROM command_output_artifact_sets",
        ] {
            assert!(
                fixture.ledger.connection.execute_batch(statement).is_err(),
                "immutable artifact table admitted `{statement}`"
            );
        }

        let path = fixture.database.path.clone();
        drop(fixture.ledger);
        let reopened = EventLedger::open(&path).expect("reopen command output artifact ledger");
        assert_eq!(
            reopened
                .load_command_output_artifact_set(&fixture.intent.effect_id)
                .expect("restart-safe command output artifact readback"),
            expected
        );
        assert_eq!(
            reopened
                .load_verification_effect_evidence(&fixture.evidence.verification.receipt_id)
                .expect("restart-safe verification evidence readback"),
            fixture.evidence
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Migration readability, no-remint, and raw no-backfill are one historical cut.
    fn v26_migration_reads_v25_evidence_but_rejects_backfill_and_current_remint() {
        let database = TestDatabase::new();
        let historical = {
            let mut v25 = open_v25_test_ledger(&database);
            let (spec, graph) = sprint_fixture();
            v25.create_sprint(&spec, &graph, 1_000)
                .expect("persist v25 sprint");
            let base = draft_base_snapshot();
            v25.persist_workspace_snapshot(&spec.sprint_id, &base)
                .expect("persist v25 verification snapshot");
            let policy = compiled_test_policy("v25-output-artifact-migration-policy");
            let launch = runner_launch(
                "launch-v25-output-artifact-migration",
                "session-v25-output-artifact-migration",
                RunnerSessionPurpose::FinalVerifier,
                None,
                &policy,
                1_100,
            );
            admit_test_runner_launch(&mut v25, &launch, &policy);
            v25.register_runner_session(&runner_session(&launch, 1_110), &policy)
                .expect("register v25 final verifier");
            let command = match &spec.acceptance_criteria[0].kind {
                AcceptanceKind::Automated(command) => command.clone(),
                AcceptanceKind::HumanJudgment => unreachable!("fixture is automated"),
            };
            let receipt = VerificationReceipt {
                receipt_id: "verify-v25-output-artifact-migration".into(),
                sprint_id: spec.sprint_id,
                task_id: None,
                snapshot_id: base.snapshot_id,
                command,
                policy_hash: launch.policy_hash.clone(),
                exit_status: Some(0),
                termination: Some(CommandTerminationV1::Exited { code: 0 }),
                output_digest: digest('0'),
                duration_ms: 10,
                finished_at_unix_ms: 1_200,
            };
            let evidence = persist_verification_evidence(
                &mut v25,
                &launch,
                receipt,
                b"historical v25 complete output commitment".to_vec(),
                1_150,
            );
            assert_eq!(evidence.output_artifacts, None);
            evidence
        };
        let mut migrated =
            EventLedger::open(&database.path).expect("migrate v25 ledger to current");
        assert_eq!(
            migrated
                .connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("read migrated schema version"),
            SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_verification_effect_evidence(&historical.verification.receipt_id)
                .expect("historical v25 evidence remains readable"),
            historical
        );
        assert_eq!(row_count(&migrated, "command_output_artifact_sets"), 0);
        assert!(matches!(
            migrated.load_command_output_artifact_set(&historical.effect_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));

        let effect = migrated
            .load_effect(&historical.effect_id)
            .expect("load migrated historical verification effect");
        let observation = effect
            .observation
            .clone()
            .expect("historical verification has observation");
        let terminal = effect
            .terminal_event
            .clone()
            .expect("historical verification has terminal event");
        let remint = migrated
            .record_verification_effect_observation(&observation, &terminal, &historical)
            .expect_err("v25 evidence cannot remint current verification authority");
        assert!(remint.to_string().contains("output_artifacts"));

        let stdout = &historical.output_evidence_bytes;
        let forged_backfill = CommandOutputArtifactSetReferenceV1::try_new(
            CommandOutputArtifactSourceV1 {
                sprint_id: historical.verification.sprint_id.clone(),
                runner_launch_id: historical.runner_launch_id.clone(),
                runner_session_id: historical.runner_session_id.clone(),
                effect_id: historical.effect_id.clone(),
                request_digest: effect.intent.request_digest.clone(),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stdout,
                byte_length: u64::try_from(stdout.len()).expect("historical output length fits"),
                content_digest: Digest::sha256(stdout),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stderr,
                byte_length: 0,
                content_digest: Digest::sha256(&[]),
            },
        )
        .expect("construct structurally valid forbidden backfill");
        let reference_json = encode(
            "forbidden command output artifact backfill",
            &forged_backfill,
        )
        .expect("encode forbidden backfill");
        let error = migrated
            .connection
            .execute(
                "INSERT INTO command_output_artifact_sets (
                    effect_id, observation_id, sprint_id, runner_launch_id,
                    runner_session_id, request_digest, format_version,
                    manifest_digest, stdout_byte_length, stdout_content_digest,
                    stderr_byte_length, stderr_content_digest, reference_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    forged_backfill.source.effect_id,
                    historical.observation_id,
                    forged_backfill.source.sprint_id,
                    forged_backfill.source.runner_launch_id,
                    forged_backfill.source.runner_session_id,
                    forged_backfill.source.request_digest.as_str(),
                    i64::from(forged_backfill.format_version),
                    forged_backfill.manifest_digest.as_str(),
                    sqlite_integer(
                        "test.stdout_byte_length",
                        forged_backfill.stdout.byte_length,
                    )
                    .expect("stdout length fits SQLite"),
                    forged_backfill.stdout.content_digest.as_str(),
                    0_i64,
                    forged_backfill.stderr.content_digest.as_str(),
                    reference_json,
                ],
            )
            .expect_err("v26 must reject artifact backfill after terminal rows");
        assert!(
            error
                .to_string()
                .contains("must commit before their new terminal rows")
        );
        assert_eq!(row_count(&migrated, "command_output_artifact_sets"), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Retry custody and every atomic row cut form one proof.
    fn claimed_formal_late_precommit_failure_rolls_back_and_returns_same_authority() {
        let mut fixture = prepare_claimed_formal_terminal_fixture(true);
        let claim_id = fixture
            .authority
            .as_ref()
            .expect("claimed formal authority")
            .claim
            .dispatch_claim_id
            .clone();
        fixture
            .ledger
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER inject_claimed_formal_late_precommit_failure
                 BEFORE INSERT ON task_attempt_formal_checks
                 BEGIN
                   SELECT RAISE(ABORT, 'injected late claimed formal precommit failure');
                 END;",
            )
            .expect("install late precommit fault trigger");

        let failure = fixture
            .ledger
            .complete_claimed_task_attempt_formal_check_with_output_capture(
                fixture.authority.take().expect("take formal authority"),
                &fixture.check,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
                fixture
                    .capture_terminal
                    .as_ref()
                    .expect("claimed formal capture terminal"),
                fixture
                    .clean_scan_receipt
                    .as_ref()
                    .expect("claimed formal clean-scan receipt"),
                fixture
                    .command_cleanup
                    .as_ref()
                    .expect("claimed formal command cleanup"),
            )
            .expect_err("final typed-check insert must inject a precommit failure");
        assert!(
            failure
                .error()
                .to_string()
                .contains("injected late claimed formal precommit failure")
        );
        assert!(failure.has_retry_authority());
        let (_, retry_authority) = failure.into_parts();
        let retry_authority = retry_authority.expect("late precommit failure returns authority");
        assert_eq!(retry_authority.claim.dispatch_claim_id, claim_id);

        for table in [
            "command_output_artifact_sets",
            "verification_receipts",
            "verification_session_bindings",
            "verification_effect_evidence",
            "effect_evidence_payloads",
            "effect_observations",
            "task_attempt_formal_checks",
        ] {
            assert_eq!(
                row_count(&fixture.ledger, table),
                0,
                "late failure leaked a row in {table}"
            );
        }
        assert!(
            !fixture
                .ledger
                .connection
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM agent_events WHERE event_id = ?1)",
                    [&fixture.terminal.event_id],
                    |row| row.get::<_, bool>(0),
                )
                .expect("query rolled-back terminal event")
        );

        fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER inject_claimed_formal_late_precommit_failure;")
            .expect("remove late precommit fault trigger");
        assert_eq!(
            fixture
                .ledger
                .complete_claimed_task_attempt_formal_check_with_output_capture(
                    retry_authority,
                    &fixture.check,
                    &fixture.observation,
                    &fixture.terminal,
                    &fixture.evidence,
                    fixture
                        .capture_terminal
                        .as_ref()
                        .expect("claimed formal capture terminal"),
                    fixture
                        .clean_scan_receipt
                        .as_ref()
                        .expect("claimed formal clean-scan receipt"),
                    fixture
                        .command_cleanup
                        .as_ref()
                        .expect("claimed formal command cleanup"),
                )
                .expect("retry exact formal terminal after definite rollback"),
            fixture.check
        );
        assert_eq!(
            fixture
                .ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("load retried claimed formal effect")
                .dispatch_claim
                .as_ref()
                .map(|claim| claim.dispatch_claim_id.as_str()),
            Some(claim_id.as_str())
        );
    }

    #[test]
    fn claimed_formal_generic_success_requires_typed_receipt() {
        let mut fixture = prepare_claimed_formal_terminal_fixture(true);
        let evidence_bytes = encode("verification effect evidence", &fixture.evidence)
            .expect("encode claimed formal evidence");
        let observation_count = row_count(&fixture.ledger, "effect_observations");
        let formal_check_count = row_count(&fixture.ledger, "task_attempt_formal_checks");
        let failure = fixture
            .ledger
            .try_record_claimed_effect_observation(
                fixture.authority.take().expect("take formal authority"),
                &fixture.observation,
                &evidence_bytes,
                &fixture.terminal,
            )
            .expect_err("generic success cannot terminalize claimed formal authority");
        assert!(matches!(
            failure.error(),
            LedgerError::FinishReceiptRequired {
                effect_id,
                kind: EffectKind::RunCommand,
            } if effect_id == &fixture.intent.effect_id
        ));
        assert!(failure.has_retry_authority());
        assert_eq!(
            row_count(&fixture.ledger, "effect_observations"),
            observation_count
        );
        assert_eq!(
            row_count(&fixture.ledger, "task_attempt_formal_checks"),
            formal_check_count
        );
        let (_, authority) = failure.into_parts();
        fixture
            .ledger
            .complete_claimed_task_attempt_formal_check_with_output_capture(
                authority.expect("typed formal path retains precommit custody"),
                &fixture.check,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
                fixture
                    .capture_terminal
                    .as_ref()
                    .expect("claimed formal capture terminal"),
                fixture
                    .clean_scan_receipt
                    .as_ref()
                    .expect("claimed formal clean-scan receipt"),
                fixture
                    .command_cleanup
                    .as_ref()
                    .expect("claimed formal command cleanup"),
            )
            .expect("typed formal receipt remains the sole successful terminal path");
    }

    #[test]
    fn fresh_formal_admission_with_discarded_permit_rejects_claimless_terminals() {
        let mut fixture = prepare_claimed_formal_terminal_fixture(false);
        let evidence_bytes = encode("verification effect evidence", &fixture.evidence)
            .expect("encode unclaimed formal evidence");
        assert!(matches!(
            fixture.ledger.record_effect_observation(
                &fixture.observation,
                &evidence_bytes,
                &fixture.terminal,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "effect observation",
                ..
            })
        ));
        assert!(matches!(
            fixture.ledger.complete_task_attempt_formal_check(
                &fixture.check,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "task attempt formal check",
                ..
            })
        ));
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
        assert_eq!(row_count(&fixture.ledger, "task_attempt_formal_checks"), 0);
    }

    #[cfg(unix)]
    #[test]
    fn claimed_formal_terminal_postcommit_uncertainty_has_no_retry_custody() {
        let mut fixture = prepare_claimed_formal_terminal_fixture(true);
        let hardlink = fixture
            .database
            .directory
            .join("claimed-formal-terminal-postcommit-hardlink.sqlite3");
        fs::hard_link(&fixture.database.path, &hardlink)
            .expect("inject claimed formal post-commit hardening fault");
        let failure = fixture
            .ledger
            .complete_claimed_task_attempt_formal_check_with_output_capture(
                fixture.authority.take().expect("take formal authority"),
                &fixture.check,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
                fixture
                    .capture_terminal
                    .as_ref()
                    .expect("claimed formal capture terminal"),
                fixture
                    .clean_scan_receipt
                    .as_ref()
                    .expect("claimed formal clean-scan receipt"),
                fixture
                    .command_cleanup
                    .as_ref()
                    .expect("claimed formal command cleanup"),
            )
            .expect_err("post-commit uncertainty is reconciliation-only");
        fs::remove_file(&hardlink).expect("remove claimed formal hardening fault");
        assert!(matches!(
            failure.error(),
            LedgerError::PostCommitStateUncertain {
                operation: "claimed task attempt formal check",
                recovery_id,
                ..
            } if recovery_id == &fixture.intent.effect_id
        ));
        assert!(!failure.has_retry_authority());
        assert!(failure.into_parts().1.is_none());
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_formal_check(&fixture.check.formal_check_id)
                .expect("reconcile committed claimed formal check"),
            fixture.check
        );
        assert_eq!(
            fixture
                .ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("reconcile committed claimed formal observation")
                .observation,
            Some(fixture.observation)
        );
        assert_eq!(
            fixture
                .ledger
                .load_command_output_artifact_set(&fixture.intent.effect_id)
                .expect("reconcile committed complete-output artifact reference"),
            fixture
                .evidence
                .output_artifacts
                .clone()
                .expect("current claimed formal evidence has output artifacts")
        );
    }

