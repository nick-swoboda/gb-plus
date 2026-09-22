    #[test]
    #[allow(clippy::too_many_lines)] // Two independent leases and one full cleanup prove task-local terminal fencing.
    fn terminal_task_transition_ignores_unrelated_active_worker_lease() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let (mut spec, mut graph) = sprint_fixture();
        spec.max_workers = 2;
        graph.tasks[0].path_scopes = vec![PathScope::Relative(PathBuf::from("task-a"))];
        graph.tasks.push(TaskSpec {
            task_id: "task-2".into(),
            goal: "Run independently".into(),
            dependencies: Vec::new(),
            path_scopes: vec![PathScope::Relative(PathBuf::from("task-b"))],
            acceptance_checks: vec!["tests".into()],
            base_snapshot: spec.base_snapshot.clone(),
            required: true,
        });
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist two-task sprint");
        ledger
            .persist_workspace_snapshot(
                &spec.sprint_id,
                &WorkspaceSnapshot {
                    snapshot_id: spec.base_snapshot.clone(),
                    grant_hash: spec.workspace_grant.grant_hash.clone(),
                    created_at_unix_ms: 1_000,
                },
            )
            .expect("persist base snapshot");

        let ready_a = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&spec.sprint_id)
                .expect("task A ready sequence"),
            event_id: "task-a-ready".into(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: None,
            causation_id: None,
            correlation_id: "task-a-lifecycle".into(),
            policy_hash: None,
            occurred_at_unix_ms: 1_050,
            payload: AgentEventKind::TaskStateChanged {
                from: "Planned".into(),
                to: "Ready".into(),
            },
        };
        ledger.append_event(&ready_a).expect("ready task A");
        let lease_a = WorkerLease::new(
            spec.sprint_id.clone(),
            1,
            "task-1".into(),
            "worker-a".into(),
            graph.tasks[0].path_scopes.clone(),
            1_060,
        )
        .expect("canonical task A lease");
        let acquire_a = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&spec.sprint_id)
                .expect("task A lease sequence"),
            event_id: "task-a-leased".into(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(lease_a.task_id.clone()),
            worker_id: Some(lease_a.worker_id.clone()),
            causation_id: Some(ready_a.event_id.clone()),
            correlation_id: "task-a-lifecycle".into(),
            policy_hash: None,
            occurred_at_unix_ms: lease_a.acquired_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Ready".into(),
                to: "Leased".into(),
            },
        };
        ledger
            .acquire_task_attempt(&lease_a, &acquire_a)
            .expect("acquire task A lease");

        let ready_b = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&spec.sprint_id)
                .expect("task B ready sequence"),
            event_id: "task-b-ready".into(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some("task-2".into()),
            worker_id: None,
            causation_id: None,
            correlation_id: "task-b-lifecycle".into(),
            policy_hash: None,
            occurred_at_unix_ms: 1_070,
            payload: AgentEventKind::TaskStateChanged {
                from: "Planned".into(),
                to: "Ready".into(),
            },
        };
        ledger.append_event(&ready_b).expect("ready task B");
        let lease_b = WorkerLease::new(
            spec.sprint_id.clone(),
            2,
            "task-2".into(),
            "worker-b".into(),
            graph.tasks[1].path_scopes.clone(),
            1_080,
        )
        .expect("canonical task B lease");
        let acquire_b = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&spec.sprint_id)
                .expect("task B lease sequence"),
            event_id: "task-b-leased".into(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(lease_b.task_id.clone()),
            worker_id: Some(lease_b.worker_id.clone()),
            causation_id: Some(ready_b.event_id.clone()),
            correlation_id: "task-b-lifecycle".into(),
            policy_hash: None,
            occurred_at_unix_ms: lease_b.acquired_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Ready".into(),
                to: "Leased".into(),
            },
        };
        ledger
            .acquire_task_attempt(&lease_b, &acquire_b)
            .expect("acquire task B lease");

        let policy = compiled_shadow_test_policy("task-local-terminal-policy");
        let mut launch_a = runner_launch(
            "launch-task-a",
            "session-task-a",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-a"),
            &policy,
            1_100,
        );
        launch_a.worker_lease = Some(lease_a.clone());
        let (cleanup_intent, _, cleanup_request_bytes, cleanup_event) =
            test_runner_launch_cleanup_contracts(
                &ledger,
                &launch_a,
                WorkerCleanupBackend::LinuxCgroupV2,
            )
            .expect("build task A cleanup admission");
        ledger
            .admit_runner_launch_with_cleanup(
                &launch_a,
                &policy,
                &cleanup_intent,
                &cleanup_request_bytes,
                &cleanup_event,
            )
            .expect("admit task A cleanup");
        let attempt_a = ledger
            .load_task_attempt(&lease_a.lease_id)
            .expect("load task A attempt authority");
        let outcome = TaskAttemptKnownCleanupOutcome::PermanentFailure(
            crate::TaskAttemptPermanentFailureCause::PermanentContractViolation {
                violation_id: "task-a-permanent-contract-violation".into(),
                evidence: crate::TaskAttemptEvidence::new(
                    "task-a-permanent-contract-violation-evidence".into(),
                    crate::TaskAttemptEvidenceKind::PermanentContractViolation,
                    b"task A cannot satisfy its immutable contract".to_vec(),
                )
                .expect("construct task A permanent-failure evidence"),
            },
        );
        ledger
            .record_task_attempt_cleanup_outcome_authority(&attempt_a, &outcome, 1_150)
            .expect("record independent task A failure authority");
        let cleanup_sequence = ledger
            .next_sequence(&spec.sprint_id)
            .expect("task A cleanup sequence");
        let metadata = TaskAttemptDispositionMetadata {
            contract_version: CONTRACT_VERSION,
            disposition_id: "task-a-permanent-disposition".into(),
            attempt: attempt_a.clone(),
            from_state: TaskState::Leased,
            state_transition_event_id: "task-a-failed".into(),
            disposed_at_unix_ms: 1_250,
        };
        let failed_a = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: cleanup_sequence + 1,
            event_id: metadata.state_transition_event_id.clone(),
            sprint_id: spec.sprint_id.clone(),
            task_id: Some(lease_a.task_id.clone()),
            worker_id: Some(lease_a.worker_id.clone()),
            causation_id: Some(attempt_a.opening_event_id.clone()),
            correlation_id: "task-a-lifecycle".into(),
            policy_hash: Some(launch_a.policy_hash.clone()),
            occurred_at_unix_ms: metadata.disposed_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Leased".into(),
                to: "Failed".into(),
            },
        };
        let disposition = ledger
            .with_task_attempt_cleanup_disposition_exclusion(
                &metadata,
                &outcome,
                "task-a-cleanup-release",
                &failed_a,
                |claim| {
                    assert_eq!(claim.next_event_sequence(), cleanup_sequence);
                    Ok(cleanup_terminal_from_live_claim(claim, "task-a", 1_200))
                },
            )
            .expect("atomically clean and fail task A");
        assert!(matches!(
            disposition,
            TaskAttemptDisposition::PermanentFailure(_)
        ));
        assert_eq!(
            ledger
                .load_active_worker_leases(&spec.sprint_id)
                .expect("task B lease remains active"),
            vec![lease_b]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The closed outcome matrix and exact-set replay belong to one lifecycle.
    fn command_domain_cleanup_exact_set_is_closed_idempotent_and_restart_safe() {
        let database = TestDatabase::new();
        // v27 joins command cleanup into the capture terminal atomically. This
        // suite preserves the pre-v27 standalone cleanup-set compatibility
        // contract; current atomic behavior is covered by the v27 tests.
        let mut ledger = open_v26_test_ledger(&database);
        let (_policy, launch, session) = prepare_command_domain_session(&mut ledger);
        let cases = [
            (
                "effect-z-succeeded",
                EffectOutcome::Succeeded {
                    evidence_digest: effect_evidence_digest(),
                },
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            ),
            (
                "effect-a-failed-before",
                EffectOutcome::FailedBeforeEffect {
                    evidence_digest: effect_evidence_digest(),
                },
                CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
            ),
            (
                "effect-m-failed-after",
                EffectOutcome::FailedAfterKnownEffect {
                    evidence_digest: effect_evidence_digest(),
                },
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            ),
            (
                "effect-b-cancelled",
                EffectOutcome::CancelledBeforeEffect {
                    evidence_digest: effect_evidence_digest(),
                },
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            ),
        ];
        for (index, (effect_id, outcome, _)) in cases.iter().enumerate() {
            let created_at = 1_200 + u64::try_from(index).expect("small index") * 100;
            let (intent, proposal, permit) =
                persist_command_domain_intent(&mut ledger, &launch, effect_id, created_at);
            persist_command_domain_observation(
                &mut ledger,
                &intent,
                &proposal,
                permit,
                outcome.clone(),
                created_at + 50,
            );
        }

        let bindings = ledger
            .load_command_domain_effect_bindings("sprint-1", &launch.launch_id, &session.session_id)
            .expect("derive exact command set");
        let expected_effect_ids = vec![
            "effect-a-failed-before".to_owned(),
            "effect-b-cancelled".to_owned(),
            "effect-m-failed-after".to_owned(),
            "effect-z-succeeded".to_owned(),
        ];
        assert_eq!(
            bindings
                .iter()
                .map(|binding| binding.effect_id.clone())
                .collect::<Vec<_>>(),
            expected_effect_ids
        );
        assert_eq!(
            ledger
                .load_command_domain_cleanup_completeness(
                    "sprint-1",
                    &launch.launch_id,
                    &session.session_id,
                    CommandDomainBackend::MacOsDedicatedIdentity,
                )
                .expect("derive missing set"),
            CommandDomainCleanupCompleteness::Incomplete(
                CommandDomainCleanupIncomplete::MissingProofs {
                    effect_ids: expected_effect_ids.clone(),
                }
            )
        );

        let first_binding = &bindings[0];
        let mut collided = command_domain_proof(
            first_binding,
            "proof-global-collision",
            CommandDomainBackend::MacOsDedicatedIdentity,
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
            1_700,
        );
        ledger
            .connection
            .execute(
                "INSERT INTO finish_receipt_ids (
                    receipt_id, sprint_id, receipt_kind, contract_version
                 ) VALUES (?1, 'sprint-1', 'VerifiedNoOp', ?2)",
                params![collided.proof_id, i64::from(CONTRACT_VERSION)],
            )
            .expect("reserve a historical global receipt identity");
        assert!(matches!(
            ledger.record_command_domain_cleanup_proof(&collided),
            Err(LedgerError::ArtifactAlreadyExists { .. })
        ));
        collided.proof_id = "proof-request-substitution".into();
        collided.request_digest = digest('d');
        assert!(matches!(
            ledger.record_command_domain_cleanup_proof(&collided),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let mut crossed = command_domain_proof(
            first_binding,
            "proof-crossed-session",
            CommandDomainBackend::MacOsDedicatedIdentity,
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
            1_700,
        );
        crossed.session_id = "session-not-the-binding".into();
        assert!(matches!(
            ledger.record_command_domain_cleanup_proof(&crossed),
            Err(LedgerError::ArtifactNotFound { .. } | LedgerError::ReferenceMismatch { .. })
        ));

        let mut persisted = Vec::new();
        for (index, binding) in bindings.iter().enumerate() {
            let disposition = cases
                .iter()
                .find(|(effect_id, _, _)| *effect_id == binding.effect_id)
                .map(|(_, _, disposition)| *disposition)
                .expect("matrix contains exact effect");
            let proof = command_domain_proof(
                binding,
                &format!("proof-{}", binding.effect_id),
                CommandDomainBackend::MacOsDedicatedIdentity,
                disposition,
                1_800 + u64::try_from(index).expect("small index"),
            );
            if binding.state == CommandDomainEffectState::Succeeded {
                let mut invalid = proof.clone();
                invalid.disposition = CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect;
                assert!(matches!(
                    ledger.record_command_domain_cleanup_proof(&invalid),
                    Err(LedgerError::ReferenceMismatch { .. })
                ));
            }
            if index == 1 {
                let mut confused = proof.clone();
                confused.backend = CommandDomainBackend::LinuxCgroupV2;
                assert!(matches!(
                    ledger.record_command_domain_cleanup_proof(&confused),
                    Err(LedgerError::ReferenceMismatch { .. })
                ));
            }
            let first = ledger
                .record_command_domain_cleanup_proof(&proof)
                .expect("persist exact command cleanup proof");
            assert_eq!(
                ledger
                    .record_command_domain_cleanup_proof(&proof)
                    .expect("exact proof replay is idempotent"),
                first
            );
            persisted.push(first);
        }
        let mut different_duplicate = persisted[0].proof.clone();
        different_duplicate.proof_id = "different-proof-for-same-effect".into();
        different_duplicate.platform_proof_bytes = b"different native proof".to_vec();
        different_duplicate.platform_proof_digest =
            Digest::sha256(&different_duplicate.platform_proof_bytes);
        assert!(matches!(
            ledger.record_command_domain_cleanup_proof(&different_duplicate),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let reverse_collision = ledger.connection.execute(
            "INSERT INTO finish_receipt_ids (
                receipt_id, sprint_id, receipt_kind, contract_version
             ) VALUES (?1, 'sprint-1', 'VerifiedNoOp', ?2)",
            params![persisted[0].proof.proof_id, i64::from(CONTRACT_VERSION)],
        );
        assert!(reverse_collision.is_err());
        let mut oversized = persisted[0].proof.clone();
        oversized.proof_id = "oversized-native-proof".into();
        oversized.platform_proof_bytes = vec![b'x'; MAX_COMMAND_DOMAIN_PLATFORM_PROOF_BYTES + 1];
        oversized.platform_proof_digest = Digest::sha256(&oversized.platform_proof_bytes);
        assert!(oversized.validate().is_err());

        let complete = ledger
            .load_command_domain_cleanup_completeness(
                "sprint-1",
                &launch.launch_id,
                &session.session_id,
                CommandDomainBackend::MacOsDedicatedIdentity,
            )
            .expect("derive complete exact set");
        let CommandDomainCleanupCompleteness::Complete(complete_set) = &complete else {
            panic!("all exact known outcomes and proofs must be complete");
        };
        assert_eq!(complete_set.entries, persisted);
        assert!(matches!(
            ledger.load_command_domain_cleanup_completeness(
                "sprint-1",
                &launch.launch_id,
                &session.session_id,
                CommandDomainBackend::LinuxCgroupV2,
            ),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        assert!(
            ledger
                .connection
                .execute(
                    "UPDATE command_domain_cleanup_proofs
                     SET backend = backend WHERE effect_id = ?1",
                    [&persisted[0].binding.effect_id],
                )
                .is_err()
        );
        assert!(
            ledger
                .connection
                .execute(
                    "DELETE FROM command_domain_cleanup_proofs WHERE effect_id = ?1",
                    [&persisted[0].binding.effect_id],
                )
                .is_err()
        );

        drop(ledger);
        let reader = reopen_test_legacy_ledger(&database);
        assert_eq!(
            reader
                .load_command_domain_cleanup_completeness(
                    "sprint-1",
                    &launch.launch_id,
                    &session.session_id,
                    CommandDomainBackend::MacOsDedicatedIdentity,
                )
                .expect("reopen exact cleanup set"),
            complete
        );
    }

    #[test]
    fn pre_observation_reaped_proof_survives_later_exact_result() {
        let database = TestDatabase::new();
        let mut ledger = open_v26_test_ledger(&database);
        let (_policy, launch, session) = prepare_command_domain_session(&mut ledger);
        let (intent, proposal, permit) =
            persist_command_domain_intent(&mut ledger, &launch, "effect-recovered-result", 1_200);
        let awaiting = ledger
            .load_command_domain_effect_bindings("sprint-1", &launch.launch_id, &session.session_id)
            .expect("derive unobserved binding")
            .pop()
            .expect("one command binding");
        assert_eq!(
            awaiting.state,
            CommandDomainEffectState::AwaitingObservation
        );
        let forbidden_no_domain = command_domain_proof(
            &awaiting,
            "proof-awaiting-no-domain",
            CommandDomainBackend::MacOsDedicatedIdentity,
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
            1_400,
        );
        assert!(matches!(
            ledger.record_command_domain_cleanup_proof(&forbidden_no_domain),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let proof = command_domain_proof(
            &awaiting,
            "proof-before-result-persistence",
            CommandDomainBackend::MacOsDedicatedIdentity,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_400,
        );
        ledger
            .record_command_domain_cleanup_proof(&proof)
            .expect("persist cleanup before result recovery");
        assert_eq!(
            ledger
                .load_command_domain_cleanup_completeness(
                    "sprint-1",
                    &launch.launch_id,
                    &session.session_id,
                    CommandDomainBackend::MacOsDedicatedIdentity,
                )
                .expect("cleanup alone cannot resolve outcome"),
            CommandDomainCleanupCompleteness::Incomplete(
                CommandDomainCleanupIncomplete::EffectOutcomeUnresolved {
                    effect_ids: vec![intent.effect_id.clone()],
                }
            )
        );

        let observation = persist_command_domain_observation(
            &mut ledger,
            &intent,
            &proposal,
            permit,
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let reopened = ledger
            .load_command_domain_cleanup_proof(&intent.effect_id)
            .expect("immutable pre-observation proof remains valid");
        assert_eq!(reopened.proof, proof);
        assert_eq!(
            reopened.binding.observation_id.as_deref(),
            Some(observation.observation_id.as_str())
        );
        assert_eq!(reopened.binding.state, CommandDomainEffectState::Succeeded);
        assert!(matches!(
            ledger
                .load_command_domain_cleanup_completeness(
                    "sprint-1",
                    &launch.launch_id,
                    &session.session_id,
                    CommandDomainBackend::MacOsDedicatedIdentity,
                )
                .expect("later known result closes completeness"),
            CommandDomainCleanupCompleteness::Complete(_)
        ));
        assert_eq!(
            ledger
                .record_command_domain_cleanup_proof(&proof)
                .expect("replay historical proof after observation"),
            reopened
        );
    }

    #[test]
    fn unfinished_and_unknown_cleanup_never_authorize_completeness() {
        let database = TestDatabase::new();
        let mut ledger = open_v26_test_ledger(&database);
        let (_policy, launch, session) = prepare_command_domain_session(&mut ledger);
        let (unknown_intent, unknown_proposal, unknown_permit) =
            persist_command_domain_intent(&mut ledger, &launch, "effect-unknown", 1_200);
        persist_command_domain_observation(
            &mut ledger,
            &unknown_intent,
            &unknown_proposal,
            unknown_permit,
            EffectOutcome::Unknown {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let (awaiting_intent, _awaiting_proposal, _awaiting_permit) =
            persist_command_domain_intent(&mut ledger, &launch, "effect-awaiting", 1_350);
        let bindings = ledger
            .load_command_domain_effect_bindings("sprint-1", &launch.launch_id, &session.session_id)
            .expect("derive unresolved set");
        let unknown = bindings
            .iter()
            .find(|binding| binding.effect_id == unknown_intent.effect_id)
            .expect("unknown binding");
        let awaiting = bindings
            .iter()
            .find(|binding| binding.effect_id == awaiting_intent.effect_id)
            .expect("awaiting binding");
        assert_eq!(unknown.state, CommandDomainEffectState::Unknown);
        assert_eq!(
            awaiting.state,
            CommandDomainEffectState::AwaitingObservation
        );

        for (binding, proof_id) in [
            (unknown, "proof-no-domain-unknown"),
            (awaiting, "proof-no-domain-awaiting"),
        ] {
            let invalid = command_domain_proof(
                binding,
                proof_id,
                CommandDomainBackend::LinuxCgroupV2,
                CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
                1_500,
            );
            assert!(matches!(
                ledger.record_command_domain_cleanup_proof(&invalid),
                Err(LedgerError::ReferenceMismatch { .. })
            ));
        }

        let mut missing_observation = command_domain_proof(
            unknown,
            "proof-post-observation-without-id",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_500,
        );
        missing_observation.observation_id = None;
        assert!(
            ledger
                .record_command_domain_cleanup_proof(&missing_observation)
                .is_err(),
            "a new proof persisted after observation must carry that exact observation identity"
        );

        for (binding, proof_id) in [
            (unknown, "proof-reaped-unknown"),
            (awaiting, "proof-reaped-awaiting"),
        ] {
            let proof = command_domain_proof(
                binding,
                proof_id,
                CommandDomainBackend::LinuxCgroupV2,
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
                1_500,
            );
            ledger
                .record_command_domain_cleanup_proof(&proof)
                .expect("retain resource cleanup despite unresolved result");
        }
        assert_eq!(
            ledger
                .load_command_domain_cleanup_completeness(
                    "sprint-1",
                    &launch.launch_id,
                    &session.session_id,
                    CommandDomainBackend::LinuxCgroupV2,
                )
                .expect("derive closed unresolved result"),
            CommandDomainCleanupCompleteness::Incomplete(
                CommandDomainCleanupIncomplete::EffectOutcomeUnresolved {
                    effect_ids: vec![awaiting_intent.effect_id, unknown_intent.effect_id],
                }
            )
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // SQL bypasses and redundant-column corruption share one exact set.
    fn command_domain_cleanup_schema_and_readback_reject_bypasses_and_corruption() {
        let database = TestDatabase::new();
        let mut ledger = open_v26_test_ledger(&database);
        let (_policy, launch, session) = prepare_command_domain_session(&mut ledger);
        for (index, effect_id) in ["effect-corrupt-a", "effect-corrupt-b"].iter().enumerate() {
            let created_at = 1_200 + u64::try_from(index).expect("small index") * 100;
            let (intent, proposal, permit) =
                persist_command_domain_intent(&mut ledger, &launch, effect_id, created_at);
            persist_command_domain_observation(
                &mut ledger,
                &intent,
                &proposal,
                permit,
                EffectOutcome::Succeeded {
                    evidence_digest: effect_evidence_digest(),
                },
                created_at + 50,
            );
        }
        let bindings = ledger
            .load_command_domain_effect_bindings("sprint-1", &launch.launch_id, &session.session_id)
            .expect("derive corruption fixture bindings");
        let mut substituted = command_domain_proof(
            &bindings[0],
            "proof-direct-request-substitution",
            CommandDomainBackend::MacOsDedicatedIdentity,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_500,
        );
        substituted.request_digest = digest('d');
        assert!(insert_command_domain_proof_row(&ledger.connection, &substituted).is_err());
        let mut crossed = command_domain_proof(
            &bindings[0],
            "proof-direct-cross-session",
            CommandDomainBackend::MacOsDedicatedIdentity,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_500,
        );
        crossed.session_id = "session-crossed-direct".into();
        assert!(insert_command_domain_proof_row(&ledger.connection, &crossed).is_err());

        let first = command_domain_proof(
            &bindings[0],
            "proof-corrupt-a",
            CommandDomainBackend::MacOsDedicatedIdentity,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_500,
        );
        ledger
            .record_command_domain_cleanup_proof(&first)
            .expect("persist first proof");
        let linux_confusion = command_domain_proof(
            &bindings[1],
            "proof-direct-backend-confusion",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_501,
        );
        assert!(insert_command_domain_proof_row(&ledger.connection, &linux_confusion).is_err());
        let second = command_domain_proof(
            &bindings[1],
            "proof-corrupt-b",
            CommandDomainBackend::MacOsDedicatedIdentity,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_501,
        );
        ledger
            .record_command_domain_cleanup_proof(&second)
            .expect("persist second proof");
        assert!(insert_command_domain_proof_row(&ledger.connection, &second).is_err());

        ledger
            .connection
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 DROP TRIGGER command_domain_cleanup_proof_requires_exact_effect;",
            )
            .expect("open an adversarial extra-row bypass");
        let mut extra = command_domain_proof(
            &bindings[1],
            "proof-corrupt-extra",
            CommandDomainBackend::MacOsDedicatedIdentity,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_502,
        );
        extra.effect_id = "effect-not-in-exact-session-set".into();
        extra.observation_id = None;
        insert_command_domain_proof_row(&ledger.connection, &extra)
            .expect("inject extra proof after disabling both database guards");
        assert!(matches!(
            ledger.load_command_domain_cleanup_completeness(
                "sprint-1",
                &launch.launch_id,
                &session.session_id,
                CommandDomainBackend::MacOsDedicatedIdentity,
            ),
            Err(LedgerError::Corrupt {
                entity: "command-domain cleanup proof set",
                ..
            })
        ));

        ledger
            .connection
            .execute_batch("DROP TRIGGER command_domain_cleanup_proofs_no_update;")
            .expect("disable immutability for indexed-column corruption");
        ledger
            .connection
            .execute(
                "UPDATE command_domain_cleanup_proofs
                 SET request_digest = ?1 WHERE effect_id = ?2",
                params![digest('e').as_str(), first.effect_id],
            )
            .expect("corrupt redundant request digest");
        assert!(matches!(
            ledger.load_command_domain_cleanup_proof(&first.effect_id),
            Err(LedgerError::Corrupt {
                entity: "command-domain cleanup proof",
                ..
            })
        ));
    }

    #[test]
    fn command_domain_cleanup_schema_enforces_hard_proof_set_bound() {
        assert_eq!(MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION, 1_024);
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
        ledger
            .connection
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 DROP TRIGGER command_domain_cleanup_proof_requires_exact_effect_v29;",
            )
            .expect("isolate the proof-count trigger");
        let template = CommandDomainEffectBinding {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            launch_id: launch.launch_id,
            session_id: launch.session_id,
            effect_id: "template".into(),
            request_digest: Digest::sha256(EFFECT_REQUEST_BYTES),
            observation_id: None,
            state: CommandDomainEffectState::AwaitingObservation,
            finalized_at_unix_ms: None,
        };
        for index in 0..MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION {
            let mut binding = template.clone();
            binding.effect_id = format!("effect-bound-{index:04}");
            let proof = command_domain_proof(
                &binding,
                &format!("proof-bound-{index:04}"),
                CommandDomainBackend::LinuxCgroupV2,
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
                1_500,
            );
            insert_command_domain_proof_row(&ledger.connection, &proof)
                .expect("insert within hard proof bound");
        }
        let mut beyond = template;
        beyond.effect_id = "effect-bound-overflow".into();
        let overflow = command_domain_proof(
            &beyond,
            "proof-bound-overflow",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_500,
        );
        let error = insert_command_domain_proof_row(&ledger.connection, &overflow)
            .expect_err("hard proof set bound must reject the next row");
        assert!(
            error
                .to_string()
                .contains("command-domain cleanup proof set exceeds its hard bound")
        );
        assert_eq!(
            row_count(&ledger, "command_domain_cleanup_proofs"),
            i64::try_from(MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION).expect("bound fits SQLite")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Three historical outcomes share one exact byte-preservation matrix.
    fn v11_opaque_application_states_migrate_as_legacy_unbound_without_authority() {
        let cases = [
            ("pending", None, EffectReconciliation::EvidenceRequired),
            (
                "failed-before",
                Some(EffectOutcome::FailedBeforeEffect {
                    evidence_digest: effect_evidence_digest(),
                }),
                EffectReconciliation::NewIntentRequired,
            ),
            (
                "unknown",
                Some(EffectOutcome::Unknown {
                    evidence_digest: effect_evidence_digest(),
                }),
                EffectReconciliation::EvidenceRequired,
            ),
        ];
        for (suffix, outcome, expected_reconciliation) in cases {
            let database = TestDatabase::new();
            let (intent, request_bytes, historical_bytes) = {
                schema_template::install_exact_database_at(11, &database.path);
                let connection = Connection::open(&database.path).expect("create v11 database");
                connection
                    .execute_batch(
                        "PRAGMA foreign_keys = ON;
                         PRAGMA synchronous = FULL;
                         PRAGMA journal_mode = WAL;",
                    )
                    .expect("configure v11 database");
                let mut v11 = EventLedger {
                    connection,
                    database_path: database.path.clone(),
                    read_only: false,
                    instance_id: next_event_ledger_instance_id(),
                };
                let (intent, request_bytes) =
                    prepare_legacy_opaque_application(&mut v11, suffix, outcome);
                let bytes = v11
                    .connection
                    .query_row(
                        "SELECT request.request_bytes, intent.intent_json,
                                observation.observation_json
                         FROM effect_intents intent
                         JOIN effect_request_payloads request
                           ON request.effect_id = intent.effect_id
                         LEFT JOIN effect_observations observation
                           ON observation.effect_id = intent.effect_id
                         WHERE intent.effect_id = ?1",
                        [&intent.effect_id],
                        |row| {
                            Ok((
                                row.get::<_, Vec<u8>>(0)?,
                                row.get::<_, Vec<u8>>(1)?,
                                row.get::<_, Option<Vec<u8>>>(2)?,
                            ))
                        },
                    )
                    .expect("capture exact v11 effect bytes");
                (intent, request_bytes, bytes)
            };

            let ledger = EventLedger::open(&database.path).expect("migrate v11 database to v12");
            let persisted = ledger
                .load_effect(&intent.effect_id)
                .expect("read migrated opaque application lifecycle");
            assert_eq!(persisted.intent, intent);
            assert_eq!(persisted.request_bytes, request_bytes);
            assert_eq!(persisted.reconciliation(), expected_reconciliation);
            assert_eq!(
                ledger
                    .load_application_request_artifact_authority(&intent.effect_id)
                    .expect("classify opaque historical request"),
                ApplicationRequestArtifactAuthority::LegacyUnbound {
                    request_digest: intent.request_digest.clone(),
                }
            );
            assert_eq!(
                ledger
                    .load_application_request_artifact_authority(&intent.effect_id)
                    .expect("reload legacy classification")
                    .artifact(),
                None
            );
            let migrated_bytes = ledger
                .connection
                .query_row(
                    "SELECT request.request_bytes, intent.intent_json,
                            observation.observation_json
                     FROM effect_intents intent
                     JOIN effect_request_payloads request
                       ON request.effect_id = intent.effect_id
                     LEFT JOIN effect_observations observation
                       ON observation.effect_id = intent.effect_id
                     WHERE intent.effect_id = ?1",
                    [&intent.effect_id],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                        ))
                    },
                )
                .expect("reload exact migrated effect bytes");
            assert_eq!(migrated_bytes, historical_bytes);
            assert_eq!(row_count(&ledger, "legacy_application_request_gaps"), 1);
            assert_eq!(
                row_count(&ledger, "application_request_artifact_authorities"),
                0
            );
            assert_eq!(row_count(&ledger, "v9_completion_receipts"), 0);
            assert_eq!(
                row_count(&ledger, "post_completion_application_artifact_authorities"),
                0
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Historical bytes, two authorities, mutation fences, and safe closure are one migration invariant.
    fn v11_active_authorities_migrate_to_v12_without_semantic_drift() {
        let database = TestDatabase::new();
        let (completion, intent, policy, launch, command_cleanup, historical_bytes, v11_schema) = {
            schema_template::install_exact_database_at(11, &database.path);
            let connection = Connection::open(&database.path).expect("create v11 database");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     PRAGMA synchronous = FULL;
                     PRAGMA journal_mode = WAL;",
                )
                .expect("configure v11 database");
            let mut v11 = EventLedger {
                connection,
                database_path: database.path.clone(),
                read_only: false,
                instance_id: next_event_ledger_instance_id(),
            };
            let (report, receipt, event) = prepare_completion_evidence(&mut v11);
            let bindings = v11
                .load_command_domain_effect_bindings("sprint-1", "launch-worker", "session-worker")
                .expect("derive v11 command-domain binding");
            assert_eq!(bindings.len(), 1);
            let command_cleanup = v11
                .load_command_domain_cleanup_proof(&bindings[0].effect_id)
                .expect("load completion fixture's active v11 command-domain proof");
            let completion =
                record_pre_v24_successful_completion_for_test(&mut v11, &report, &receipt, &event)
                    .expect("record v11 completion");
            let intent = v11
                .build_post_completion_rollback_intent(
                    "sprint-1",
                    "rollback-v11-migration".into(),
                    "idempotency-rollback-v11-migration".into(),
                    "rollback-effect-v11-migration".into(),
                    2_100,
                )
                .expect("build v11 post-completion rollback intent");
            v11.record_post_completion_rollback_intent(&intent)
                .expect("persist v11 post-completion rollback intent");
            let policy = compiled_test_policy("policy-applier");
            let mut launch = runner_launch(
                "launch-rollback-v11-migration",
                "session-rollback-v11-migration",
                RunnerSessionPurpose::Applier,
                None,
                &policy,
                2_200,
            );
            launch.private_state_digest = Digest::sha256(b"launch-applier");
            v11.record_post_completion_rollback_applier_launch(
                &intent.operation_id,
                PostCompletionRollbackApplierRole::Executor,
                &launch,
                &policy,
            )
            .expect("persist v11 pre-spawn rollback launch");
            let historical_bytes = v11
                .connection
                .query_row(
                    "SELECT operation.request_json, operation.intent_json,
                            launch.launch_json, launch.execution_policy_json,
                            completion.receipt_json, request.request_bytes,
                            proof.proof_json, proof.platform_proof_bytes
                     FROM post_completion_rollback_operations operation
                     JOIN post_completion_rollback_applier_launches launch
                       ON launch.operation_id = operation.operation_id
                     JOIN v9_completion_receipts completion
                       ON completion.receipt_id = operation.completion_receipt_id
                     JOIN application_receipts application
                       ON application.receipt_id = operation.application_receipt_id
                     JOIN effect_request_payloads request
                       ON request.effect_id = application.effect_id
                     JOIN command_domain_cleanup_proofs proof
                       ON proof.effect_id = ?2
                     WHERE operation.operation_id = ?1",
                    params![intent.operation_id, command_cleanup.binding.effect_id],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                        ))
                    },
                )
                .expect("capture exact v11 durable bytes");
            let schema = load_schema_objects(&v11.connection).expect("capture exact v11 schema");
            (
                completion,
                intent,
                policy,
                launch,
                command_cleanup,
                historical_bytes,
                schema,
            )
        };

        let connection = Connection::open(&database.path).expect("reopen v11 ledger");
        register_schema_functions(&connection).expect("register v12 schema functions");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
            .expect("configure v12 migration connection");
        connection
            .execute_batch(MIGRATIONS[11])
            .expect("install exact migration v12");
        connection
            .pragma_update(None, "user_version", 12_i64)
            .expect("mark exact v12 schema");
        let mut ledger = EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        };
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read v12 schema version");
        assert_eq!(version, 12);
        let v12_schema = load_schema_objects(&ledger.connection).expect("load v12 schema");
        for historical_object in &v11_schema {
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
                v12_schema.contains(historical_object),
                "current schema must preserve unaffected v11 schema object {} byte-for-byte",
                historical_object.name
            );
        }
        let migrated_bytes = ledger
            .connection
            .query_row(
                "SELECT operation.request_json, operation.intent_json,
                        launch.launch_json, launch.execution_policy_json,
                        completion.receipt_json, request.request_bytes,
                        proof.proof_json, proof.platform_proof_bytes
                 FROM post_completion_rollback_operations operation
                 JOIN post_completion_rollback_applier_launches launch
                   ON launch.operation_id = operation.operation_id
                 JOIN v9_completion_receipts completion
                   ON completion.receipt_id = operation.completion_receipt_id
                 JOIN application_receipts application
                   ON application.receipt_id = operation.application_receipt_id
                 JOIN effect_request_payloads request
                   ON request.effect_id = application.effect_id
                 JOIN command_domain_cleanup_proofs proof
                   ON proof.effect_id = ?2
                 WHERE operation.operation_id = ?1",
                params![intent.operation_id, command_cleanup.binding.effect_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                    ))
                },
            )
            .expect("reload exact bytes after v12 migration");
        assert_eq!(migrated_bytes, historical_bytes);
        completion.assert_matches_pre_v24_rows(&ledger);
        assert_eq!(
            ledger
                .load_command_domain_cleanup_proof(&command_cleanup.binding.effect_id)
                .expect("reload v11 command proof through v12"),
            command_cleanup
        );
        let operation = ledger
            .load_post_completion_rollback(&intent.operation_id)
            .expect("load legacy active operation through v12");
        assert_eq!(operation.intent, intent);
        assert_eq!(
            operation.application_artifact_authority,
            PostCompletionRollbackApplicationArtifactAuthorityState::LegacyMissing
        );
        assert_eq!(operation.application_artifact_authority.artifact(), None);
        assert_eq!(
            operation.status(),
            PostCompletionRollbackStatus::ExecutingOrReconciling
        );
        assert_eq!(operation.appliers.len(), 1);
        assert_eq!(operation.appliers[0].launch, launch);
        assert_eq!(operation.appliers[0].session, None);

        let mut recovery_launch = runner_launch(
            "launch-v12-blocked-recovery",
            "session-v12-blocked-recovery",
            RunnerSessionPurpose::Applier,
            None,
            &policy,
            2_250,
        );
        recovery_launch.private_state_digest = launch.private_state_digest.clone();
        assert!(matches!(
            ledger.record_post_completion_rollback_applier_launch(
                &intent.operation_id,
                PostCompletionRollbackApplierRole::RecoveryValidator,
                &recovery_launch,
                &policy,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "post-completion application artifact authority",
                ..
            })
        ));
        let executor_session = runner_session(&launch, 2_250);
        assert!(matches!(
            ledger.register_post_completion_rollback_applier_session(
                &intent.operation_id,
                &executor_session,
                &policy,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "post-completion application artifact authority",
                ..
            })
        ));
        let blocked_observation = post_completion_success(
            &mut ledger,
            &intent,
            &launch,
            &executor_session,
            &launch,
            &executor_session,
            RollbackValidationMode::DirectEffectResponse,
            2_300,
            2_350,
            false,
        );
        assert!(matches!(
            ledger.record_post_completion_rollback_observation(&blocked_observation),
            Err(LedgerError::ReferenceMismatch {
                entity: "post-completion application artifact authority",
                ..
            })
        ));
        let direct_session_error = ledger.connection.execute(
            "INSERT INTO post_completion_rollback_applier_sessions (
                session_id, operation_id, sprint_id, launch_id, launch_role,
                policy_hash, session_nonce, runner_binary_digest,
                protocol_digest, private_state_digest, grant_hash,
                policy_version, contract_version, registered_at_unix_ms,
                session_json, execution_policy_json
             ) VALUES (?1, ?2, ?3, ?4, 'Executor', ?5, ?6, ?7, ?8, ?9,
                       ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                executor_session.session_id,
                intent.operation_id,
                executor_session.sprint_id,
                executor_session.launch_id,
                executor_session.policy_hash.as_str(),
                executor_session.session_nonce.as_str(),
                executor_session.runner_binary_digest.as_str(),
                executor_session.protocol_digest.as_str(),
                executor_session.private_state_digest.as_str(),
                executor_session.grant_hash.as_str(),
                i64::from(executor_session.policy_version),
                i64::from(executor_session.contract_version),
                i64::try_from(executor_session.registered_at_unix_ms)
                    .expect("timestamp fits SQLite"),
                encode("post-completion rollback session", &executor_session)
                    .expect("encode blocked session"),
                encode(
                    "post-completion rollback execution policy",
                    policy.contract(),
                )
                .expect("encode blocked policy"),
            ],
        );
        assert!(
            direct_session_error
                .expect_err("SQL session admission must reject legacy operation")
                .to_string()
                .contains("post-completion session requires application artifact authority")
        );

        let failure_bytes = b"legacy launch was refused before spawn".to_vec();
        let failure = PostCompletionRollbackLaunchFailure {
            contract_version: CONTRACT_VERSION,
            failure_id: "failure-v11-migrated-launch".into(),
            operation_id: intent.operation_id.clone(),
            sprint_id: intent.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            expected_session_id: launch.session_id.clone(),
            launch_role: PostCompletionRollbackApplierRole::Executor,
            kind: PostCompletionRollbackLaunchFailureKind::LaunchRefusedBeforeSpawn,
            failure_evidence_digest: Digest::sha256(&failure_bytes),
            failure_evidence_bytes: failure_bytes,
            failed_at_unix_ms: 2_300,
        };
        ledger
            .record_post_completion_rollback_launch_failure(&failure)
            .expect("legacy operation may retain exact no-effect launch failure");
        let cleanup = finish_post_completion_cleanup(
            &mut ledger,
            &intent,
            &launch,
            "v11-migrated",
            2_350,
            2_400,
        );
        let terminal = PostCompletionRollbackTerminal {
            contract_version: CONTRACT_VERSION,
            terminal_id: "terminal-v11-migrated-launch".into(),
            operation_id: intent.operation_id.clone(),
            sprint_id: intent.sprint_id.clone(),
            application_receipt_id: intent.request.application_receipt_id.clone(),
            outcome_id: failure.failure_id,
            kind: PostCompletionRollbackOutcomeKind::NoEffect,
            cleanup_receipt_ids: vec![cleanup.evidence.receipt.receipt_id],
            terminal_at_unix_ms: 2_450,
        };
        assert_eq!(
            ledger
                .finalize_post_completion_rollback(&terminal)
                .expect("safely close migrated operation after cleanup")
                .status(),
            PostCompletionRollbackStatus::Terminal(PostCompletionRollbackOutcomeKind::NoEffect)
        );
        assert!(matches!(
            ledger.append_event(&AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger.next_sequence("sprint-1").expect("next sequence"),
                event_id: "event-after-v12-migration".into(),
                sprint_id: "sprint-1".into(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: "v12-migration-terminal-fence".into(),
                policy_hash: None,
                occurred_at_unix_ms: 2_500,
                payload: AgentEventKind::Diagnostic("must remain completed".into()),
            }),
            Err(LedgerError::SprintAlreadyTerminal(_))
        ));
        completion.assert_matches_pre_v24_rows(&ledger);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exact legacy bytes, admission fences, and safe cleanup are one migration invariant.
    fn v12_runner_launches_migrate_to_v13_as_readable_cleanup_only_gaps() {
        let database = TestDatabase::new();
        let (
            policy,
            initialized_launch,
            uninitialized_launch,
            initialized_session,
            command_intent,
            historical_bytes,
            v12_schema,
        ) = {
            schema_template::install_exact_database_at(12, &database.path);
            let connection = Connection::open(&database.path).expect("create v12 database");
            connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     PRAGMA synchronous = FULL;
                     PRAGMA journal_mode = WAL;",
                )
                .expect("configure v12 database");
            let mut v12 = EventLedger {
                connection,
                database_path: database.path.clone(),
                read_only: false,
                instance_id: next_event_ledger_instance_id(),
            };
            prepare_effect_input(&mut v12);
            let policy = compiled_shadow_test_policy("v12-runner-migration-policy");
            let initialized_launch = runner_launch(
                "v12-initialized-launch",
                "v12-initialized-session",
                RunnerSessionPurpose::TaskWorker,
                Some("worker-1"),
                &policy,
                1_100,
            );
            let uninitialized_launch = runner_launch(
                "v12-uninitialized-launch",
                "v12-uninitialized-session",
                RunnerSessionPurpose::TaskWorker,
                Some("worker-2"),
                &policy,
                1_101,
            );
            v12.record_runner_launch_intent(&initialized_launch, &policy)
                .expect("persist initialized v12 launch");
            v12.record_runner_launch_intent(&uninitialized_launch, &policy)
                .expect("persist uninitialized v12 launch");
            let initialized_session = runner_session(&initialized_launch, 1_150);
            v12.register_runner_session(&initialized_session, &policy)
                .expect("persist v12 runner session");
            let (command_intent, command_event, _command_permit) = persist_command_domain_intent(
                &mut v12,
                &initialized_launch,
                "v12-runner-command",
                1_200,
            );
            let historical_bytes = v12
                .connection
                .query_row(
                    "SELECT initialized.intent_json,
                            initialized.execution_policy_json,
                            uninitialized.intent_json,
                            uninitialized.execution_policy_json,
                            session.record_json,
                            session.execution_policy_json,
                            effect.intent_json,
                            request.request_bytes,
                            event.event_json
                     FROM runner_launch_intents initialized
                     JOIN runner_launch_intents uninitialized
                       ON uninitialized.launch_id = ?2
                     JOIN runner_session_policies session
                       ON session.launch_id = initialized.launch_id
                     JOIN effect_intents effect ON effect.effect_id = ?3
                     JOIN effect_request_payloads request
                       ON request.effect_id = effect.effect_id
                     JOIN agent_events event ON event.event_id = ?4
                     WHERE initialized.launch_id = ?1",
                    params![
                        initialized_launch.launch_id,
                        uninitialized_launch.launch_id,
                        command_intent.effect_id,
                        command_event.event_id,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                            row.get::<_, Vec<u8>>(8)?,
                        ))
                    },
                )
                .expect("capture exact v12 runner lifecycle bytes");
            let schema = load_schema_objects(&v12.connection).expect("capture exact v12 schema");
            (
                policy,
                initialized_launch,
                uninitialized_launch,
                initialized_session,
                command_intent,
                historical_bytes,
                schema,
            )
        };

        let connection = Connection::open(&database.path).expect("reopen v12 ledger");
        register_schema_functions(&connection).expect("register v14 schema functions");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
            .expect("configure v14 migration connection");
        for migration in MIGRATIONS.iter().take(14).skip(12) {
            connection
                .execute_batch(migration)
                .expect("install migration through exact v14");
        }
        connection
            .pragma_update(None, "user_version", 14_i64)
            .expect("mark exact v14 schema");
        let mut ledger = EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        };
        let version: i64 = ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read v13 schema version");
        assert_eq!(version, 14);
        let v13_schema = load_schema_objects(&ledger.connection).expect("load v13 schema");
        for historical_object in &v12_schema {
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
                // v14 adds indexed lease join columns to these tables. ALTER
                // TABLE necessarily changes their sqlite_master definitions;
                // the historical row bytes remain covered below.
                continue;
            }
            assert!(
                v13_schema.contains(historical_object),
                "v14 must preserve unaffected v12 schema object {} byte-for-byte",
                historical_object.name
            );
        }
        let migrated_bytes = ledger
            .connection
            .query_row(
                "SELECT initialized.intent_json,
                        initialized.execution_policy_json,
                        uninitialized.intent_json,
                        uninitialized.execution_policy_json,
                        session.record_json,
                        session.execution_policy_json,
                        effect.intent_json,
                        request.request_bytes,
                        event.event_json
                 FROM runner_launch_intents initialized
                 JOIN runner_launch_intents uninitialized
                   ON uninitialized.launch_id = ?2
                 JOIN runner_session_policies session
                   ON session.launch_id = initialized.launch_id
                 JOIN effect_intents effect ON effect.effect_id = ?3
                 JOIN effect_request_payloads request
                   ON request.effect_id = effect.effect_id
                 JOIN agent_events event ON event.event_id = effect.proposed_event_id
                 WHERE initialized.launch_id = ?1",
                params![
                    initialized_launch.launch_id,
                    uninitialized_launch.launch_id,
                    command_intent.effect_id,
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                    ))
                },
            )
            .expect("reload exact v12 runner lifecycle bytes through v13");
        assert_eq!(migrated_bytes, historical_bytes);
        assert_eq!(row_count(&ledger, "legacy_runner_launch_cleanup_gaps"), 2);
        assert_eq!(row_count(&ledger, "runner_launch_cleanup_admissions"), 0);
        let mut expected_initialized_launch = initialized_launch.clone();
        expected_initialized_launch.worker_lease = None;
        let mut expected_uninitialized_launch = uninitialized_launch.clone();
        expected_uninitialized_launch.worker_lease = None;
        let mut expected_initialized_session = initialized_session.clone();
        expected_initialized_session.worker_lease = None;
        let mut expected_command_intent = command_intent.clone();
        expected_command_intent.worker_lease = None;
        assert_eq!(
            ledger
                .load_runner_launch_intent(
                    &initialized_launch.sprint_id,
                    &initialized_launch.launch_id,
                )
                .expect("read exact initialized legacy launch"),
            expected_initialized_launch
        );
        assert_eq!(
            ledger
                .load_runner_launch_intent(
                    &uninitialized_launch.sprint_id,
                    &uninitialized_launch.launch_id,
                )
                .expect("read exact uninitialized legacy launch"),
            expected_uninitialized_launch
        );
        assert_eq!(
            ledger
                .load_runner_session(
                    &initialized_session.sprint_id,
                    &initialized_session.session_id,
                )
                .expect("read existing legacy session"),
            expected_initialized_session
        );
        assert_eq!(
            ledger
                .load_effect(&command_intent.effect_id)
                .expect("read existing legacy runner effect")
                .intent,
            expected_command_intent
        );

        let blocked_session = runner_session(&uninitialized_launch, 1_250);
        assert!(matches!(
            ledger.register_runner_session(&blocked_session, &policy),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch cleanup admission",
                ..
            })
        ));
        let mut blocked_command = effect_intent(
            "v13-blocked-legacy-command",
            "v13-blocked-legacy-command-key",
            1_300,
        );
        blocked_command.policy_hash = initialized_launch.policy_hash.clone();
        let blocked_event = effect_proposal_event(
            &blocked_command,
            ledger
                .next_sequence("sprint-1")
                .expect("blocked command sequence"),
            "v13-blocked-legacy-command-event",
        );
        assert!(matches!(
            ledger.record_runner_effect_intent(
                &blocked_command,
                EFFECT_REQUEST_BYTES,
                &blocked_event,
                &initialized_launch.session_id,
            ),
            Err(LedgerError::LegacyWorkerLeaseUnproven(sprint_id))
                if sprint_id == "sprint-1"
        ));
        let fresh_launch = runner_launch(
            "v13-standalone-launch",
            "v13-standalone-session",
            RunnerSessionPurpose::TaskWorker,
            Some("worker-3"),
            &policy,
            1_301,
        );
        assert!(matches!(
            ledger.record_runner_launch_intent(&fresh_launch, &policy),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch intent",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "runner_session_policies"), 1);
        assert_eq!(row_count(&ledger, "effect_intents"), 1);
        assert_eq!(row_count(&ledger, "agent_events"), 1);
        assert_eq!(row_count(&ledger, "runner_launch_intents"), 2);

        let cleanup_request = WorkerCleanupRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: uninitialized_launch.sprint_id.clone(),
            launch_id: uninitialized_launch.launch_id.clone(),
            session_id: uninitialized_launch.session_id.clone(),
            policy_hash: uninitialized_launch.policy_hash.clone(),
            grant_hash: uninitialized_launch.grant_hash.clone(),
            policy_version: uninitialized_launch.policy_version,
            platform_backend: WorkerCleanupBackend::LinuxCgroupV2,
        };
        let cleanup_request_bytes =
            encode("worker cleanup request", &cleanup_request).expect("encode legacy cleanup");
        let cleanup_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "v13-legacy-launch-cleanup".into(),
            idempotency_key: "v13-legacy-launch-cleanup-key".into(),
            sprint_id: uninitialized_launch.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "v13-legacy-launch-cleanup-correlation".into(),
            kind: EffectKind::CleanupWorkerDomain,
            request_digest: Digest::sha256(&cleanup_request_bytes),
            policy_hash: uninitialized_launch.policy_hash.clone(),
            input_snapshot: digest('b'),
            created_at_unix_ms: 1_350,
        };
        let cleanup_event = effect_proposal_event(
            &cleanup_intent,
            ledger
                .next_sequence("sprint-1")
                .expect("legacy cleanup sequence"),
            "v13-legacy-launch-cleanup-proposed",
        );
        ledger
            .record_cleanup_effect_intent_for_launch(
                &cleanup_intent,
                &cleanup_request_bytes,
                &cleanup_event,
                &uninitialized_launch.launch_id,
            )
            .expect("add one safe cleanup to migrated legacy launch");
        let os_evidence_bytes = b"linux cgroup empty after migrated launch".to_vec();
        let cleanup_evidence = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: "v13-legacy-launch-cleanup-receipt".into(),
                sprint_id: uninitialized_launch.sprint_id.clone(),
                launch_id: uninitialized_launch.launch_id.clone(),
                effect_id: cleanup_intent.effect_id.clone(),
                observation_id: "v13-legacy-launch-cleanup-observation".into(),
                session_id: uninitialized_launch.session_id.clone(),
                worker_lease: None,
                policy_hash: uninitialized_launch.policy_hash.clone(),
                grant_hash: uninitialized_launch.grant_hash.clone(),
                policy_version: uninitialized_launch.policy_version,
                platform_backend: WorkerCleanupBackend::LinuxCgroupV2,
                os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms: 1_400,
            },
            os_evidence_bytes,
        };
        let cleanup_evidence_bytes = encode("worker cleanup evidence", &cleanup_evidence)
            .expect("encode legacy cleanup evidence");
        let cleanup_observation = effect_observation(
            &cleanup_intent,
            &cleanup_evidence.receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&cleanup_evidence_bytes),
            },
            cleanup_evidence.receipt.cleaned_at_unix_ms,
        );
        let cleanup_terminal = effect_terminal_event(
            &cleanup_intent,
            &cleanup_event.event_id,
            &cleanup_observation,
            ledger
                .next_sequence("sprint-1")
                .expect("legacy cleanup terminal sequence"),
            "v13-legacy-launch-cleanup-finished",
        );
        ledger
            .record_worker_cleanup_effect_observation(
                &cleanup_observation,
                &cleanup_terminal,
                &cleanup_evidence,
            )
            .expect("close migrated legacy launch with exact cleanup evidence");
        assert_eq!(
            ledger
                .load_worker_cleanup_evidence(&cleanup_evidence.receipt.receipt_id)
                .expect("reload migrated launch cleanup evidence"),
            cleanup_evidence
        );
        assert!(matches!(
            ledger.register_runner_session(&blocked_session, &policy),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch cleanup admission",
                ..
            })
        ));
        assert_eq!(row_count(&ledger, "runner_launch_cleanup_admissions"), 0);
        assert_eq!(row_count(&ledger, "legacy_runner_launch_cleanup_gaps"), 2);
    }

