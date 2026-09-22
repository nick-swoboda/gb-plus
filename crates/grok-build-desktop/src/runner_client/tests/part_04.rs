    #[allow(
        clippy::too_many_lines,
        reason = "the stage contract test keeps preparation, durable effect, artifact mapping, ambiguity, and reconciliation in one sequential lifecycle"
    )]
    #[test]
    fn worker_stage_is_an_exact_prepared_effect_with_typed_reconciliation() {
        let (harness, mut ledger) = TestHarness::new("stage-effect");
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("stage-effect"),
            transport(
                unique_nonce("stage-effect"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
            ),
        )
        .expect("initialize stage fixture");
        let result_snapshot = Digest::sha256(b"stage result");
        client.captured_base = true;
        client.shadow_created = true;
        client.shadow_snapshot = Some(result_snapshot.clone());
        let change_set = ChangeSet {
            change_set_id: "change-stage".into(),
            base_snapshot: harness.base_snapshot.clone(),
            result_snapshot: result_snapshot.clone(),
            operations: vec![grok_build_core::FileOperation::Create {
                path: PathBuf::from("src/staged.rs"),
                result_hash: Digest::sha256(b"staged bytes"),
            }],
        };
        let expected_bundle = StageBundleReference {
            format_version: 1,
            bundle_digest: Digest::sha256(b"expected stage bundle"),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
        };
        let prepare = RunnerRequest::WorkerPrepareStage {
            change_set_id: change_set.change_set_id.clone(),
            created_at_unix_ms: client.session.registered_at_unix_ms + 1,
        };
        client
            .validate_control_request(&prepare)
            .expect("exact preparation control");
        client
            .validate_and_apply_control_response(
                &prepare,
                &RunnerResponse::StagePrepared {
                    change_set: Box::new(change_set.clone()),
                    expected_bundle: expected_bundle.clone(),
                },
            )
            .expect("retain exact prepared stage");

        let core_request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: change_set.clone(),
            artifact: expected_bundle
                .to_core_integration_artifact()
                .expect("map expected bundle"),
        };
        let core_request_bytes =
            serde_json::to_vec(&core_request).expect("canonical integration request");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-stage".into(),
            idempotency_key: "key-stage".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(harness.worker_lease.clone()),
            causation_event_id: None,
            correlation_id: "correlation-stage".into(),
            kind: EffectKind::IntegrateChangeSet,
            request_digest: Digest::sha256(&core_request_bytes),
            policy_hash: harness.policy.contract().policy_hash.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            created_at_unix_ms: client.session.registered_at_unix_ms + 2,
        };
        let stage = RunnerRequest::WorkerStageChanges {
            change_set: Box::new(change_set.clone()),
            expected_bundle: expected_bundle.clone(),
        };
        assert_eq!(
            exact_effect_kind(&stage).expect("stage effect kind"),
            EffectKind::IntegrateChangeSet
        );
        assert_eq!(control_role(&stage), None);
        client
            .validate_effect_request(&intent, &core_request_bytes, &stage)
            .expect("exact prepared stage effect");
        let mut artifact_request = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: client.session.session_id.clone(),
            runner_nonce: Some(client.session.session_nonce.clone()),
            sequence: 9,
            request_id: "request-stage-artifact".into(),
            effect: Some(WireEffectContext {
                contract_version: intent.contract_version,
                launch_id: client.session.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                idempotency_key: intent.idempotency_key.clone(),
                sprint_id: intent.sprint_id.clone(),
                task_id: intent.task_id.clone(),
                worker_id: intent.worker_id.clone(),
                worker_lease: intent.worker_lease.clone(),
                policy_hash: intent.policy_hash.clone(),
                input_snapshot: intent.input_snapshot.clone(),
                request_digest: intent.request_digest.clone(),
                transport_commitment_digest: Digest::sha256(&[]),
            }),
            request: stage.clone(),
        };
        artifact_request
            .bind_transport_commitment_digest()
            .expect("bind stage artifact request");
        let artifact_exchange = RunnerEffectResponse {
            response: RunnerResponseEnvelope {
                protocol_version: artifact_request.protocol_version,
                session_id: artifact_request.session_id.clone(),
                runner_nonce: client.session.session_nonce.clone(),
                sequence: artifact_request.sequence,
                request_id: artifact_request.request_id.clone(),
                effect: artifact_request.effect.clone(),
                response: RunnerResponse::StageBundlePersisted {
                    bundle: expected_bundle.clone(),
                },
            },
            request: artifact_request,
        };
        let artifact = artifact_exchange
            .task_integration_artifact()
            .expect("map exact persisted bundle to core artifact");
        assert_eq!(artifact.artifact_digest, expected_bundle.bundle_digest);
        assert_eq!(artifact.change_set_id, change_set.change_set_id);
        let mut noncanonical = core_request_bytes.clone();
        noncanonical.push(b' ');
        assert!(
            client
                .validate_effect_request(&intent, &noncanonical, &stage)
                .is_err()
        );
        let mut crossed_core_request = core_request;
        crossed_core_request.artifact.artifact_digest = Digest::sha256(b"crossed artifact");
        let crossed_core_bytes =
            serde_json::to_vec(&crossed_core_request).expect("encode crossed request");
        let mut crossed_intent = intent.clone();
        crossed_intent.request_digest = Digest::sha256(&crossed_core_bytes);
        assert!(
            client
                .validate_effect_request(&crossed_intent, &crossed_core_bytes, &stage)
                .is_err()
        );
        client
            .validate_and_apply_effect_response(
                &intent,
                &stage,
                &RunnerResponse::StageBundlePersisted {
                    bundle: expected_bundle.clone(),
                },
            )
            .expect("exact stage persistence response");
        assert!(client.prepared_stage.is_none());

        client
            .validate_control_request(&prepare)
            .expect("prepare reconciliation fixture");
        client
            .validate_and_apply_control_response(
                &prepare,
                &RunnerResponse::StagePrepared {
                    change_set: Box::new(change_set),
                    expected_bundle: expected_bundle.clone(),
                },
            )
            .expect("retain reconciliation preparation");
        assert!(
            client
                .apply_failure_response(&RunnerResponse::Failed {
                    code: "stage_uncertain".into(),
                    class: WireFailureClass::ReconciliationRequired,
                    reconciliation: Some(WireReconciliationReference::StageBundle {
                        bundle: expected_bundle.clone(),
                    }),
                    message: "stage persistence requires reconciliation".into(),
                })
                .expect("retain exact stage reconciliation")
        );
        let reconcile = RunnerRequest::WorkerReconcileStage {
            expected_bundle: expected_bundle.clone(),
        };
        client
            .validate_control_request(&reconcile)
            .expect("exact stage reconciliation control");
        client
            .validate_and_apply_control_response(
                &reconcile,
                &RunnerResponse::StageBundleReconciled {
                    bundle: expected_bundle,
                },
            )
            .expect("exact stage reconciliation response");
        assert!(client.prepared_stage.is_none());
        assert!(client.pending_reconciliation.is_none());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the adversarial test keeps Candidate admission, typed claim, exact wire mapping, and claim readback contiguous"
    )]
    fn task_integration_claim_uses_no_running_boundary_and_exact_stage_request() {
        let (harness, mut ledger) = TestHarness::new("typed-integration-dispatch");
        let exchange_count = Rc::new(Cell::new(0));
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("typed-integration-dispatch"),
            transport_with_exchange_count(
                unique_nonce("typed-integration-dispatch"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize integration worker");
        let running = client
            .task_attempt_running_boundary()
            .expect("worker entered Running")
            .clone();
        let result_snapshot = Digest::sha256(b"typed integration result");
        let change_set = ChangeSet {
            change_set_id: "change-typed-integration".into(),
            base_snapshot: harness.base_snapshot.clone(),
            result_snapshot: result_snapshot.clone(),
            operations: vec![FileOperation::Create {
                path: PathBuf::from("src/integrated.rs"),
                result_hash: Digest::sha256(b"integrated"),
            }],
        };
        let expected_bundle = StageBundleReference {
            format_version: 1,
            bundle_digest: Digest::sha256(b"typed integration bundle"),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
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
            .expect("persist integration result snapshot");
        ledger
            .persist_change_set(&harness.sprint_id, &change_set)
            .expect("persist integration change set");
        let verifying_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&harness.sprint_id)
                .expect("next integration Verifying sequence"),
            event_id: "event-typed-integration-verifying".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            causation_id: Some(running.transition_event_id.clone()),
            correlation_id: "correlation-typed-integration".into(),
            policy_hash: Some(harness.policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: phase_time,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Verifying".into(),
            },
        };
        let verifying = TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "boundary-typed-integration-verifying".into(),
            attempt: running.attempt.clone(),
            runner_launch_id: client.launch.launch_id.clone(),
            runner_session_id: client.session.session_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
            sealed_snapshot: result_snapshot.clone(),
            transition_event_id: verifying_event.event_id.clone(),
            terminal_non_cleanup_effects: Vec::new(),
            sealed_at_unix_ms: phase_time,
        };
        ledger
            .transition_task_attempt_to_verifying(&verifying, &verifying_event)
            .expect("enter integration Verifying phase");
        let candidate_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&harness.sprint_id)
                .expect("next Candidate sequence"),
            event_id: "event-typed-integration-candidate".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            causation_id: Some(verifying_event.event_id.clone()),
            correlation_id: "correlation-typed-integration".into(),
            policy_hash: Some(harness.policy.contract().policy_hash.clone()),
            occurred_at_unix_ms: phase_time + 1,
            payload: AgentEventKind::TaskStateChanged {
                from: "Verifying".into(),
                to: "Candidate".into(),
            },
        };
        let candidate = TaskAttemptCandidateBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "boundary-typed-integration-candidate".into(),
            attempt: running.attempt.clone(),
            verification_boundary_id: verifying.boundary_id,
            change_set_id: change_set.change_set_id.clone(),
            sealed_snapshot: result_snapshot.clone(),
            formal_check_ids: Vec::new(),
            verification_receipt_ids: Vec::new(),
            transition_event_id: candidate_event.event_id.clone(),
            admitted_at_unix_ms: phase_time + 1,
        };
        ledger
            .transition_task_attempt_to_candidate(&candidate, &candidate_event)
            .expect("enter exact Candidate phase");
        client.shadow_created = true;
        client.shadow_snapshot = Some(result_snapshot.clone());
        client.prepared_stage = Some(PreparedWorkerStage {
            change_set: change_set.clone(),
            expected_bundle: expected_bundle.clone(),
        });

        let request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: change_set.clone(),
            artifact: expected_bundle
                .to_core_integration_artifact()
                .expect("map integration artifact"),
        };
        let request_bytes = serde_json::to_vec(&request).expect("encode integration request");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-typed-integration".into(),
            idempotency_key: "key-typed-integration".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(harness.worker_lease.clone()),
            causation_event_id: Some(candidate_event.event_id.clone()),
            correlation_id: "correlation-typed-integration".into(),
            kind: EffectKind::IntegrateChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: harness.policy.contract().policy_hash.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            created_at_unix_ms: phase_time + 2,
        };
        let proposal = proposal(
            &intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next integration proposal sequence"),
        );
        let admission = TaskAttemptIntegrationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: "admission-typed-integration".into(),
            candidate_boundary: candidate,
            effect_id: intent.effect_id.clone(),
            runner_launch_id: client.launch.launch_id.clone(),
            runner_session_id: client.session.session_id.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            result_snapshot,
            admitted_at_unix_ms: intent.created_at_unix_ms,
        };
        let permit = match ledger
            .admit_task_attempt_integration_for_dispatch(&admission, &intent, &request, &proposal)
            .expect("admit exact integration")
        {
            TaskIntegrationDispatchAdmission::Fresh { permit, .. } => permit,
            TaskIntegrationDispatchAdmission::Existing { .. } => {
                panic!("new integration must retain fresh authority")
            }
        };
        let (client, claimed) = client
            .send_precommitted_task_integration(&mut ledger, permit, &intent, &request)
            .expect("dispatch exact typed integration");
        assert_eq!(
            exchange_count.get(),
            2,
            "initialization plus one stage effect"
        );
        assert!(client.prepared_stage.is_none());
        let (exchange, _request_frame, _response_digest, claimed_effect, _authority) =
            claimed.into_parts();
        assert!(matches!(
            exchange.response.response,
            RunnerResponse::StageBundlePersisted { ref bundle } if bundle == &expected_bundle
        ));
        let claim = claimed_effect
            .dispatch_claim
            .as_ref()
            .expect("integration effect has one exact claim");
        assert!(claim.running_boundary_id.is_none());
        assert!(matches!(
            claim.authority,
            RunnerEffectRequestAuthority::TaskIntegration { .. }
        ));
        assert_eq!(
            ledger
                .load_effect(&intent.effect_id)
                .expect("reload integration claim"),
            claimed_effect
        );
    }

    #[test]
    fn fresh_applier_stage_reconciliation_remains_session_control_evidence() {
        let (harness, mut ledger) = TestHarness::new("applier-stage-reconcile");
        let applier_policy = ExecutionPolicyCompiler::compile(
            &harness.authority,
            ExecutionPolicyRequest {
                policy_id: "policy-applier-stage-reconcile".into(),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: Vec::new(),
                environment: Vec::new(),
                network: ExecutionNetwork::None,
                mutation_mode: MutationMode::ReadOnly,
                resource_limits: ResourceLimits {
                    wall_time_ms: 30_000,
                    max_output_bytes: 1_024 * 1_024,
                    max_processes: 1,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile read-only applier policy");
        let mut launch = harness.launch("applier-stage-reconcile");
        launch.role = RunnerRole::Applier;
        launch.worker_id = None;
        launch.worker_lease = None;
        launch.shadow_root = None;
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &applier_policy,
            launch,
            transport(
                unique_nonce("applier-stage-reconcile"),
                harness.identity(),
                ScriptMode::Good,
                false,
                Vec::new(),
            ),
        )
        .expect("initialize fresh applier fixture");
        let expected_bundle = StageBundleReference {
            format_version: 1,
            bundle_digest: Digest::sha256(b"durable stage artifact"),
            change_set_id: "change-restart".into(),
            base_snapshot: harness.base_snapshot.clone(),
            result_snapshot: Digest::sha256(b"restart stage result"),
        };
        let request = RunnerRequest::ApplierReconcileStageBundle {
            expected_bundle: expected_bundle.clone(),
        };
        assert_eq!(control_role(&request), Some(RunnerRole::Applier));
        assert!(client.validate_control_request(&request).is_err());
        client.applier_recovery_complete = true;
        client
            .validate_control_request(&request)
            .expect("recovered fresh applier admits exact stage reconciliation");
        client
            .validate_and_apply_control_response(
                &request,
                &RunnerResponse::StageBundleReconciled {
                    bundle: expected_bundle,
                },
            )
            .expect("validate fresh applier stage reconciliation response");
        assert!(client.pending_reconciliation.is_none());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test retains the complete durable authority join, adversarial preimages, exact transport count, and cleanup handoff"
    )]
    fn post_completion_dispatch_authoritative_operation_sends_exactly_one_rollback() {
        let (harness, mut ledger) = TestHarness::new("post-completion-authoritative");
        let (fixture, policy) = prepare_authoritative_post_completion_dispatch(
            &harness,
            &mut ledger,
            "post-completion-authoritative",
        );
        let exchange_count = Rc::new(Cell::new(0));
        let mut client = launch_post_completion_test_client(
            &harness,
            &mut ledger,
            &fixture,
            &policy,
            "post-completion-authoritative-executor",
            PostCompletionRollbackApplierRole::Executor,
            fixture.operation.created_at_unix_ms + 1,
            Rc::clone(&exchange_count),
        );
        let expected_session = client.session().clone();
        client
            .validate_post_completion_rollback_request(
                &ledger,
                &fixture.operation,
                &fixture.application,
                &fixture.rollback_reference,
                &fixture.change_set,
                &fixture.bundle,
                &fixture.rollback,
            )
            .expect("exact durable request is dispatchable");

        let mut substituted_bundle = fixture.bundle.clone();
        substituted_bundle.bundle_digest = Digest::sha256(b"same change set, different bundle");
        assert!(
            client
                .validate_post_completion_rollback_request(
                    &ledger,
                    &fixture.operation,
                    &fixture.application,
                    &fixture.rollback_reference,
                    &fixture.change_set,
                    &substituted_bundle,
                    &fixture.rollback,
                )
                .is_err()
        );
        let mut crossed_application = fixture.application.clone();
        crossed_application.receipt.receipt_id = "crossed-application-authority".into();
        assert!(
            client
                .validate_post_completion_rollback_request(
                    &ledger,
                    &fixture.operation,
                    &crossed_application,
                    &fixture.rollback_reference,
                    &fixture.change_set,
                    &fixture.bundle,
                    &fixture.rollback,
                )
                .is_err()
        );
        let mut fabricated_operation = fixture.operation.clone();
        fabricated_operation.operation_id = "fabricated-operation".into();
        assert!(matches!(
            client.validate_post_completion_rollback_request(
                &ledger,
                &fabricated_operation,
                &fixture.application,
                &fixture.rollback_reference,
                &fixture.change_set,
                &fixture.bundle,
                &fixture.rollback,
            ),
            Err(RunnerClientError::MissingDurableApplicationArtifactAuthority)
        ));
        let durable_session_id = client.session.session_id.clone();
        client.session.session_id = "crossed-session".into();
        assert!(
            client
                .validate_post_completion_rollback_request(
                    &ledger,
                    &fixture.operation,
                    &fixture.application,
                    &fixture.rollback_reference,
                    &fixture.change_set,
                    &fixture.bundle,
                    &fixture.rollback,
                )
                .is_err()
        );
        client.session.session_id = durable_session_id;
        assert_eq!(exchange_count.get(), 2);

        let outcome = client
            .send_post_completion_rollback(
                &ledger,
                &fixture.operation,
                &fixture.application,
                &fixture.rollback_reference,
                &fixture.change_set,
                fixture.bundle.clone(),
                fixture.rollback.clone(),
            )
            .expect("authoritative operation reaches one rollback exchange");
        assert!(matches!(
            outcome.exchange().response.response,
            RunnerResponse::Failed {
                class: WireFailureClass::BeforeEffect,
                reconciliation: None,
                ..
            }
        ));
        let (exchange, cleanup) = outcome.into_parts();
        assert!(matches!(
            exchange.request.request,
            RunnerRequest::ApplierRollback { .. }
        ));
        assert_eq!(cleanup.session(), Some(&expected_session));
        assert!(cleanup.shutdown_prepared().is_some());
        assert!(matches!(
            cleanup.direct_child_outcome(),
            DirectChildOutcome::Exited { success: true, .. }
        ));
        assert_eq!(exchange_count.get(), 4);
        assert!(
            ledger
                .load_effect(&fixture.operation.rollback_effect_id)
                .is_err()
        );
    }

    #[test]
    fn post_completion_dispatch_missing_operation_and_legacy_authority_fail_closed() {
        assert!(matches!(
            map_post_completion_ledger_error(LedgerError::ArtifactNotFound {
                entity: "post-completion rollback operation",
                id: "missing-operation".into(),
            }),
            RunnerClientError::MissingDurableApplicationArtifactAuthority
        ));
        assert!(matches!(
            require_post_completion_application_artifact_authority(
                &PostCompletionRollbackApplicationArtifactAuthorityState::LegacyMissing,
            ),
            Err(RunnerClientError::MissingDurableApplicationArtifactAuthority)
        ));
    }

    #[test]
    fn post_completion_dispatch_accepts_typed_success_conflict_and_legacy_success() {
        for response_kind in ["typed-success", "live-conflict", "legacy-success"] {
            let (harness, mut ledger) = TestHarness::new(response_kind);
            let (fixture, policy) = prepare_authoritative_post_completion_dispatch(
                &harness,
                &mut ledger,
                response_kind,
            );
            let response = match response_kind {
                "typed-success" => typed_rollback_success(&fixture),
                "live-conflict" => typed_rollback_live_conflict(&fixture),
                "legacy-success" => legacy_rollback_success(&fixture),
                _ => unreachable!("closed response fixture set"),
            };
            let exchange_count = Rc::new(Cell::new(0));
            let client = launch_post_completion_test_client_with_response(
                &harness,
                &mut ledger,
                &fixture,
                &policy,
                &format!("{response_kind}-executor"),
                response,
                Rc::clone(&exchange_count),
            );
            let outcome = client
                .send_post_completion_rollback(
                    &ledger,
                    &fixture.operation,
                    &fixture.application,
                    &fixture.rollback_reference,
                    &fixture.change_set,
                    fixture.bundle,
                    fixture.rollback,
                )
                .expect("admitted rollback response shape");
            match (response_kind, &outcome.exchange().response.response) {
                ("typed-success", RunnerResponse::RollbackCompletedWithEvidence { .. })
                | ("live-conflict", RunnerResponse::RollbackLiveConflict { .. })
                | ("legacy-success", RunnerResponse::RollbackCompleted { .. }) => {}
                _ => panic!("rollback response changed after strict correlation"),
            }
            let (_, cleanup) = outcome.into_parts();
            assert!(cleanup.shutdown_prepared().is_some());
            assert!(matches!(
                cleanup.direct_child_outcome(),
                DirectChildOutcome::Exited { success: true, .. }
            ));
            assert_eq!(exchange_count.get(), 4);
        }
    }

    #[test]
    fn post_completion_dispatch_substituted_bundle_fails_before_transport() {
        let (harness, mut ledger) = TestHarness::new("post-completion-substitution");
        let (mut fixture, policy) = prepare_authoritative_post_completion_dispatch(
            &harness,
            &mut ledger,
            "post-completion-substitution",
        );
        let exchange_count = Rc::new(Cell::new(0));
        let client = launch_post_completion_test_client(
            &harness,
            &mut ledger,
            &fixture,
            &policy,
            "post-completion-substitution-executor",
            PostCompletionRollbackApplierRole::Executor,
            fixture.operation.created_at_unix_ms + 1,
            Rc::clone(&exchange_count),
        );
        let expected_session = client.session().clone();
        fixture.bundle.bundle_digest = Digest::sha256(b"substituted bundle identity");
        let failure = client
            .send_post_completion_rollback(
                &ledger,
                &fixture.operation,
                &fixture.application,
                &fixture.rollback_reference,
                &fixture.change_set,
                fixture.bundle,
                fixture.rollback,
            )
            .expect_err("substituted bundle must fail before transport");
        assert!(matches!(
            failure.error(),
            RunnerClientError::InvalidLifecycle(message)
                if message.contains("post-completion rollback differs")
        ));
        assert!(!failure.rollback_exchange_started());
        let (_, exchange, cleanup) = failure.into_parts();
        assert!(exchange.is_none());
        assert_eq!(cleanup.session(), Some(&expected_session));
        assert!(cleanup.shutdown_prepared().is_none());
        assert!(matches!(
            cleanup.direct_child_outcome(),
            DirectChildOutcome::Exited { success: true, .. }
        ));
        assert_eq!(exchange_count.get(), 2);
    }

    #[test]
    fn post_completion_substituted_result_snapshot_fails_before_launch_or_transport() {
        let (harness, mut ledger) = TestHarness::new("post-completion-result-substitution");
        let (fixture, policy) = prepare_authoritative_post_completion_dispatch(
            &harness,
            &mut ledger,
            "post-completion-result-substitution",
        );
        let mut launch = harness.launch("post-completion-result-substitution-executor");
        launch.role = RunnerRole::Applier;
        launch.worker_id = None;
        launch.worker_lease = None;
        launch.shadow_root = None;
        launch.expected_base_snapshot = harness.base_snapshot.clone();
        launch.created_at_unix_ms = fixture.operation.created_at_unix_ms + 1;
        let spawned = Cell::new(false);
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_post_completion_rollback_with_spawner(
                &mut ledger,
                &harness.authority,
                &policy,
                &fixture.operation,
                PostCompletionRollbackApplierRole::Executor,
                launch,
                |_, _| {
                    spawned.set(true);
                    unreachable!("substituted applied result must fail before transport")
                },
            ),
            "substituted applied-result snapshot must fail",
        );
        assert!(!spawned.get());
        assert!(matches!(
            failure.error(),
            RunnerClientError::InvalidLifecycle(message)
                if message.contains("exact applied artifact result snapshot")
        ));
        assert!(failure.into_cleanup_required().is_none());
        assert!(
            ledger
                .load_post_completion_rollback(&fixture.operation.operation_id)
                .expect("reload untouched rollback operation")
                .appliers
                .is_empty(),
            "result substitution must not persist a rollback applier launch"
        );
    }

    #[test]
    fn post_completion_dispatch_recovery_launch_fences_executor_replay() {
        let (harness, mut ledger) = TestHarness::new("post-completion-recovery-no-replay");
        let (fixture, policy) = prepare_authoritative_post_completion_dispatch(
            &harness,
            &mut ledger,
            "post-completion-recovery-no-replay",
        );
        let executor_count = Rc::new(Cell::new(0));
        let executor = launch_post_completion_test_client(
            &harness,
            &mut ledger,
            &fixture,
            &policy,
            "post-completion-recovery-original",
            PostCompletionRollbackApplierRole::Executor,
            fixture.operation.created_at_unix_ms + 1,
            Rc::clone(&executor_count),
        );
        let expected_session = executor.session().clone();
        let recovery_count = Rc::new(Cell::new(0));
        let recovery = launch_post_completion_test_client(
            &harness,
            &mut ledger,
            &fixture,
            &policy,
            "post-completion-recovery-validator",
            PostCompletionRollbackApplierRole::RecoveryValidator,
            expected_session.registered_at_unix_ms + 1,
            Rc::clone(&recovery_count),
        );
        let recovery_cleanup = recovery
            .shutdown()
            .expect("shut down recovery validator fixture");
        assert!(recovery_cleanup.shutdown_prepared().is_some());
        assert_eq!(recovery_count.get(), 3);

        let failure = executor
            .send_post_completion_rollback(
                &ledger,
                &fixture.operation,
                &fixture.application,
                &fixture.rollback_reference,
                &fixture.change_set,
                fixture.bundle,
                fixture.rollback,
            )
            .expect_err("a recovery launch proves the executor exchange is not replayable");
        assert!(matches!(
            failure.error(),
            RunnerClientError::InvalidLifecycle(message)
                if message.contains("exactly one executor")
        ));
        assert!(!failure.rollback_exchange_started());
        let (_, exchange, cleanup) = failure.into_parts();
        assert!(exchange.is_none());
        assert_eq!(cleanup.session(), Some(&expected_session));
        assert!(matches!(
            cleanup.direct_child_outcome(),
            DirectChildOutcome::Exited { success: true, .. }
        ));
        assert_eq!(executor_count.get(), 2);
    }

    #[test]
    fn post_completion_recovery_registration_error_reads_back_second_applier() {
        let (harness, mut ledger) = TestHarness::new("post-completion-recovery-registration");
        let (fixture, policy) = prepare_authoritative_post_completion_dispatch(
            &harness,
            &mut ledger,
            "post-completion-recovery-registration",
        );
        let executor_count = Rc::new(Cell::new(0));
        let executor = launch_post_completion_test_client(
            &harness,
            &mut ledger,
            &fixture,
            &policy,
            "post-completion-registration-executor",
            PostCompletionRollbackApplierRole::Executor,
            fixture.operation.created_at_unix_ms + 1,
            Rc::clone(&executor_count),
        );

        let mut recovery_launch = harness.launch("post-completion-registration-recovery");
        recovery_launch.role = RunnerRole::Applier;
        recovery_launch.worker_id = None;
        recovery_launch.worker_lease = None;
        recovery_launch.shadow_root = None;
        recovery_launch.expected_base_snapshot = fixture.change_set.result_snapshot.clone();
        recovery_launch.created_at_unix_ms = executor.session.registered_at_unix_ms + 1;
        let expected_launch_id = recovery_launch.launch_id.clone();
        let expected_session_id = recovery_launch.session_id.clone();
        let hardlink = harness
            .root
            .join("post-completion-recovery-session-hardlink.sqlite3");
        let spawn_hardlink = hardlink.clone();
        let database = harness.database.clone();
        let scripted = transport(
            unique_nonce("post-completion-registration-recovery"),
            harness.identity(),
            ScriptMode::Good,
            false,
            Vec::new(),
        );
        let failure = expect_launch_failure(
            RunnerLifecycleClient::launch_post_completion_rollback_with_spawner(
                &mut ledger,
                &harness.authority,
                &policy,
                &fixture.operation,
                PostCompletionRollbackApplierRole::RecoveryValidator,
                recovery_launch,
                move |executable, expected_binding| {
                    assert!(expected_binding.is_none());
                    fs::hard_link(&database, &spawn_hardlink)
                        .expect("create recovery registration hardening fault");
                    scripted(executable, expected_binding)
                },
            ),
            "recovery session post-commit hardening must abort launch",
        );
        fs::remove_file(&hardlink).expect("remove recovery registration hardlink fault");
        let cleanup = failure
            .into_cleanup_required()
            .expect("operation-local registration failure requires cleanup");
        let registered = cleanup
            .session()
            .expect("second applier exact readback is durably registered");
        assert_eq!(registered.launch_id, expected_launch_id);
        assert_eq!(registered.session_id, expected_session_id);
        assert!(matches!(
            cleanup.session_registration(),
            RunnerSessionRegistrationState::Registered(session) if session == registered
        ));
        assert!(cleanup.launch_cleanup_admission().is_none());
        assert!(cleanup.expected_platform_launch_binding().is_none());
        let operation = ledger
            .load_post_completion_rollback(&fixture.operation.operation_id)
            .expect("reload both operation-local appliers");
        assert_eq!(operation.appliers.len(), 2);
        assert_eq!(
            operation.appliers[1]
                .session
                .as_ref()
                .expect("recovery session persisted"),
            registered
        );
        executor.shutdown().expect("shut down original executor");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the terminal replay regression keeps the observation, exact cleanup set, terminal, rejected dispatch, and surviving cleanup handoff visible"
    )]
    fn post_completion_dispatch_terminal_observation_fences_replay() {
        let (harness, mut ledger) = TestHarness::new("post-completion-observed-no-replay");
        let (fixture, policy) = prepare_authoritative_post_completion_dispatch(
            &harness,
            &mut ledger,
            "post-completion-observed-no-replay",
        );
        let exchange_count = Rc::new(Cell::new(0));
        let client = launch_post_completion_test_client(
            &harness,
            &mut ledger,
            &fixture,
            &policy,
            "post-completion-observed-executor",
            PostCompletionRollbackApplierRole::Executor,
            fixture.operation.created_at_unix_ms + 1,
            Rc::clone(&exchange_count),
        );
        let expected_session = client.session().clone();
        let evidence_bytes = b"correlated executor result remains unprovable".to_vec();
        let effect_started_at_unix_ms = expected_session.registered_at_unix_ms + 1;
        let operation_observation = PostCompletionRollbackObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: "observation-post-completion-unknown".into(),
            operation_id: fixture.operation.operation_id.clone(),
            sprint_id: fixture.operation.sprint_id.clone(),
            rollback_effect_id: fixture.operation.rollback_effect_id.clone(),
            request_digest: fixture.operation.request_digest.clone(),
            executor_launch_id: client.launch.launch_id.clone(),
            executor_session_id: expected_session.session_id.clone(),
            outcome: PostCompletionRollbackOutcome::Unknown {
                evidence: PostCompletionRollbackUnknownEvidence {
                    evidence_id: "evidence-post-completion-unknown".into(),
                    reason: "test retains truthful ambiguity".into(),
                    reconciliation_evidence_digest: Digest::sha256(&evidence_bytes),
                    reconciliation_evidence_bytes: evidence_bytes,
                },
                validation: RollbackValidationEvidence {
                    mode: RollbackValidationMode::DirectEffectResponse,
                    runner_launch_id: client.launch.launch_id.clone(),
                    runner_session_id: expected_session.session_id.clone(),
                    policy_hash: expected_session.policy_hash.clone(),
                    grant_hash: expected_session.grant_hash.clone(),
                    policy_version: expected_session.policy_version,
                    private_state_digest: expected_session.private_state_digest.clone(),
                },
            },
            effect_started_at_unix_ms,
            observed_at_unix_ms: effect_started_at_unix_ms + 1,
        };
        ledger
            .record_post_completion_rollback_observation(&operation_observation)
            .expect("persist immutable operation observation");
        let cleanup_request = WorkerCleanupRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: fixture.operation.sprint_id.clone(),
            launch_id: client.launch.launch_id.clone(),
            session_id: expected_session.session_id.clone(),
            policy_hash: expected_session.policy_hash.clone(),
            grant_hash: expected_session.grant_hash.clone(),
            policy_version: expected_session.policy_version,
            platform_backend: WorkerCleanupBackend::TrustedApplierDirectChildWait,
        };
        let cleanup_intent = PostCompletionRollbackCleanupIntent::new(
            fixture.operation.operation_id.clone(),
            "post-completion-terminal-cleanup-effect".into(),
            cleanup_request,
            operation_observation.observed_at_unix_ms + 1,
        )
        .expect("construct operation-local cleanup intent");
        ledger
            .record_post_completion_rollback_cleanup_intent(&cleanup_intent)
            .expect("persist operation-local cleanup intent");
        let cleanup_bytes = b"zero descendants for terminal replay fixture".to_vec();
        let cleanup_receipt_id = "post-completion-terminal-cleanup-receipt".to_owned();
        let cleanup_evidence = PostCompletionRollbackCleanupEvidence {
            contract_version: CONTRACT_VERSION,
            operation_id: fixture.operation.operation_id.clone(),
            cleanup_effect_id: cleanup_intent.cleanup_effect_id.clone(),
            request_digest: cleanup_intent.request_digest.clone(),
            evidence: WorkerCleanupEvidence {
                receipt: WorkerCleanupReceipt {
                    contract_version: CONTRACT_VERSION,
                    receipt_id: cleanup_receipt_id.clone(),
                    sprint_id: fixture.operation.sprint_id.clone(),
                    launch_id: client.launch.launch_id.clone(),
                    effect_id: cleanup_intent.cleanup_effect_id,
                    observation_id: "post-completion-terminal-cleanup-observation".into(),
                    session_id: expected_session.session_id.clone(),
                    worker_lease: None,
                    policy_hash: expected_session.policy_hash.clone(),
                    grant_hash: expected_session.grant_hash.clone(),
                    policy_version: expected_session.policy_version,
                    platform_backend: WorkerCleanupBackend::TrustedApplierDirectChildWait,
                    os_evidence_digest: Digest::sha256(&cleanup_bytes),
                    surviving_processes: 0,
                    cleaned_at_unix_ms: operation_observation.observed_at_unix_ms + 2,
                },
                os_evidence_bytes: cleanup_bytes,
            },
        };
        ledger
            .record_post_completion_rollback_cleanup(&cleanup_evidence)
            .expect("persist operation-local cleanup evidence");
        ledger
            .finalize_post_completion_rollback(&PostCompletionRollbackTerminal {
                contract_version: CONTRACT_VERSION,
                terminal_id: "post-completion-terminal-replay-fixture".into(),
                operation_id: fixture.operation.operation_id.clone(),
                sprint_id: fixture.operation.sprint_id.clone(),
                application_receipt_id: fixture.operation.request.application_receipt_id.clone(),
                outcome_id: operation_observation.observation_id.clone(),
                kind: PostCompletionRollbackOutcomeKind::Unknown,
                cleanup_receipt_ids: vec![cleanup_receipt_id],
                terminal_at_unix_ms: operation_observation.observed_at_unix_ms + 3,
            })
            .expect("finalize observed operation");

        let failure = client
            .send_post_completion_rollback(
                &ledger,
                &fixture.operation,
                &fixture.application,
                &fixture.rollback_reference,
                &fixture.change_set,
                fixture.bundle,
                fixture.rollback,
            )
            .expect_err("terminal observed operation cannot dispatch again");
        assert!(matches!(
            failure.error(),
            RunnerClientError::InvalidLifecycle(message)
                if message.contains("immutable outcome")
        ));
        assert!(!failure.rollback_exchange_started());
        let (_, exchange, cleanup) = failure.into_parts();
        assert!(exchange.is_none());
        assert_eq!(cleanup.session(), Some(&expected_session));
        assert!(matches!(
            cleanup.direct_child_outcome(),
            DirectChildOutcome::Exited { success: true, .. }
        ));
        assert_eq!(exchange_count.get(), 2);
    }

    #[test]
    fn applier_requires_exact_canonical_artifact_bound_application_request() {
        let base = Digest::sha256(b"typed-apply-base");
        let result = Digest::sha256(b"typed-apply-result");
        let change_set = ChangeSet {
            change_set_id: "typed-change-1".into(),
            base_snapshot: base.clone(),
            result_snapshot: result.clone(),
            operations: vec![FileOperation::Create {
                path: PathBuf::from("src/typed.rs"),
                result_hash: Digest::sha256(b"typed bytes"),
            }],
        };
        let bundle = StageBundleReference {
            format_version: 1,
            bundle_digest: Digest::sha256(b"typed-stage-bundle"),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: base.clone(),
            result_snapshot: result.clone(),
        };
        let application = ApplicationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: change_set.clone(),
            artifact: bundle
                .to_core_integration_artifact()
                .expect("map typed bundle"),
        };
        let canonical = serde_json::to_vec(&application).expect("encode typed application");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-typed-applier".into(),
            idempotency_key: "key-typed-applier".into(),
            sprint_id: "sprint-typed-applier".into(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-typed-applier".into(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&canonical),
            policy_hash: Digest::sha256(b"typed-policy"),
            input_snapshot: base.clone(),
            created_at_unix_ms: 1,
        };
        let request = RunnerRequest::ApplierApplyBundle {
            bundle: bundle.clone(),
        };
        validate_applier_application_request(&intent, &canonical, &request, &base)
            .expect("exact application request and bundle");

        let bare_change_set = serde_json::to_vec(&change_set).expect("encode old bare request");
        assert!(
            validate_applier_application_request(&intent, &bare_change_set, &request, &base)
                .is_err()
        );

        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(&canonical);
        assert!(
            validate_applier_application_request(&intent, &noncanonical, &request, &base).is_err()
        );

        let mut substituted_bundle = bundle.clone();
        substituted_bundle.bundle_digest = Digest::sha256(b"substituted-stage-bundle");
        assert!(
            validate_applier_application_request(
                &intent,
                &canonical,
                &RunnerRequest::ApplierApplyBundle {
                    bundle: substituted_bundle,
                },
                &base,
            )
            .is_err()
        );
        assert!(
            validate_applier_application_request(
                &intent,
                &canonical,
                &request,
                &Digest::sha256(b"another-admitted-base"),
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed table keeps all five provider file schemas and their exact runner mappings visible together"
    )]
    fn provider_file_calls_map_field_for_field_to_runner_requests() {
        let expected_hash = Digest::sha256(b"expected provider file");
        let cases = [
            (
                ProviderToolIntent::ReadRelativeFile {
                    path: PathBuf::from("src/read.rs"),
                    max_bytes: 321,
                },
                EffectKind::ReadRelativeFile,
                RunnerRequest::WorkerReadFile {
                    path: "src/read.rs".into(),
                    max_bytes: 321,
                },
            ),
            (
                ProviderToolIntent::SearchLiteral {
                    path: PathBuf::from("src/search.rs"),
                    literal: "exact literal".into(),
                    max_matches: 17,
                },
                EffectKind::SearchLiteral,
                RunnerRequest::WorkerSearchLiteral {
                    path: "src/search.rs".into(),
                    needle: b"exact literal".to_vec(),
                    max_bytes: u64::try_from(MAX_PROVIDER_FILE_BYTES)
                        .expect("provider file limit fits u64"),
                    max_matches: 17,
                },
            ),
            (
                ProviderToolIntent::CreateRegularFile {
                    path: PathBuf::from("src/create.rs"),
                    contents: b"create bytes".to_vec(),
                },
                EffectKind::CreateRegularFile,
                RunnerRequest::WorkerCreateFile {
                    path: "src/create.rs".into(),
                    contents: b"create bytes".to_vec(),
                },
            ),
            (
                ProviderToolIntent::ReplaceRegularFile {
                    path: PathBuf::from("src/replace.rs"),
                    expected_hash: expected_hash.clone(),
                    contents: b"replacement bytes".to_vec(),
                },
                EffectKind::ReplaceRegularFile,
                RunnerRequest::WorkerReplaceFile {
                    path: "src/replace.rs".into(),
                    expected_digest: expected_hash.clone(),
                    contents: b"replacement bytes".to_vec(),
                },
            ),
            (
                ProviderToolIntent::DeleteRegularFile {
                    path: PathBuf::from("src/delete.rs"),
                    expected_hash: expected_hash.clone(),
                },
                EffectKind::DeleteRegularFile,
                RunnerRequest::WorkerDeleteFile {
                    path: "src/delete.rs".into(),
                    expected_digest: expected_hash,
                },
            ),
        ];

        let lease = provider_map_worker_lease();
        for (index, (tool, kind, request)) in cases.into_iter().enumerate() {
            let idempotency_key = format!("provider-map-key-{index}");
            let bytes = encode_tool_call(&ProviderToolCall {
                sprint_id: "provider-map-sprint".into(),
                task_id: "provider-map-task".into(),
                sequence: u32::try_from(index + 1).expect("case index fits u32"),
                call_id: format!("provider-map-call-{index}"),
                idempotency_key: idempotency_key.clone(),
                intent: tool,
            })
            .expect("encode canonical provider file call");
            let intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: format!("provider-map-effect-{index}"),
                idempotency_key: task_lease_provider_call_effect_key(
                    &lease.lease_id,
                    &idempotency_key,
                ),
                sprint_id: "provider-map-sprint".into(),
                task_id: Some("provider-map-task".into()),
                worker_id: Some("provider-map-worker".into()),
                worker_lease: Some(lease.clone()),
                causation_event_id: None,
                correlation_id: "provider-map-correlation".into(),
                kind,
                request_digest: Digest::sha256(&bytes),
                policy_hash: Digest::sha256(b"provider-map-policy"),
                input_snapshot: Digest::sha256(b"provider-map-snapshot"),
                created_at_unix_ms: 1,
            };
            validate_worker_provider_tool_request(&intent, &bytes, &request)
                .expect("canonical provider call must map to one exact runner request");
        }
    }

    /// One exact task-attempt lease for the provider-call context tests. A
    /// worker tool effect only exists inside an attempt, so every intent these
    /// tests build carries the lease its durable key is scoped to.
    fn provider_map_worker_lease() -> WorkerLease {
        WorkerLease {
            contract_version: CONTRACT_VERSION,
            lease_id: "provider-map-lease-v1".into(),
            sprint_id: "provider-map-sprint".into(),
            lease_epoch: 1,
            task_id: "provider-map-task".into(),
            worker_id: "provider-map-worker".into(),
            path_scopes: Vec::new(),
            acquired_at_unix_ms: 1,
        }
    }

    /// D-0012 regression. The coordinator scopes every worker tool effect's
    /// durable idempotency key to the attempt's lease
    /// (`task-attempt-<sha256(lease_id)>-<provider key>`) because a provider
    /// re-emits the same raw call key on every attempt of the same task, and
    /// ADR-0004 requires each side-effecting action to receive a globally
    /// unique key and forbids the original intent from becoming replay
    /// authority for a retry. The runner client used to compare the provider's
    /// **raw** key against `intent.idempotency_key`, so the two validators of
    /// one relation disagreed and every worker tool effect was refused.
    ///
    /// Both validators are exercised over the same pair here: disagreement is
    /// the defect, so agreement is what has to be pinned. The expected key is
    /// spelled out literally rather than re-derived, so a silent change to the
    /// shared derivation cannot make this test vacuously pass.
    #[test]
    fn worker_tool_call_idempotency_key_is_lease_scoped_for_both_validators() {
        use crate::durable_coordinator::validate_provider_call_for_effect;

        let lease = provider_map_worker_lease();
        let call = ProviderToolCall {
            sprint_id: lease.sprint_id.clone(),
            task_id: lease.task_id.clone(),
            sequence: 1,
            call_id: "provider-map-lease-scoped-call".into(),
            idempotency_key: "fake-v1-01-read-agents".into(),
            intent: ProviderToolIntent::ReadRelativeFile {
                path: PathBuf::from("AGENTS.md"),
                max_bytes: 64 * 1024,
            },
        };
        let bytes = encode_tool_call(&call).expect("encode canonical provider file call");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "provider-map-lease-scoped-effect".into(),
            idempotency_key: format!(
                "task-attempt-{}-fake-v1-01-read-agents",
                Digest::sha256(lease.lease_id.as_bytes())
            ),
            sprint_id: lease.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            worker_lease: Some(lease.clone()),
            causation_event_id: None,
            correlation_id: format!("{}:walking-skeleton-v1", lease.sprint_id),
            kind: EffectKind::ReadRelativeFile,
            request_digest: Digest::sha256(&bytes),
            policy_hash: Digest::sha256(b"provider-map-policy"),
            input_snapshot: Digest::sha256(b"provider-map-snapshot"),
            created_at_unix_ms: 1,
        };

        // The relation the coordinator mints is admitted by both validators.
        validate_worker_provider_call_context(&call, &intent).expect(
            "the runner client must admit the lease-scoped derivation of the raw provider key",
        );
        validate_provider_call_for_effect(&call, &intent, &bytes)
            .expect("the coordinator must admit the exact same pair");

        // The raw provider key is not an effect identity. Before the fix the
        // runner client admitted exactly this intent and refused the durable
        // one above.
        let mut raw_key_intent = intent.clone();
        raw_key_intent.idempotency_key = call.idempotency_key.clone();
        assert!(
            validate_worker_provider_call_context(&call, &raw_key_intent).is_err(),
            "the raw provider call key must not be accepted as the durable effect identity"
        );
        assert!(
            validate_provider_call_for_effect(&call, &raw_key_intent, &bytes).is_err(),
            "the coordinator must refuse the raw key for the same reason"
        );

        // A call whose raw key does not derive to the intent's key is refused
        // even though sprint, task, and kind all agree.
        let mut crossed_call = call.clone();
        crossed_call.idempotency_key = "fake-v1-02-read-source".into();
        assert!(
            validate_worker_provider_call_context(&crossed_call, &intent).is_err(),
            "a provider call whose key does not derive to the intent's key must be refused"
        );

        // The same raw key under a different lease derives to a different
        // durable key, which is the global uniqueness a retry depends on.
        let mut retry_lease = lease.clone();
        retry_lease.lease_id = "provider-map-lease-v2".into();
        retry_lease.lease_epoch = 2;
        let mut retry_intent = intent.clone();
        retry_intent.worker_lease = Some(retry_lease);
        assert!(
            validate_worker_provider_call_context(&call, &retry_intent).is_err(),
            "a fresh lease must not admit the previous attempt's durable key"
        );

        // Worker-only: a missing attempt lease is refused, never skipped.
        let mut leaseless_intent = intent.clone();
        leaseless_intent.worker_lease = None;
        let leaseless = validate_worker_provider_call_context(&call, &leaseless_intent)
            .expect_err("a worker provider call without its attempt lease must be refused");
        assert!(
            leaseless
                .to_string()
                .contains("lacks exact task-attempt authority"),
            "the refusal must name the missing attempt authority: {leaseless}"
        );
    }

    #[test]
    fn nonce_registry_and_applier_snapshot_bindings_fail_closed() {
        let first = Digest::sha256(b"first");
        let second = Digest::sha256(b"second");
        let mut seen = BTreeSet::new();
        admit_nonce_into(&mut seen, &first, 1).expect("first nonce");
        assert!(admit_nonce_into(&mut seen, &first, 1).is_err());
        assert!(admit_nonce_into(&mut seen, &second, 1).is_err());

        let base = Digest::sha256(b"apply-base");
        let result = Digest::sha256(b"apply-result");
        let bundle = StageBundleReference {
            format_version: 1,
            bundle_digest: Digest::sha256(b"bundle"),
            change_set_id: "change-1".into(),
            base_snapshot: base.clone(),
            result_snapshot: result.clone(),
        };
        let mut intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-applier".into(),
            idempotency_key: "key-applier".into(),
            sprint_id: "sprint-applier".into(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-applier".into(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(b"request"),
            policy_hash: Digest::sha256(b"policy"),
            input_snapshot: result.clone(),
            created_at_unix_ms: 1,
        };
        assert!(
            validate_applier_input_snapshot(
                &intent,
                &RunnerRequest::ApplierApplyBundle {
                    bundle: bundle.clone()
                }
            )
            .is_err()
        );
        intent.input_snapshot = base.clone();
        assert!(
            validate_applier_input_snapshot(
                &intent,
                &RunnerRequest::ApplierApplyBundle {
                    bundle: bundle.clone()
                }
            )
            .is_ok()
        );

        let rollback = WireRollbackArtifactReference {
            transaction_id: "transaction-1".into(),
            change_set_id: bundle.change_set_id.clone(),
            base_snapshot: base.clone(),
            touched_target_set_digest: Digest::sha256(b"targets"),
            target_contract_digest: Digest::sha256(b"target contract"),
            transaction_device: 1,
            transaction_inode: 1,
            transaction_mode: 0o700,
            transaction_owner_uid: 1,
            artifacts_digest: Digest::sha256(b"artifacts"),
            artifacts: Vec::new(),
        };
        intent.kind = EffectKind::RollbackChangeSet;
        intent.input_snapshot = base;
        assert!(
            validate_applier_input_snapshot(
                &intent,
                &RunnerRequest::ApplierRollback {
                    bundle: bundle.clone(),
                    rollback: rollback.clone(),
                }
            )
            .is_err()
        );
        intent.input_snapshot = result;
        assert!(
            validate_applier_input_snapshot(
                &intent,
                &RunnerRequest::ApplierRollback { bundle, rollback }
            )
            .is_ok()
        );
    }

    #[test]
    fn typed_reconciliation_allows_only_exact_same_session_repairs() {
        let (harness, mut ledger) = TestHarness::new("reconciliation");
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("reconciliation"),
            transport(
                unique_nonce("reconciliation"),
                harness.identity(),
                ScriptMode::Good,
                false,
                Vec::new(),
            ),
        )
        .expect("initialize reconciliation client");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());

        for reference in [
            WireReconciliationReference::ApplicationRecovery,
            WireReconciliationReference::SessionPrivateState {
                state_id: "worker-shadow".into(),
            },
        ] {
            let failure = RunnerResponse::Failed {
                code: "restart-required".into(),
                class: WireFailureClass::ReconciliationRequired,
                reconciliation: Some(reference),
                message: "fresh recovery session required".into(),
            };
            assert!(client.apply_failure_response(&failure).is_err());
        }

        let file_failure = RunnerResponse::Failed {
            code: "file-uncertain".into(),
            class: WireFailureClass::ReconciliationRequired,
            reconciliation: Some(WireReconciliationReference::File {
                path: "README.md".into(),
            }),
            message: "reconcile exact endpoint".into(),
        };
        assert!(
            client
                .apply_failure_response(&file_failure)
                .expect("typed file reconciliation is resumable")
        );
        assert!(client.shadow_snapshot.is_none());
        assert!(
            client
                .validate_control_request(&RunnerRequest::WorkerReconcileFile {
                    path: "other.md".into(),
                    expected: grok_build_runner::WireFileExpectation::Absent,
                    max_bytes: 1,
                })
                .is_err()
        );
        assert!(
            client
                .validate_control_request(&RunnerRequest::WorkerReconcileFile {
                    path: "README.md".into(),
                    expected: grok_build_runner::WireFileExpectation::Absent,
                    max_bytes: 1,
                })
                .is_ok()
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the lifecycle cleanup fixture keeps the terminal command, phase boundaries, claimed integration, and exact disposition authority contiguous"
    )]
    fn persist_integrated_task_with_terminal_command(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        client: &RunnerLifecycleClient,
        suffix: &str,
    ) -> (TaskAttemptDisposition, String) {
        let running = client
            .task_attempt_running_boundary()
            .expect("cleanup fixture worker entered Running")
            .clone();
        let launch = client.launch.clone();
        let session = client.session().clone();
        let phase_time = session.registered_at_unix_ms.saturating_add(10);
        let result_snapshot = Digest::sha256(format!("integrated-result-{suffix}").as_bytes());
        let change_set = ChangeSet {
            change_set_id: format!("change-integrated-cleanup-{suffix}"),
            base_snapshot: harness.base_snapshot.clone(),
            result_snapshot: result_snapshot.clone(),
            operations: vec![FileOperation::Create {
                path: PathBuf::from(format!("src/integrated-cleanup-{suffix}.rs")),
                result_hash: Digest::sha256(format!("integrated-content-{suffix}").as_bytes()),
            }],
        };
        ledger
            .persist_workspace_snapshot(
                &harness.sprint_id,
                &WorkspaceSnapshot {
                    snapshot_id: result_snapshot.clone(),
                    grant_hash: harness.authority.contract().grant_hash.clone(),
                    created_at_unix_ms: phase_time,
                },
            )
            .expect("persist cleanup fixture result snapshot");
        ledger
            .persist_change_set(&harness.sprint_id, &change_set)
            .expect("persist cleanup fixture change set");

        let command = CommandSpec {
            program: "true".into(),
            arguments: Vec::new(),
            working_directory: PathBuf::new(),
        };
        let command_request_bytes =
            serde_json::to_vec(&command).expect("encode cleanup fixture command");
        let command_effect_id = format!("effect-integrated-cleanup-command-{suffix}");
        let command_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: command_effect_id.clone(),
            idempotency_key: format!("key-integrated-cleanup-command-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some(running.attempt.worker_lease.task_id.clone()),
            worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
            worker_lease: Some(running.attempt.worker_lease.clone()),
            causation_event_id: Some(running.transition_event_id.clone()),
            correlation_id: format!("correlation-integrated-cleanup-{suffix}"),
            kind: EffectKind::RunCommand,
            request_digest: Digest::sha256(&command_request_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            created_at_unix_ms: phase_time,
        };
        let command_proposal = proposal(
            &command_intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next cleanup command proposal sequence"),
        );
        let output_capture_intent = fresh_command_output_capture_intent(
            &command_intent,
            &launch,
            &session,
            &harness.policy,
        )
        .expect("construct exact cleanup-fixture command capture intent");
        let CommandOutputCaptureIntentAdmission::Fresh {
            effect: admitted_command,
            capture: admitted_capture,
            permit,
        } = ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &command_intent,
                &command_request_bytes,
                &command_proposal,
                &session.session_id,
                &output_capture_intent,
            )
            .expect("persist command and exact output capture bound to cleanup fixture session")
        else {
            panic!("fresh cleanup-fixture command must mint one capture permit")
        };
        assert_eq!(admitted_command.intent, command_intent);
        assert_eq!(admitted_capture.intent, output_capture_intent);
        assert!(admitted_capture.acquired.is_none());
        drop(permit);
        let command_failure_evidence =
            format!("command domain was admitted but execution was refused for {suffix}")
                .into_bytes();
        let command_observation = observation(
            &command_intent,
            format!("observation-integrated-cleanup-command-{suffix}"),
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: Digest::sha256(&command_failure_evidence),
            },
            phase_time.saturating_add(1),
        );
        let command_terminal = terminal_event(
            ledger,
            &command_intent,
            &command_proposal.event_id,
            &command_observation,
        );
        let capture_terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &output_capture_intent,
            None,
            &command_observation,
            CommandOutputCaptureTerminalDispositionV1::Abandoned,
            CommandOutputCaptureStoreHeadV1 {
                generation: 1,
                record_digest: Digest::sha256(
                    format!("intent-only capture abandoned for {suffix}").as_bytes(),
                ),
            },
            Digest::sha256(
                format!("no physical output reservation existed for {suffix}").as_bytes(),
            ),
            None,
            phase_time.saturating_add(1),
        )
        .expect("construct exact intent-only abandoned capture terminal");
        ledger
            .abandon_command_output_capture_before_dispatch(
                &command_observation,
                &command_failure_evidence,
                &command_terminal,
                &capture_terminal,
            )
            .expect("terminalize cleanup fixture command and capture atomically");

        let verification_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&harness.sprint_id)
                .expect("next cleanup fixture Verifying sequence"),
            event_id: format!("event-integrated-cleanup-verifying-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some(running.attempt.worker_lease.task_id.clone()),
            worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(command_terminal.event_id.clone()),
            correlation_id: format!("correlation-integrated-cleanup-{suffix}"),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: phase_time.saturating_add(2),
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Verifying".into(),
            },
        };
        let verification = TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("boundary-integrated-cleanup-verifying-{suffix}"),
            attempt: running.attempt.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
            sealed_snapshot: result_snapshot.clone(),
            transition_event_id: verification_event.event_id.clone(),
            terminal_non_cleanup_effects: vec![TaskAttemptTerminalEffect {
                effect_id: command_effect_id.clone(),
                observation_id: command_observation.observation_id.clone(),
            }],
            sealed_at_unix_ms: verification_event.occurred_at_unix_ms,
        };
        ledger
            .transition_task_attempt_to_verifying(&verification, &verification_event)
            .expect("enter cleanup fixture Verifying phase");

        let candidate_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&harness.sprint_id)
                .expect("next cleanup fixture Candidate sequence"),
            event_id: format!("event-integrated-cleanup-candidate-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some(running.attempt.worker_lease.task_id.clone()),
            worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(verification_event.event_id.clone()),
            correlation_id: format!("correlation-integrated-cleanup-{suffix}"),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: phase_time.saturating_add(3),
            payload: AgentEventKind::TaskStateChanged {
                from: "Verifying".into(),
                to: "Candidate".into(),
            },
        };
        let candidate = TaskAttemptCandidateBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("boundary-integrated-cleanup-candidate-{suffix}"),
            attempt: running.attempt.clone(),
            verification_boundary_id: verification.boundary_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
            sealed_snapshot: result_snapshot.clone(),
            formal_check_ids: Vec::new(),
            verification_receipt_ids: Vec::new(),
            transition_event_id: candidate_event.event_id.clone(),
            admitted_at_unix_ms: candidate_event.occurred_at_unix_ms,
        };
        ledger
            .transition_task_attempt_to_candidate(&candidate, &candidate_event)
            .expect("enter cleanup fixture Candidate phase");

        let bundle = StageBundleReference {
            format_version: 1,
            bundle_digest: Digest::sha256(format!("integration-bundle-{suffix}").as_bytes()),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
        };
        let artifact = bundle
            .to_core_integration_artifact()
            .expect("map cleanup fixture integration artifact");
        let integration_request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: change_set.clone(),
            artifact: artifact.clone(),
        };
        let integration_request_bytes =
            serde_json::to_vec(&integration_request).expect("encode cleanup integration request");
        let integration_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("effect-integrated-cleanup-{suffix}"),
            idempotency_key: format!("key-integrated-cleanup-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some(running.attempt.worker_lease.task_id.clone()),
            worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
            worker_lease: Some(running.attempt.worker_lease.clone()),
            causation_event_id: Some(candidate_event.event_id.clone()),
            correlation_id: format!("correlation-integrated-cleanup-{suffix}"),
            kind: EffectKind::IntegrateChangeSet,
            request_digest: Digest::sha256(&integration_request_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot: change_set.base_snapshot.clone(),
            created_at_unix_ms: phase_time.saturating_add(4),
        };
        let integration_proposal = proposal(
            &integration_intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next cleanup integration proposal sequence"),
        );
        let integration_admission = TaskAttemptIntegrationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("admission-integrated-cleanup-{suffix}"),
            candidate_boundary: candidate.clone(),
            effect_id: integration_intent.effect_id.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            input_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
            admitted_at_unix_ms: integration_intent.created_at_unix_ms,
        };
        let TaskIntegrationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_task_attempt_integration_for_dispatch(
                &integration_admission,
                &integration_intent,
                &integration_request,
                &integration_proposal,
            )
            .expect("admit cleanup fixture integration")
        else {
            panic!("new cleanup fixture integration must be fresh")
        };
        let (_, transport) = ledger
            .claim_task_attempt_integration_dispatch(permit, &integration_request_bytes)
            .expect("claim cleanup fixture integration");
        let observation_authority = transport
            .validate_transport_request(
                &integration_intent,
                &integration_request_bytes,
                &launch,
                &session,
                None,
                &integration_request_bytes,
            )
            .expect("validate cleanup fixture integration transport authority");
        let integration_evidence = TaskIntegrationEvidence {
            contract_version: CONTRACT_VERSION,
            artifact,
            validation: TaskIntegrationValidationEvidence {
                mode: TaskIntegrationValidationMode::WorkerPublication,
                runner_launch_id: launch.launch_id.clone(),
                runner_session_id: session.session_id.clone(),
                policy_hash: session.policy_hash.clone(),
                grant_hash: session.grant_hash.clone(),
                private_state_digest: session.private_state_digest.clone(),
            },
            receipt: TaskIntegrationReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!("receipt-integrated-cleanup-{suffix}"),
                sprint_id: harness.sprint_id.clone(),
                task_id: running.attempt.worker_lease.task_id.clone(),
                worker_id: running.attempt.worker_lease.worker_id.clone(),
                worker_lease: Some(running.attempt.worker_lease.clone()),
                worker_launch_id: launch.launch_id.clone(),
                worker_session_id: session.session_id.clone(),
                worker_policy_hash: session.policy_hash.clone(),
                effect_id: integration_intent.effect_id.clone(),
                observation_id: format!("observation-integrated-cleanup-{suffix}"),
                change_set_id: change_set.change_set_id.clone(),
                input_snapshot: change_set.base_snapshot.clone(),
                result_snapshot: change_set.result_snapshot.clone(),
                task_verification_receipt_ids: candidate.verification_receipt_ids.clone(),
                integration_ordinal: 0,
                integrated_at_unix_ms: phase_time.saturating_add(5),
            },
        };
        let integration_evidence_bytes =
            serde_json::to_vec(&integration_evidence).expect("encode cleanup integration evidence");
        let integration_observation = observation(
            &integration_intent,
            integration_evidence.receipt.observation_id.clone(),
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&integration_evidence_bytes),
            },
            integration_evidence.receipt.integrated_at_unix_ms,
        );
        let integration_terminal = terminal_event(
            ledger,
            &integration_intent,
            &integration_proposal.event_id,
            &integration_observation,
        );
        let integrated_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: integration_terminal.sequence.saturating_add(1),
            event_id: format!("event-integrated-cleanup-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some(running.attempt.worker_lease.task_id.clone()),
            worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(integration_terminal.event_id.clone()),
            correlation_id: format!("correlation-integrated-cleanup-{suffix}"),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: phase_time.saturating_add(6),
            payload: AgentEventKind::TaskStateChanged {
                from: "Candidate".into(),
                to: "Integrated".into(),
            },
        };
        let disposition = TaskAttemptDisposition::Integrated(TaskAttemptIntegratedDisposition {
            metadata: TaskAttemptDispositionMetadata {
                contract_version: CONTRACT_VERSION,
                disposition_id: format!("disposition-integrated-cleanup-{suffix}"),
                attempt: running.attempt,
                from_state: TaskState::Candidate,
                state_transition_event_id: integrated_event.event_id.clone(),
                disposed_at_unix_ms: integrated_event.occurred_at_unix_ms,
            },
            candidate_boundary: candidate,
            integration_receipt: integration_evidence.receipt.clone(),
            evidence: TaskAttemptEvidence::new(
                format!("evidence-integrated-cleanup-{suffix}"),
                TaskAttemptEvidenceKind::Integrated,
                integration_evidence_bytes,
            )
            .expect("construct cleanup fixture integration evidence"),
        });
        ledger
            .integrate_claimed_task_attempt(
                observation_authority,
                &disposition,
                &integration_observation,
                &integration_terminal,
                &integration_evidence,
                &integrated_event,
            )
            .expect("persist cleanup fixture Integrated disposition");
        (disposition, command_effect_id)
    }

    struct RestartIntegratedNativeCleanupFixture {
        harness: TestHarness,
        ledger: EventLedger,
        disposition: TaskAttemptDisposition,
        cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        cleanup_at_unix_ms: u64,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the restart fixture preserves the exact native launch journal, Integrated disposition, and command-domain cleanup ordering in one setup"
    )]
    fn restart_integrated_native_cleanup_fixture(
        label: &str,
    ) -> RestartIntegratedNativeCleanupFixture {
        let (harness, mut ledger) = TestHarness::new(label);
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
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
        .with_cleanup_script(Rc::new(Cell::new(0)), ScriptedNativeCleanupMutation::Exact);
        let launch = harness.launch(label);
        let client = RunnerLifecycleClient::launch_with_native_service(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            launch,
            Box::new(service),
        )
        .expect("initialize restart cleanup fixture through native prepare and release");
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 1);

        let cleanup_admission = client
            .launch_cleanup_admission()
            .expect("native launch retains its atomic cleanup admission")
            .clone();
        let session = client.session().clone();
        let preparation = ledger
            .load_runner_launch_preparation(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.launch_id,
            )
            .expect("reload exact durable native preparation");
        let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
            &cleanup_admission,
            Some(&preparation),
            client
                .platform_launch_binding
                .as_deref()
                .expect("native launch retains its exact platform binding"),
        );
        let (disposition, command_effect_id) =
            persist_integrated_task_with_terminal_command(&harness, &mut ledger, &client, label);
        let TaskAttemptDisposition::Integrated(integrated) = &disposition else {
            unreachable!("restart cleanup fixture always reaches Integrated")
        };
        let command_cleanup = CompletionRoleAdmission {
            launch: cleanup_admission.launch.clone(),
            cleanup_request: cleanup_admission.cleanup_request.clone(),
            cleanup_intent: cleanup_admission.cleanup_effect.intent.clone(),
            cleanup_proposed_event_id: cleanup_admission
                .cleanup_effect
                .proposed_event
                .event_id
                .clone(),
            session: session.clone(),
            task_attempt_running: None,
        };
        let command_cleaned_at_unix_ms = integrated
            .integration_receipt
            .integrated_at_unix_ms
            .saturating_add(1);
        persist_command_domain_cleanup_evidence(
            &mut ledger,
            &command_cleanup,
            &session,
            &command_effect_id,
            &format!("restart-command-cleanup-{label}"),
            command_cleaned_at_unix_ms,
        );

        // Dropping the old process-local owner models a desktop crash after
        // release: only durable launch/session/cleanup authority survives.
        drop(client);
        RestartIntegratedNativeCleanupFixture {
            harness,
            ledger,
            disposition,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms: command_cleaned_at_unix_ms.saturating_add(1),
            prepare_count,
            release_count,
        }
    }

    fn admitted_cleanup_without_native_custody(
        admission: PersistedRunnerLaunchCleanupAdmission,
        session: RunnerSessionPolicyRecord,
        platform_launch_binding: PlatformLaunchBinding,
    ) -> RunnerCleanupRequired {
        RunnerCleanupRequired {
            launch: admission.launch.clone(),
            launch_cleanup_admission: Some(Box::new(admission)),
            platform_launch_binding: Some(Box::new(platform_launch_binding)),
            native_cleanup_custody: None,
            session_registration: RunnerSessionRegistrationState::Registered(session),
            direct_child: DirectChildOutcome::NativeChildStateUnknown,
            shutdown_prepared: None,
        }
    }

    struct RestartUnadmittedFinalVerifierCleanupFixture {
        harness: TestHarness,
        ledger: EventLedger,
        final_snapshot: Digest,
        cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        cleanup_at_unix_ms: u64,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
        native_cleanup_count: Rc<Cell<u64>>,
        active: Option<(RunnerClientLaunch, RunnerLifecycleClient)>,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture constructs exact TaskDone plus one native FinalVerifier launch/session while deliberately omitting phase admission"
    )]
    fn restart_unadmitted_final_verifier_cleanup_fixture(
        label: &str,
    ) -> RestartUnadmittedFinalVerifierCleanupFixture {
        restart_unadmitted_final_verifier_cleanup_fixture_inner(label, true, false)
    }

    fn restart_sessionless_unadmitted_final_verifier_cleanup_fixture(
        label: &str,
    ) -> RestartUnadmittedFinalVerifierCleanupFixture {
        restart_unadmitted_final_verifier_cleanup_fixture_inner(label, false, false)
    }

    fn active_unadmitted_final_verifier_cleanup_fixture(
        label: &str,
    ) -> RestartUnadmittedFinalVerifierCleanupFixture {
        restart_unadmitted_final_verifier_cleanup_fixture_inner(label, true, true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the restart fixture keeps TaskDone, worker cleanup, native final-verifier launch, and optional session registration contiguous"
    )]
    fn restart_unadmitted_final_verifier_cleanup_fixture_inner(
        label: &str,
        register_session: bool,
        retain_active: bool,
    ) -> RestartUnadmittedFinalVerifierCleanupFixture {
        assert!(
            register_session || !retain_active,
            "a sessionless launch cannot retain an active client"
        );
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
        .expect("construct TaskDone cleanup owner for unadmitted final verifier");
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
            .expect("complete worker cleanup before unadmitted final-verifier launch"),
            crate::WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(_)
        ));
        assert_eq!(worker_reopen_count.get(), 1);
        assert_eq!(worker_cleanup_count.get(), 1);

        let TaskAttemptDisposition::Integrated(task_integrated) = &integrated.disposition else {
            unreachable!("unadmitted final-verifier fixture starts from Integrated")
        };
        let final_snapshot = task_integrated.integration_receipt.result_snapshot.clone();
        let final_policy = read_only_policy(&integrated.harness, &format!("{label}-policy"));
        let prepare_count = Rc::new(Cell::new(0));
        let release_count = Rc::new(Cell::new(0));
        let native_cleanup_count = Rc::new(Cell::new(0));
        let service = AdversarialNativeLaunchService::new(
            RunnerLaunchPreparationDisposition::HeldChildPrepared,
            NativeReleaseMutation::Exact,
            transport(
                unique_nonce(&format!("{label}-final-verifier")),
                integrated.harness.identity(),
                if register_session {
                    ScriptMode::Good
                } else {
                    ScriptMode::BadReceipt
                },
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
        let retained_request = request.clone();
        let launched = RunnerLifecycleClient::launch_with_native_service(
            &mut integrated.ledger,
            &integrated.harness.authority,
            &final_policy,
            request,
            Box::new(service),
        );
        assert_eq!(prepare_count.get(), 1);
        assert_eq!(release_count.get(), 1);
        let (cleanup_admission, cleanup_authority, cleanup_at_unix_ms, active) =
            match (register_session, launched) {
                (true, Ok(client)) => {
                    let cleanup_admission = client
                        .launch_cleanup_admission()
                        .expect("unadmitted final verifier retains atomic cleanup admission")
                        .clone();
                    let preparation = integrated
                        .ledger
                        .load_runner_launch_preparation(
                            &cleanup_admission.launch.sprint_id,
                            &cleanup_admission.launch.launch_id,
                        )
                        .expect("reload unadmitted final-verifier native preparation");
                    let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
                        &cleanup_admission,
                        Some(&preparation),
                        client
                            .platform_launch_binding
                            .as_deref()
                            .expect("unadmitted final verifier retains platform binding"),
                    );
                    let cleanup_at_unix_ms =
                        client.session().registered_at_unix_ms.saturating_add(1);
                    let active = if retain_active {
                        Some((retained_request, client))
                    } else {
                        drop(client);
                        None
                    };
                    (
                        cleanup_admission,
                        cleanup_authority,
                        cleanup_at_unix_ms,
                        active,
                    )
                }
                (false, Err(failure)) => {
                    let cleanup = failure
                        .into_cleanup_required()
                        .expect("failed initialization retains final-verifier cleanup custody");
                    assert!(matches!(
                        cleanup.session_registration(),
                        RunnerSessionRegistrationState::NotRegistered
                    ));
                    let cleanup_admission = cleanup
                        .launch_cleanup_admission()
                        .expect("sessionless final verifier retains atomic cleanup admission")
                        .clone();
                    let cleanup_authority = cleanup
                        .native_cleanup_custody
                        .as_ref()
                        .expect("sessionless final verifier retains native cleanup custody")
                        .authority()
                        .clone();
                    let preparation = integrated
                        .ledger
                        .load_runner_launch_preparation(
                            &cleanup_admission.launch.sprint_id,
                            &cleanup_admission.launch.launch_id,
                        )
                        .expect("reload sessionless final-verifier preparation");
                    let preparation_finished_at = preparation
                        .outcome
                        .as_ref()
                        .map_or(preparation.attempt.claimed_at_unix_ms, |outcome| {
                            outcome.finished_at_unix_ms
                        });
                    let cleanup_at_unix_ms = cleanup_admission
                        .cleanup_effect
                        .intent
                        .created_at_unix_ms
                        .max(preparation_finished_at)
                        .saturating_add(1);
                    drop(cleanup);
                    (
                        cleanup_admission,
                        cleanup_authority,
                        cleanup_at_unix_ms,
                        None,
                    )
                }
                (true, Err(failure)) => {
                    panic!(
                        "exact initialized final verifier failed: {}",
                        failure.error()
                    )
                }
                (false, Ok(_)) => {
                    panic!("bad initialization receipt unexpectedly registered a session")
                }
            };
        RestartUnadmittedFinalVerifierCleanupFixture {
            harness: integrated.harness,
            ledger: integrated.ledger,
            final_snapshot,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
            native_cleanup_count,
            active,
        }
    }

    #[test]
    fn lifecycle_owner_unadmitted_final_verifier_restart_reopens_once_and_closes_launch() {
        let label = "lifecycle-owner-unadmitted-final-verifier-restart";
        let RestartUnadmittedFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            final_snapshot,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
            native_cleanup_count: _,
            active: _,
        } = restart_unadmitted_final_verifier_cleanup_fixture(label);
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
        .expect("construct restarted unadmitted final-verifier owner");

        let completed = match crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_final_verifier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_snapshot: &final_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("close unadmitted final-verifier launch after restart")
        {
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(completed) => completed,
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired { reason } => {
                panic!("exact unadmitted final-verifier cleanup remained pending: {reason}")
            }
        };
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(claims.borrow().len(), 1);
        assert_eq!(completed.intent, cleanup_admission.cleanup_effect.intent);
        assert!(matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        let PersistedFinishReceipt::WorkerCleanup(evidence) = &completed.finish_receipt else {
            panic!("unadmitted final-verifier cleanup must persist WorkerCleanup evidence")
        };
        assert_eq!(evidence.receipt.surviving_processes, 0);
        assert_eq!(
            evidence.receipt.platform_backend,
            cleanup_admission.cleanup_request.platform_backend
        );
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload unadmitted final-verifier cleanup terminal"),
            completed
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_same_process_active_unadmitted_final_verifier_closes_once() {
        let label = "lifecycle-owner-active-unadmitted-final-verifier";
        let RestartUnadmittedFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            final_snapshot,
            cleanup_admission,
            cleanup_authority: _,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
            native_cleanup_count,
            active,
        } = active_unadmitted_final_verifier_cleanup_fixture(label);
        let (launch_request, client) = active.expect("fixture retains the exact live verifier");
        let mut owner = DesktopRunnerLifecycleOwner::from_active_final_verifier_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            launch_request,
            client,
            final_snapshot.clone(),
        )
        .expect("construct exact active final-verifier owner");
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::ActiveFinalVerifier { ref binding }
                if binding.sprint_id == harness.sprint_spec.sprint_id
                    && binding.launch_id == cleanup_admission.launch.launch_id
                    && binding.session_id == cleanup_admission.launch.session_id
                    && binding.final_snapshot == &final_snapshot
        ));
        assert_eq!(native_cleanup_count.get(), 0);

        let completed = match crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_final_verifier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_snapshot: &final_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("active final verifier closes through the atomic no-phase exclusion")
        {
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(completed) => completed,
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired { reason } => {
                panic!("active final-verifier cleanup remained pending: {reason}")
            }
        };
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(native_cleanup_count.get(), 1);
        assert_eq!(completed.intent, cleanup_admission.cleanup_effect.intent);
        assert!(matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        let PersistedFinishReceipt::WorkerCleanup(evidence) = &completed.finish_receipt else {
            panic!("active final-verifier cleanup must persist WorkerCleanup evidence")
        };
        assert_eq!(evidence.receipt.surviving_processes, 0);
        assert_eq!(
            evidence.receipt.platform_backend,
            cleanup_admission.cleanup_request.platform_backend
        );
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload same-process final-verifier cleanup terminal"),
            completed
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_exact_retained_unadmitted_final_verifier_cleanup_closes_once() {
        let label = "lifecycle-owner-retained-unadmitted-final-verifier";
        let RestartUnadmittedFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            final_snapshot,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
            native_cleanup_count,
            active: _,
        } = restart_unadmitted_final_verifier_cleanup_fixture(label);
        let session = ledger
            .load_runner_session(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.session_id,
            )
            .expect("reload exact retained final-verifier session");
        let retained = admitted_cleanup_without_native_custody(
            cleanup_admission.clone(),
            session,
            cleanup_authority.platform_binding().clone(),
        );
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let mut owner = DesktopRunnerLifecycleOwner::from_custody_free_final_verifier_cleanup_with_reopener_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            retained,
            final_snapshot.clone(),
            Box::new(ScriptedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                mutation: ScriptedNativeCleanupMutation::Exact,
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct exact retained final-verifier cleanup owner");
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::FinalVerifierCleanupRequired { cleanup, .. }
                if !cleanup.has_native_cleanup_custody()
        ));

        let completed = match crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_final_verifier_launch(
            &mut owner,
            &mut ledger,
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanup {
                sprint_spec: &harness.sprint_spec,
                launch_id: &cleanup_admission.launch.launch_id,
                final_snapshot: &final_snapshot,
                cleanup_at_unix_ms,
            },
        )
        .expect("exact retained final-verifier custody closes through the no-phase exclusion")
        {
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(completed) => completed,
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired { reason } => {
                panic!("exact retained final-verifier cleanup remained pending: {reason}")
            }
        };
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(native_cleanup_count.get(), 0);
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert_eq!(claims.borrow().len(), 1);
        assert_eq!(completed.intent, cleanup_admission.cleanup_effect.intent);
        assert!(matches!(
            completed
                .observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        let PersistedFinishReceipt::WorkerCleanup(evidence) = &completed.finish_receipt else {
            panic!("retained final-verifier cleanup must persist WorkerCleanup evidence")
        };
        assert_eq!(evidence.receipt.surviving_processes, 0);
        assert_eq!(
            evidence.receipt.platform_backend,
            cleanup_admission.cleanup_request.platform_backend
        );
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("reload retained final-verifier cleanup terminal"),
            completed
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_sessionless_unadmitted_final_verifier_restart_closes_without_fabricating_session()
     {
        let label = "lifecycle-owner-sessionless-unadmitted-final-verifier";
        let RestartUnadmittedFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            final_snapshot,
            cleanup_admission,
            cleanup_authority,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
            native_cleanup_count: _,
            active: _,
        } = restart_sessionless_unadmitted_final_verifier_cleanup_fixture(label);
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
        .expect("construct sessionless cleanup-only restart owner");
        let outcome =
            crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_final_verifier_launch(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonUnadmittedFinalVerifierCleanup {
                    sprint_spec: &harness.sprint_spec,
                    launch_id: &cleanup_admission.launch.launch_id,
                    final_snapshot: &final_snapshot,
                    cleanup_at_unix_ms,
                },
            )
            .expect("close sessionless unadmitted final-verifier launch");
        if let crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired {
            reason,
        } = outcome
        {
            panic!("sessionless unadmitted final-verifier cleanup remained pending: {reason}");
        }
        assert_eq!((reopen_count.get(), cleanup_count.get()), (1, 1));
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
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
    fn lifecycle_owner_unadmitted_final_verifier_restart_without_reopener_writes_nothing() {
        let label = "lifecycle-owner-unadmitted-final-verifier-missing-reopener";
        let RestartUnadmittedFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            final_snapshot,
            cleanup_admission,
            cleanup_authority: _,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
            native_cleanup_count: _,
            active: _,
        } = restart_unadmitted_final_verifier_cleanup_fixture(label);
        let pending = ledger
            .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending unadmitted final-verifier cleanup");
        let mut owner = DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
            runner_binary: harness.runner_binary.clone(),
            private_state_root: harness.private_state.clone(),
        })
        .expect("construct restarted owner without cleanup reopener");
        let outcome =
            crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_final_verifier_launch(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonUnadmittedFinalVerifierCleanup {
                    sprint_spec: &harness.sprint_spec,
                    launch_id: &cleanup_admission.launch.launch_id,
                    final_snapshot: &final_snapshot,
                    cleanup_at_unix_ms,
                },
            )
            .expect("missing reopener is a typed cleanup-required stop");
        assert!(matches!(
            outcome,
            crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired { ref reason }
                if reason.contains("reopener")
        ));
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
        assert_eq!(
            ledger
                .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                .expect("missing reopener cannot close cleanup effect"),
            pending
        );
        assert!(matches!(
            owner.state(),
            DesktopRunnerLifecycleStateView::Idle
        ));
    }

    #[test]
    fn lifecycle_owner_unadmitted_final_verifier_crossed_reopener_retains_custody_once() {
        let label = "lifecycle-owner-unadmitted-final-verifier-crossed-reopener";
        let RestartUnadmittedFinalVerifierCleanupFixture {
            harness,
            mut ledger,
            final_snapshot,
            cleanup_admission,
            mut cleanup_authority,
            cleanup_at_unix_ms,
            prepare_count,
            release_count,
            native_cleanup_count: _,
            active: _,
        } = restart_unadmitted_final_verifier_cleanup_fixture(label);
        let session = ledger
            .load_runner_session(
                &cleanup_admission.launch.sprint_id,
                &cleanup_admission.launch.session_id,
            )
            .expect("reload unadmitted final-verifier session");
        let retained = admitted_cleanup_without_native_custody(
            cleanup_admission.clone(),
            session,
            cleanup_authority.platform_binding().clone(),
        );
        cleanup_authority.expected_platform_binding_digest =
            Digest::sha256(b"crossed-unadmitted-final-verifier-cleanup-authority");
        let pending = ledger
            .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
            .expect("load pending crossed unadmitted final-verifier cleanup");
        let reopen_count = Rc::new(Cell::new(0));
        let cleanup_count = Rc::new(Cell::new(0));
        let claims = Rc::new(RefCell::new(Vec::new()));
        let mut owner = DesktopRunnerLifecycleOwner::from_custody_free_final_verifier_cleanup_with_reopener_for_test(
            RunnerLifecycleOwnerConfig {
                runner_binary: harness.runner_binary.clone(),
                private_state_root: harness.private_state.clone(),
            },
            retained,
            final_snapshot.clone(),
            Box::new(UncheckedNativeCleanupReopener {
                authority: cleanup_authority,
                reopen_count: Rc::clone(&reopen_count),
                cleanup_count: Rc::clone(&cleanup_count),
                claims: Rc::clone(&claims),
            }),
        )
        .expect("construct crossed unadmitted final-verifier cleanup owner");

        for requested_at_unix_ms in [cleanup_at_unix_ms, cleanup_at_unix_ms.saturating_add(1)] {
            let outcome = crate::WalkingSkeletonRunnerLifecycle::cleanup_unadmitted_sprint_final_verifier_launch(
                &mut owner,
                &mut ledger,
                crate::WalkingSkeletonUnadmittedFinalVerifierCleanup {
                    sprint_spec: &harness.sprint_spec,
                    launch_id: &cleanup_admission.launch.launch_id,
                    final_snapshot: &final_snapshot,
                    cleanup_at_unix_ms: requested_at_unix_ms,
                },
            )
            .expect("crossed reopened custody remains cleanup-required");
            assert!(matches!(
                outcome,
                crate::WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::CleanupRequired { .. }
            ));
            assert_eq!(reopen_count.get(), 1);
            assert_eq!(cleanup_count.get(), 0);
            assert_eq!(claims.borrow().len(), 1);
            assert_eq!(
                ledger
                    .load_effect(&cleanup_admission.cleanup_effect.intent.effect_id)
                    .expect("crossed custody leaves cleanup pending"),
                pending
            );
            assert!(matches!(
                owner.state(),
                DesktopRunnerLifecycleStateView::FinalVerifierCleanupRequired { cleanup, .. }
                    if cleanup.has_native_cleanup_custody()
            ));
        }
        assert_eq!((prepare_count.get(), release_count.get()), (1, 1));
    }

    struct UnadmittedApplicationOwnerFixture {
        harness: TestHarness,
        ledger: EventLedger,
        policy: CompiledExecutionPolicy,
        final_verification_receipt_id: String,
        final_verification_terminal: AgentEvent,
        request: ApplicationRequest,
        stage_bundle: StageBundleReference,
        artifact_assembly_id: String,
        cleanup_admission: PersistedRunnerLaunchCleanupAdmission,
        cleanup_authority: NativeLaunchCleanupAuthority,
        cleanup_session: RunnerSessionPolicyRecord,
        cleanup_at_unix_ms: u64,
        active: Option<(RunnerClientLaunch, RunnerLifecycleClient)>,
        crossed_launch_id: Option<String>,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
        native_cleanup_count: Rc<Cell<u64>>,
        exchange_count: Rc<Cell<u64>>,
    }

    #[derive(Clone, Copy)]
    enum ApplicationEffectScript {
        Unused,
        Success,
        AdaptationRejected,
        NoRequestBytesWritten,
    }

    fn restart_unadmitted_application_fixture(
        label: &str,
        register_session: bool,
    ) -> UnadmittedApplicationOwnerFixture {
        unadmitted_application_owner_fixture_inner(
            label,
            register_session,
            false,
            ScriptedNativeCleanupMutation::Exact,
            ApplicationEffectScript::Unused,
        )
    }

    fn active_unadmitted_application_fixture(
        label: &str,
        mutation: ScriptedNativeCleanupMutation,
    ) -> UnadmittedApplicationOwnerFixture {
        unadmitted_application_owner_fixture_inner(
            label,
            true,
            true,
            mutation,
            ApplicationEffectScript::Unused,
        )
    }

    fn active_admitted_application_fixture(
        label: &str,
        mutation: ScriptedNativeCleanupMutation,
        effect_script: ApplicationEffectScript,
    ) -> UnadmittedApplicationOwnerFixture {
        unadmitted_application_owner_fixture_inner(label, true, true, mutation, effect_script)
    }

    fn scripted_application_success_response(
        harness: &TestHarness,
        policy: &CompiledExecutionPolicy,
        session: &RunnerSessionPolicyRecord,
        request: &ApplicationRequest,
        stage_bundle: &StageBundleReference,
        label: &str,
    ) -> RunnerResponse {
        let fixture = post_completion_dispatch_fixture(harness, policy, session, label);
        assert_eq!(fixture.change_set, request.change_set);
        assert_eq!(&fixture.bundle, stage_bundle);
        RunnerResponse::ApplicationApplied {
            evidence: WireApplicationEvidence {
                bundle: stage_bundle.clone(),
                change_set_id: request.change_set.change_set_id.clone(),
                base_snapshot: request.change_set.base_snapshot.clone(),
                result_snapshot: request.change_set.result_snapshot.clone(),
                transaction_id: fixture.application.receipt.transaction_id,
                live_manifest_digest: fixture.application.receipt.live_manifest_digest,
                applied_operations_digest: request
                    .change_set
                    .applied_operations_digest()
                    .expect("digest scripted application operations"),
                touched_path_endpoints_digest: request
                    .change_set
                    .touched_path_endpoints_digest()
                    .expect("digest scripted application endpoints"),
                touched_target_set_digest: request
                    .change_set
                    .touched_target_set_digest()
                    .expect("digest scripted application targets"),
                rollback: fixture.rollback,
            },
        }
    }
