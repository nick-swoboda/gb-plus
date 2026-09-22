    fn launch_live_state_completion_role_with_registration(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        policy: &CompiledExecutionPolicy,
        plan: &SprintLiveStateCapturePlan,
        suffix: &str,
        register_session: bool,
    ) -> CompletionRoleAdmission {
        let mut request = harness.launch(suffix);
        request.role = RunnerRole::LiveStateVerifier;
        request.worker_id = None;
        request.worker_lease = None;
        request.shadow_root = None;
        request.expected_base_snapshot = plan.expected_snapshot.clone();
        request.created_at_unix_ms = plan.planned_at_unix_ms.saturating_add(1);
        let role_input_authority = RunnerRoleInputAuthority::LiveStateFinalization {
            plan: Box::new(plan.clone()),
            plan_digest: plan.plan_digest().expect("digest live-state capture plan"),
        };
        let prepared =
            prepare_launch_with_context(&harness.authority, policy, &request, role_input_authority)
                .expect("prepare exact live-state verifier launch");
        let launch = prepared.intent.clone();
        drop(prepared);
        let cleanup = prepare_ordinary_launch_cleanup(ledger, &launch, &plan.expected_snapshot)
            .expect("prepare live-state verifier cleanup contract");
        let admitted = ledger
            .admit_live_state_verifier_launch_with_cleanup(
                plan,
                &launch,
                policy,
                &cleanup.intent,
                &cleanup.request_bytes,
                &cleanup.event,
            )
            .expect("atomically admit live-state verifier and cleanup");
        let session = RunnerSessionPolicyRecord {
            contract_version: CONTRACT_VERSION,
            sprint_id: launch.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: launch.session_id.clone(),
            purpose: launch.purpose,
            worker_id: None,
            worker_lease: None,
            policy_hash: launch.policy_hash.clone(),
            session_nonce: unique_nonce(&format!("{suffix}-session")),
            runner_binary_digest: launch.runner_binary_digest.clone(),
            protocol_digest: launch.protocol_digest.clone(),
            private_state_digest: launch.private_state_digest.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            registered_at_unix_ms: launch.created_at_unix_ms.saturating_add(1),
        };
        if register_session {
            ledger
                .register_live_state_verifier_session(plan, &session, policy)
                .expect("register exact live-state verifier session");
        }
        CompletionRoleAdmission {
            launch: admitted.launch,
            cleanup_request: admitted.cleanup_request,
            cleanup_intent: admitted.cleanup_effect.intent,
            cleanup_proposed_event_id: admitted.cleanup_effect.proposed_event.event_id,
            session,
            task_attempt_running: None,
        }
    }

    fn persist_one_to_one_human_acceptance(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
        criterion_id: &str,
        snapshot: &Digest,
        suffix: &str,
        awaiting_at_unix_ms: u64,
        decided_at_unix_ms: u64,
    ) -> (AgentEvent, CriterionEvidenceReceiptV2) {
        assert!(
            decided_at_unix_ms >= awaiting_at_unix_ms,
            "human decision must not predate its rendered prompt"
        );
        let awaiting_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&launch.sprint_id)
                .expect("next one-to-one human-acceptance phase sequence"),
            event_id: format!("sprint-awaiting-acceptance-{suffix}"),
            sprint_id: launch.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: format!("correlation-human-acceptance-{suffix}"),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: awaiting_at_unix_ms,
            payload: AgentEventKind::SprintStateChanged {
                from: "Running".into(),
                to: "AwaitingAcceptance".into(),
            },
        };
        ledger
            .append_event(&awaiting_event)
            .expect("enter AwaitingAcceptance before minting one human prompt");

        let prompt_id = format!("human-acceptance-prompt-{suffix}");
        let ui_session_id = format!("human-acceptance-ui-session-{suffix}");
        let rendered_claim_digest = Digest::sha256(
            format!(
                "criterion-id={criterion_id}\nsnapshot={snapshot}\nbacking=1:1\nclaim=accepted-by-you\n"
            )
            .as_bytes(),
        );
        let prompt = ledger
            .issue_human_acceptance_prompt_v1(
                &prompt_id,
                &ui_session_id,
                &launch.sprint_id,
                criterion_id,
                rendered_claim_digest,
            )
            .expect("mint one exact one-to-one human-acceptance prompt");
        assert_eq!(prompt.snapshot_digest, *snapshot);
        let consumption = ledger
            .consume_human_acceptance_prompt_v1(
                &prompt.prompt_id,
                &prompt.ui_session_id,
                &format!("criterion-evidence-accepted-by-you-{suffix}"),
                HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                decided_at_unix_ms,
            )
            .expect("atomically consume one exact human-acceptance prompt");
        assert_eq!(
            consumption.decision.outcome,
            HumanAcceptanceDecisionOutcomeV1::AcceptedByYou
        );
        let evidence = consumption
            .criterion_evidence
            .expect("accepted-by-you decision creates typed criterion evidence");
        assert_eq!(evidence.sprint_id(), launch.sprint_id);
        assert_eq!(evidence.criterion_id(), criterion_id);
        assert_eq!(evidence.snapshot_digest(), snapshot);
        (awaiting_event, evidence)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the fixture keeps phase, runner, snapshot, and time authority explicit"
    )]
    fn persist_claimed_final_verification_evidence_v12(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
        session: &RunnerSessionPolicyRecord,
        policy: &CompiledExecutionPolicy,
        authority: &IssuedWorkspaceGrant,
        private_state_root: &Path,
        command_backend: CommandDomainBackend,
        command_cleanup_proof_id: &str,
        receipt_id: &str,
        suffix: &str,
        snapshot: &Digest,
        admitted_at_unix_ms: u64,
        finished_at_unix_ms: u64,
    ) -> (VerificationReceipt, AgentEvent, CriterionEvidenceReceiptV2) {
        let stdout = format!("passing output for {receipt_id}").into_bytes();
        let command = CommandSpec {
            program: "true".into(),
            arguments: Vec::new(),
            working_directory: PathBuf::new(),
        };
        let command_bytes =
            serde_json::to_vec(&command).expect("encode claimed final-verification command");
        let (awaiting_event, criterion_evidence) = persist_one_to_one_human_acceptance(
            ledger,
            launch,
            "criterion-1",
            snapshot,
            suffix,
            admitted_at_unix_ms.saturating_sub(1),
            admitted_at_unix_ms,
        );
        let phase_sequence = ledger
            .next_sequence(&launch.sprint_id)
            .expect("next claimed final-verification phase sequence");
        let phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: phase_sequence,
            event_id: format!("sprint-final-verification-{suffix}"),
            sprint_id: launch.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(awaiting_event.event_id),
            correlation_id: format!("correlation-final-verification-{suffix}"),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: admitted_at_unix_ms,
            payload: AgentEventKind::SprintStateChanged {
                from: "AwaitingAcceptance".into(),
                to: "FinalVerification".into(),
            },
        };
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("effect-{receipt_id}"),
            idempotency_key: format!("key-{receipt_id}"),
            sprint_id: launch.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(phase_event.event_id.clone()),
            correlation_id: phase_event.correlation_id.clone(),
            kind: EffectKind::RunCommand,
            request_digest: Digest::sha256(&command_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot: snapshot.clone(),
            created_at_unix_ms: admitted_at_unix_ms,
        };
        let proposed = proposal(&intent, phase_sequence + 1);
        let admission = SprintFinalVerificationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("final-verification-admission-{suffix}"),
            sprint_id: launch.sprint_id.clone(),
            sprint_phase_event_id: phase_event.event_id.clone(),
            final_snapshot: snapshot.clone(),
            effect_id: intent.effect_id.clone(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            command: command.clone(),
            admitted_at_unix_ms,
        };
        let capture_intent = fresh_command_output_capture_intent(&intent, launch, session, policy)
            .expect("construct exact final-verification output-capture intent");
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_final_verification_with_output_capture_for_dispatch(
                &admission,
                &phase_event,
                &intent,
                &proposed,
                &capture_intent,
            )
            .expect("atomically admit claimed final verification")
        else {
            panic!("new claimed final-verification fixture must mint one fresh permit")
        };
        let dispatch_permit = FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit);
        let detector_policy = dispatch_permit
            .sensitive_output_detection_policy()
            .cloned()
            .expect("final-verification permit carries exact detector policy");
        let dispatch_claim_id = dispatch_permit
            .expected_output_capture_dispatch_claim_id()
            .expect("fresh final verification carries its capture claim identity");
        let store = CapabilityCommandOutputStore::open(private_state_root)
            .expect("open exact final-verification private output store");
        let acquired = store
            .reserve_anchored_capture_v2(
                &capture_intent,
                &dispatch_claim_id,
                admitted_at_unix_ms,
                &detector_policy,
            )
            .expect("reserve exact v12 final-verification capture")
            .into_acquired_anchor_for_handoff()
            .expect("synchronize exact v12 final-verification acquisition");
        let output_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
            .expect("construct exact v12 final-verification capture anchor");
        let mut request = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: session.session_id.clone(),
            runner_nonce: session.session_nonce.clone(),
            sequence: 1,
            request_id: format!("final-verification-v12-request-{suffix}"),
            effect: WireEffectContext {
                contract_version: intent.contract_version,
                launch_id: launch.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                idempotency_key: intent.idempotency_key.clone(),
                sprint_id: intent.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: None,
                policy_hash: intent.policy_hash.clone(),
                input_snapshot: intent.input_snapshot.clone(),
                request_digest: intent.request_digest.clone(),
                transport_commitment_digest: Digest::sha256(&[]),
            },
            request: RunnerRequestV12::RunCommand {
                request: RunnerRequest::FinalVerifierRunCommand {
                    command: WireCommandSpec {
                        program: command.program.clone(),
                        arguments: command.arguments.clone(),
                        working_directory: String::new(),
                    },
                    output_capture,
                },
                detector_policy: detector_policy.clone(),
            },
        };
        request
            .bind_transport_commitment_digest()
            .expect("bind exact v12 final-verification request");
        let request_frame = encode_request_frame_v12(&request)
            .expect("encode exact v12 final-verification request");
        let (_, transport) = ledger
            .claim_command_output_capture_dispatch(
                dispatch_permit,
                acquired.clone(),
                &request_frame,
            )
            .expect("claim exact v12 final-verification runner dispatch");
        assert_eq!(
            transport.sensitive_output_detection_policy(),
            Some(&detector_policy)
        );
        let observation_authority = transport
            .validate_transport_request(
                &intent,
                &command_bytes,
                launch,
                session,
                None,
                &request_frame,
            )
            .expect("validate exact v12 final-verification transport request");
        let runner_backend = match command_backend {
            CommandDomainBackend::LinuxCgroupV2 => RunnerCommandDomainCleanupBackend::LinuxCgroupV2,
            CommandDomainBackend::MacOsDedicatedIdentity => {
                RunnerCommandDomainCleanupBackend::MacOsDedicatedIdentity
            }
        };
        let backend = WireCommandBackendIdentity {
            command_domain_backend: runner_backend,
            backend_id: format!("final-verification-v12-backend-{suffix}"),
            implementation_digest: Digest::sha256(
                format!("final-verification-v12-backend-{suffix}").as_bytes(),
            ),
        };
        let proof_box = complete_sensitive_output_clean_test_proof_box_v1(
            ClaimedCommandOutputV2TestProofBoxInput {
                private_state_root: private_state_root.to_path_buf(),
                grant_hash: authority.contract().grant_hash.clone(),
                acquired,
                request,
                termination: CommandTerminationV1::Exited { code: 0 },
                backend,
            },
            &stdout,
            &[],
        )
        .expect("complete runner-owned clean v12 final-verification proof box");
        let observed_at_unix_ms =
            finished_at_unix_ms.max(proof_box.receipt().terminal_prepared_at_unix_ms);
        let terminal_anchored_at_unix_ms = observed_at_unix_ms.saturating_add(1);
        let exchange = RunnerCommandEffectResponse {
            request: proof_box.request().clone(),
            response: proof_box.response().clone(),
        };
        let observation_id = format!("observation-{receipt_id}");
        let adapted = crate::adapt_verification_response_v12(
            crate::CommandV12ResponseInput {
                exchange: &exchange,
                intent: &intent,
                runner_session: session,
                private_state_root,
                authority,
                command: &command,
                capture_intent: &capture_intent,
                core_request_bytes: &command_bytes,
                task_id: None,
                observation_id: &observation_id,
                observed_at_unix_ms,
            },
            receipt_id,
        )
        .expect("adapt exact clean v12 final verification");
        let crate::AdaptedVerificationResponseV12::Completed(adapted) = adapted else {
            panic!("clean v12 proof box must return completed verification evidence")
        };
        let receipt = adapted.evidence.verification.clone();
        let evidence = adapted.evidence.clone();
        let observed = observation(
            &intent,
            observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: adapted.canonical_evidence.digest.clone(),
            },
            observed_at_unix_ms,
        );
        let closure = adapted.command_terminal();
        let wire_capture = closure.output_capture();
        let output_capture_terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture_intent,
            Some(proof_box.acquired()),
            &observed,
            CommandOutputCaptureTerminalDispositionV1::Published,
            wire_capture.terminal_prepared_store_head.clone(),
            wire_capture.terminal_record_digest.clone(),
            Some(wire_capture.expected_output_artifacts.clone()),
            terminal_anchored_at_unix_ms,
        )
        .expect("construct exact v12 final-verification core capture terminal");
        let clean_scan = CommandOutputCleanScanPublicationReceiptV1::try_new_from_runner_reference(
            &capture_intent,
            closure
                .clean_runner()
                .expect("clean v12 closure carries exact runner receipt"),
            &output_capture_terminal,
        )
        .expect("construct exact v12 clean-scan publication receipt");
        let native_cleanup = proof_box.native_cleanup_proof();
        let command_cleanup = CommandDomainCleanupProof {
            contract_version: CONTRACT_VERSION,
            proof_id: command_cleanup_proof_id.into(),
            sprint_id: launch.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: session.session_id.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: Some(observed.observation_id.clone()),
            request_digest: intent.request_digest.clone(),
            backend: command_backend,
            disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            surviving_processes: 0,
            platform_proof_digest: native_cleanup.os_evidence_digest().clone(),
            platform_proof_bytes: native_cleanup.os_evidence_bytes().to_vec(),
            cleaned_at_unix_ms: terminal_anchored_at_unix_ms,
        };
        let terminal = terminal_event(ledger, &intent, &proposed.event_id, &observed);
        ledger
            .complete_claimed_sprint_final_verification_with_output_capture(
                observation_authority,
                &observed,
                &terminal,
                &evidence,
                &output_capture_terminal,
                &clean_scan,
                &command_cleanup,
            )
            .expect("persist exact claimed v12 final-verification evidence");
        assert_eq!(
            observed.outcome.evidence_digest(),
            &adapted.canonical_evidence.digest
        );
        (receipt, terminal, criterion_evidence)
    }

    fn persist_cleanup_evidence(
        ledger: &mut EventLedger,
        admission: &CompletionRoleAdmission,
        session: &RunnerSessionPolicyRecord,
        integrated_disposition_id: Option<&str>,
        receipt_id: &str,
        cleaned_at_unix_ms: u64,
    ) {
        let launch = &admission.launch;
        let intent = &admission.cleanup_intent;
        let backend = admission.cleanup_request.platform_backend;
        let os_evidence_bytes = format!("zero survivors for {}", launch.launch_id).into_bytes();
        let evidence = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: receipt_id.into(),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                observation_id: format!("observation-{receipt_id}"),
                session_id: session.session_id.clone(),
                worker_lease: launch.worker_lease.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: backend,
                os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms,
            },
            os_evidence_bytes,
        };
        let evidence_bytes = serde_json::to_vec(&evidence).expect("encode cleanup evidence");
        let observed = observation(
            intent,
            evidence.receipt.observation_id.clone(),
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            cleaned_at_unix_ms,
        );
        let terminal = |next_event_sequence| RunnerCleanupTerminalRecord {
            observation: observed.clone(),
            event: terminal_event_at_sequence(
                next_event_sequence,
                intent,
                &admission.cleanup_proposed_event_id,
                &observed,
            ),
            evidence: evidence.clone(),
        };
        if launch.worker_lease.is_some() {
            let disposition_id = integrated_disposition_id
                .expect("managed task cleanup requires exact Integrated disposition");
            ledger
                .with_integrated_task_attempt_cleanup_exclusion(disposition_id, |claim| {
                    assert_eq!(claim.admission().launch, *launch);
                    assert_eq!(claim.admission().cleanup_request, admission.cleanup_request);
                    assert_eq!(claim.admission().cleanup_effect.intent, *intent);
                    assert_eq!(
                        claim.admission().cleanup_effect.proposed_event.event_id,
                        admission.cleanup_proposed_event_id
                    );
                    Ok(terminal(claim.next_event_sequence()))
                })
                .expect("persist managed task cleanup and release atomically");
        } else {
            assert!(
                integrated_disposition_id.is_none(),
                "non-attempt cleanup cannot carry an Integrated disposition"
            );
            ledger
                .with_runner_launch_cleanup_exclusion(
                    &launch.sprint_id,
                    &launch.launch_id,
                    |claim| {
                        assert_eq!(claim.admission().launch, *launch);
                        assert_eq!(claim.admission().cleanup_request, admission.cleanup_request);
                        assert_eq!(claim.admission().cleanup_effect.intent, *intent);
                        assert_eq!(
                            claim.admission().cleanup_effect.proposed_event.event_id,
                            admission.cleanup_proposed_event_id
                        );
                        Ok(terminal(claim.next_event_sequence()))
                    },
                )
                .expect("persist cleanup evidence through the live exclusion");
        }
    }

    fn persist_command_domain_cleanup_evidence(
        ledger: &mut EventLedger,
        admission: &CompletionRoleAdmission,
        session: &RunnerSessionPolicyRecord,
        effect_id: &str,
        proof_id: &str,
        cleaned_at_unix_ms: u64,
    ) {
        let binding = ledger
            .load_command_domain_effect_bindings(
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
                &session.session_id,
            )
            .expect("load exact command-domain binding")
            .into_iter()
            .find(|binding| binding.effect_id == effect_id)
            .expect("find exact command-domain effect");
        let backend = match admission.cleanup_request.platform_backend {
            WorkerCleanupBackend::MacOsDedicatedIdentity => {
                CommandDomainBackend::MacOsDedicatedIdentity
            }
            WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
            WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                panic!("ordinary command role requires a native command-domain backend")
            }
        };
        let platform_proof_bytes =
            format!("validated native cleanup proof for {proof_id}").into_bytes();
        ledger
            .record_command_domain_cleanup_proof(&CommandDomainCleanupProof {
                contract_version: CONTRACT_VERSION,
                proof_id: proof_id.into(),
                sprint_id: binding.sprint_id,
                launch_id: binding.launch_id,
                session_id: binding.session_id,
                effect_id: binding.effect_id,
                observation_id: binding.observation_id,
                request_digest: binding.request_digest,
                backend,
                disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
                surviving_processes: 0,
                platform_proof_digest: Digest::sha256(&platform_proof_bytes),
                platform_proof_bytes,
                cleaned_at_unix_ms,
            })
            .expect("persist exact command-domain cleanup proof");
    }

    struct PostCompletionDispatchFixture {
        operation: PostCompletionRollbackIntent,
        application: ApplicationEvidence,
        rollback_reference: RollbackReferenceEvidence,
        change_set: ChangeSet,
        bundle: StageBundleReference,
        rollback: WireRollbackArtifactReference,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AuthoritativePostCompletionFixtureMode {
        Complete,
        StopBeforeLiveStateLaunch,
        StopAfterLiveStateClaim,
        StopBeforeApplicationAdmission { register_session: bool },
    }

    struct UnlaunchedLiveStatePreparation {
        policy: CompiledExecutionPolicy,
        plan: SprintLiveStateCapturePlan,
    }

    struct ClaimedLiveStateRestartPreparation {
        policy: CompiledExecutionPolicy,
        plan: SprintLiveStateCapturePlan,
        verifier: CompletionRoleAdmission,
        admission: SprintLiveStateCaptureAdmission,
        intent: EffectIntent,
        proposed_event: AgentEvent,
        claimed: PersistedEffect,
    }

    struct UnadmittedApplicationPreparation {
        policy: CompiledExecutionPolicy,
        final_verification_receipt_id: String,
        final_verification_terminal: AgentEvent,
        application: CompletionRoleAdmission,
        request: ApplicationRequest,
        stage_bundle: StageBundleReference,
        artifact_assembly_id: String,
    }

    #[allow(
        clippy::large_enum_variant,
        reason = "test-only stopped-state fixtures keep their complete authoritative contracts visible"
    )]
    enum AuthoritativePostCompletionPreparation {
        Complete(PostCompletionDispatchFixture, CompiledExecutionPolicy),
        UnlaunchedLiveState(UnlaunchedLiveStatePreparation),
        ClaimedLiveState(ClaimedLiveStateRestartPreparation),
        UnadmittedApplication(UnadmittedApplicationPreparation),
    }

    fn wire_contract_digest(domain: &[u8], value: &(impl serde::Serialize + ?Sized)) -> Digest {
        let encoded = serde_json::to_vec(value).expect("encode wire digest preimage");
        let mut preimage = Vec::with_capacity(domain.len() + encoded.len());
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(&encoded);
        Digest::sha256(&preimage)
    }

    fn rollback_target_contract(change_set: &ChangeSet) -> Vec<WireRollbackTargetContract> {
        change_set
            .operations
            .iter()
            .map(|operation| match operation {
                FileOperation::Create { path, result_hash } => WireRollbackTargetContract {
                    path: path
                        .to_str()
                        .expect("portable rollback fixture path")
                        .to_owned(),
                    application: WireRollbackExpectedEndpoint::Regular {
                        digest: result_hash.clone(),
                        mode: 0o600,
                    },
                    restored_base: WireRollbackExpectedEndpoint::Absent,
                },
                FileOperation::Modify { .. } | FileOperation::Delete { .. } => {
                    panic!("post-completion desktop fixture uses one create operation")
                }
            })
            .collect()
    }

    fn rollback_target_contract_digest(targets: &[WireRollbackTargetContract]) -> Digest {
        wire_contract_digest(b"grok-build.rollback.target-contract.v1\0", targets)
    }

    #[derive(serde::Serialize)]
    struct ExpectedApplicationEndpointDigestEntry<'a> {
        path: &'a str,
        endpoint: &'a WireRollbackExpectedEndpoint,
    }

    fn expected_application_endpoints_digest(targets: &[WireRollbackTargetContract]) -> Digest {
        let entries = targets
            .iter()
            .map(|target| ExpectedApplicationEndpointDigestEntry {
                path: &target.path,
                endpoint: &target.application,
            })
            .collect::<Vec<_>>();
        wire_contract_digest(
            b"grok-build.rollback.expected-application-endpoints.v1\0",
            &entries,
        )
    }

    #[derive(serde::Serialize)]
    struct RestoredEndpointDigestEntry<'a> {
        path: &'a str,
        restored_hash: Option<&'a Digest>,
    }

    fn restored_base_endpoints_digest(targets: &[WireRollbackTargetContract]) -> Digest {
        let entries = targets
            .iter()
            .map(|target| RestoredEndpointDigestEntry {
                path: &target.path,
                restored_hash: match &target.restored_base {
                    WireRollbackExpectedEndpoint::Absent => None,
                    WireRollbackExpectedEndpoint::Regular { digest, .. } => Some(digest),
                },
            })
            .collect::<Vec<_>>();
        wire_contract_digest(b"grok-build.restored-base-endpoints.v1\0", &entries)
    }

    fn rollback_observations_digest(observations: &[WireRollbackPathObservation]) -> Digest {
        wire_contract_digest(b"grok-build.rollback.observed-endpoints.v1\0", observations)
    }

    fn typed_rollback_success(fixture: &PostCompletionDispatchFixture) -> RunnerResponse {
        let targets = rollback_target_contract(&fixture.change_set);
        let pre_effect_observations = targets
            .iter()
            .map(|target| WireRollbackPathObservation {
                path: target.path.clone(),
                endpoint: match &target.application {
                    WireRollbackExpectedEndpoint::Absent => WireRollbackObservedEndpoint::Absent,
                    WireRollbackExpectedEndpoint::Regular { digest, mode } => {
                        WireRollbackObservedEndpoint::Regular {
                            digest: digest.clone(),
                            length: 1,
                            mode: *mode,
                        }
                    }
                },
            })
            .collect::<Vec<_>>();
        let post_restore_observations = targets
            .iter()
            .map(|target| WireRollbackPathObservation {
                path: target.path.clone(),
                endpoint: WireRollbackObservedEndpoint::Absent,
            })
            .collect::<Vec<_>>();
        RunnerResponse::RollbackCompletedWithEvidence {
            evidence: WireExplicitRollbackEvidence {
                bundle: fixture.bundle.clone(),
                rollback: fixture.rollback.clone(),
                transaction_id: fixture.rollback.transaction_id.clone(),
                change_set_id: fixture.rollback.change_set_id.clone(),
                expected_application_endpoints_digest: expected_application_endpoints_digest(
                    &targets,
                ),
                restored_base_endpoints_digest: restored_base_endpoints_digest(&targets),
                touched_target_set_digest: fixture.rollback.touched_target_set_digest.clone(),
                pre_effect_observations_digest: rollback_observations_digest(
                    &pre_effect_observations,
                ),
                pre_effect_observations,
                effect_started_at_unix_ms: 1,
                post_restore_observations_digest: rollback_observations_digest(
                    &post_restore_observations,
                ),
                post_restore_observations,
                final_live_manifest_digest: fixture.change_set.base_snapshot.clone(),
                final_live_manifest_observed_at_unix_ms: 2,
                target_contract: targets,
            },
        }
    }

    fn typed_rollback_live_conflict(fixture: &PostCompletionDispatchFixture) -> RunnerResponse {
        let targets = rollback_target_contract(&fixture.change_set);
        let observations = targets
            .iter()
            .map(|target| WireRollbackPathObservation {
                path: target.path.clone(),
                endpoint: WireRollbackObservedEndpoint::Absent,
            })
            .collect::<Vec<_>>();
        let conflicts = targets
            .iter()
            .map(|target| {
                let expected_endpoint_digest = match &target.application {
                    WireRollbackExpectedEndpoint::Absent => {
                        Digest::sha256(b"grok-build.post-completion-rollback.endpoint.absent.v1\0")
                    }
                    WireRollbackExpectedEndpoint::Regular { digest, .. } => digest.clone(),
                };
                WireRollbackPathConflict {
                    path: target.path.clone(),
                    expected_endpoint_digest,
                    observed_endpoint_digest: Digest::sha256(
                        b"grok-build.post-completion-rollback.endpoint.absent.v1\0",
                    ),
                }
            })
            .collect();
        RunnerResponse::RollbackLiveConflict {
            conflict: WireRollbackLiveConflict {
                bundle: fixture.bundle.clone(),
                rollback: fixture.rollback.clone(),
                transaction_id: fixture.rollback.transaction_id.clone(),
                change_set_id: fixture.rollback.change_set_id.clone(),
                expected_application_endpoints_digest: expected_application_endpoints_digest(
                    &targets,
                ),
                touched_target_set_digest: fixture.rollback.touched_target_set_digest.clone(),
                observed_endpoints_digest: rollback_observations_digest(&observations),
                observations,
                conflicts,
                live_manifest_digest: Digest::sha256(b"conflicted live manifest"),
                manifest_observed_at_unix_ms: 1,
                observed_at_unix_ms: 2,
                rollback_mutation_started: false,
                target_contract: targets,
            },
        }
    }

    fn legacy_rollback_success(fixture: &PostCompletionDispatchFixture) -> RunnerResponse {
        RunnerResponse::RollbackCompleted {
            evidence: WireRollbackEvidence {
                bundle: fixture.bundle.clone(),
                transaction_id: fixture.rollback.transaction_id.clone(),
                change_set_id: fixture.change_set.change_set_id.clone(),
                base_snapshot: fixture.change_set.base_snapshot.clone(),
                live_manifest_digest: fixture.change_set.base_snapshot.clone(),
                restored_base_endpoints_digest: fixture
                    .change_set
                    .restored_base_endpoints_digest()
                    .expect("restored endpoint digest"),
                touched_target_set_digest: fixture.rollback.touched_target_set_digest.clone(),
            },
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the authorization fixture constructs the full application, journal, change-set, bundle, wire-artifact, and operation digest chain"
    )]
    fn post_completion_dispatch_fixture(
        harness: &TestHarness,
        policy: &CompiledExecutionPolicy,
        session: &RunnerSessionPolicyRecord,
        suffix: &str,
    ) -> PostCompletionDispatchFixture {
        let result_hash = Digest::sha256(format!("post-completion-result-{suffix}").as_bytes());
        let result_manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            harness.authority.contract().grant_hash.clone(),
            1,
            2,
            vec![DescriptorRelativeManifestEntry {
                path: format!("src/{suffix}.rs"),
                content_digest: result_hash.clone(),
                byte_length: 1,
                unix_mode: 0o600,
            }],
        )
        .expect("derive descriptor-relative applied result snapshot");
        let result_snapshot = result_manifest.manifest_digest;
        let change_set = ChangeSet {
            change_set_id: format!("change-{suffix}"),
            base_snapshot: harness.base_snapshot.clone(),
            result_snapshot: result_snapshot.clone(),
            operations: vec![FileOperation::Create {
                path: PathBuf::from(format!("src/{suffix}.rs")),
                result_hash,
            }],
        };
        change_set.validate().expect("valid dispatch change set");
        let bundle = StageBundleReference {
            format_version: 1,
            bundle_digest: Digest::sha256(format!("stage-bundle-{suffix}").as_bytes()),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
        };
        let target_contract = rollback_target_contract(&change_set);
        let application_receipt = ApplicationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: format!("application-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            effect_id: format!("application-effect-{suffix}"),
            observation_id: format!("application-observation-{suffix}"),
            applier_session_id: session.session_id.clone(),
            transaction_id: format!("transaction-{suffix}"),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
            policy_hash: policy.contract().policy_hash.clone(),
            grant_hash: harness.authority.contract().grant_hash.clone(),
            policy_version: harness.authority.contract().policy_version,
            applied_operations_digest: change_set
                .applied_operations_digest()
                .expect("application operation digest"),
            touched_path_endpoints_digest: change_set
                .touched_path_endpoints_digest()
                .expect("application endpoint digest"),
            live_manifest_digest: change_set.result_snapshot.clone(),
            applied_at_unix_ms: 1_020,
        };
        let application = ApplicationEvidence {
            contract_version: CONTRACT_VERSION,
            receipt: application_receipt.clone(),
            validation: ApplicationValidationEvidence {
                mode: ApplicationValidationMode::DirectEffectResponse,
                runner_launch_id: session.launch_id.clone(),
                runner_session_id: session.session_id.clone(),
                policy_hash: session.policy_hash.clone(),
                grant_hash: session.grant_hash.clone(),
                policy_version: session.policy_version,
                private_state_digest: session.private_state_digest.clone(),
            },
        };
        application.validate().expect("valid application evidence");
        let plan = WireRollbackArtifact {
            kind: WireRollbackArtifactKind::Plan,
            name: "plan".into(),
            length: 1,
            mode: 0o600,
            digest: Digest::sha256(format!("plan-{suffix}").as_bytes()),
            device: 7,
            inode: 11,
            owner_uid: 501,
            modified_seconds: 1,
            modified_nanoseconds: 0,
            changed_seconds: 1,
            changed_nanoseconds: 0,
        };
        let mut rollback = WireRollbackArtifactReference {
            transaction_id: application_receipt.transaction_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: change_set.base_snapshot.clone(),
            touched_target_set_digest: change_set
                .touched_target_set_digest()
                .expect("application target digest"),
            target_contract_digest: rollback_target_contract_digest(&target_contract),
            transaction_device: 7,
            transaction_inode: 10,
            transaction_mode: 0o700,
            transaction_owner_uid: 501,
            artifacts_digest: Digest::sha256(b"placeholder"),
            artifacts: vec![plan],
        };
        let reopened_artifacts_bytes = rollback.reopened_artifacts_bytes();
        rollback.artifacts_digest = Digest::sha256(&reopened_artifacts_bytes);
        let rollback_reference = RollbackReferenceEvidence {
            reference: RollbackReference {
                contract_version: CONTRACT_VERSION,
                reference_id: format!("rollback-reference-{suffix}"),
                sprint_id: harness.sprint_id.clone(),
                application_receipt_id: application_receipt.receipt_id.clone(),
                transaction_id: application_receipt.transaction_id.clone(),
                journal_binding_digest: application_receipt
                    .journal_binding_digest()
                    .expect("journal binding digest"),
                base_snapshot: change_set.base_snapshot.clone(),
                touched_target_set_digest: rollback.touched_target_set_digest.clone(),
                reopened_artifacts_digest: rollback.artifacts_digest.clone(),
                validated_at_unix_ms: 1_030,
            },
            reopened_artifacts_bytes,
        };
        rollback_reference
            .validate()
            .expect("valid rollback reference evidence");
        let request = RollbackRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: harness.sprint_id.clone(),
            application_receipt_id: application_receipt.receipt_id.clone(),
            application_transaction_id: application_receipt.transaction_id.clone(),
            rollback_reference_id: rollback_reference.reference.reference_id.clone(),
        };
        let operation = PostCompletionRollbackIntent {
            contract_version: CONTRACT_VERSION,
            operation_id: format!("operation-{suffix}"),
            idempotency_key: format!("idempotency-{suffix}"),
            rollback_effect_id: format!("rollback-effect-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            completion_receipt_id: format!("completion-{suffix}"),
            completion_receipt_digest: Digest::sha256(format!("completion-{suffix}").as_bytes()),
            application_evidence_digest: Digest::sha256(
                &serde_json::to_vec(&application).expect("encode application evidence"),
            ),
            rollback_reference_evidence_digest: Digest::sha256(
                &serde_json::to_vec(&rollback_reference)
                    .expect("encode rollback reference evidence"),
            ),
            request_digest: Digest::sha256(
                &serde_json::to_vec(&request).expect("encode rollback request"),
            ),
            request,
            policy_hash: policy.contract().policy_hash.clone(),
            grant_hash: harness.authority.contract().grant_hash.clone(),
            policy_version: harness.authority.contract().policy_version,
            created_at_unix_ms: 1_050,
        };
        operation.validate().expect("valid operation envelope");
        PostCompletionDispatchFixture {
            operation,
            application,
            rollback_reference,
            change_set,
            bundle,
            rollback,
        }
    }

    fn prepare_authoritative_post_completion_dispatch(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        suffix: &str,
    ) -> (PostCompletionDispatchFixture, CompiledExecutionPolicy) {
        let AuthoritativePostCompletionPreparation::Complete(fixture, policy) =
            prepare_authoritative_post_completion_dispatch_inner(
                harness,
                ledger,
                suffix,
                AuthoritativePostCompletionFixtureMode::Complete,
            )
        else {
            unreachable!("complete post-completion fixture stopped after live-state claim")
        };
        (fixture, policy)
    }

    fn prepare_unadmitted_application_fixture(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        suffix: &str,
        register_session: bool,
    ) -> UnadmittedApplicationPreparation {
        let AuthoritativePostCompletionPreparation::UnadmittedApplication(prepared) =
            prepare_authoritative_post_completion_dispatch_inner(
                harness,
                ledger,
                suffix,
                AuthoritativePostCompletionFixtureMode::StopBeforeApplicationAdmission {
                    register_session,
                },
            )
        else {
            unreachable!("unadmitted application fixture crossed its pre-admission stop")
        };
        prepared
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the regression fixture deliberately constructs the complete public completion and post-completion authority chain"
    )]
    fn prepare_authoritative_post_completion_dispatch_inner(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        suffix: &str,
        mode: AuthoritativePostCompletionFixtureMode,
    ) -> AuthoritativePostCompletionPreparation {
        let final_policy = read_only_policy(harness, &format!("{suffix}-final"));
        let applier_policy = read_only_policy(harness, &format!("{suffix}-applier"));
        let worker_cleanup = launch_ordinary_completion_role(
            harness,
            ledger,
            &harness.policy,
            &format!("{suffix}-worker"),
            RunnerRole::Worker,
        );
        let final_cleanup = launch_ordinary_completion_role(
            harness,
            ledger,
            &final_policy,
            &format!("{suffix}-final"),
            RunnerRole::FinalVerifier,
        );
        let register_application_session = !matches!(
            mode,
            AuthoritativePostCompletionFixtureMode::StopBeforeApplicationAdmission {
                register_session: false,
            }
        );
        let application_cleanup = launch_ordinary_completion_role_with_registration(
            harness,
            ledger,
            &applier_policy,
            &format!("{suffix}-application"),
            RunnerRole::Applier,
            register_application_session,
            None,
            None,
        );
        let worker_launch = worker_cleanup.launch.clone();
        let worker_session = worker_cleanup.session.clone();
        let final_launch = final_cleanup.launch.clone();
        let final_session = final_cleanup.session.clone();
        let application_launch = application_cleanup.launch.clone();
        let application_session = application_cleanup.session.clone();

        let mut fixture = post_completion_dispatch_fixture(
            harness,
            &applier_policy,
            &application_session,
            suffix,
        );
        ledger
            .persist_workspace_snapshot(
                &harness.sprint_id,
                &WorkspaceSnapshot {
                    snapshot_id: fixture.change_set.result_snapshot.clone(),
                    grant_hash: harness.authority.contract().grant_hash.clone(),
                    created_at_unix_ms: 1_002,
                },
            )
            .expect("persist completed result snapshot");
        ledger
            .persist_change_set(&harness.sprint_id, &fixture.change_set)
            .expect("persist completed change set");

        let start = [
            worker_session.registered_at_unix_ms,
            final_session.registered_at_unix_ms,
            application_session.registered_at_unix_ms,
        ]
        .into_iter()
        .max()
        .expect("completion sessions")
        .checked_add(10)
        .expect("bounded completion fixture timestamp");
        let running = worker_cleanup
            .task_attempt_running
            .as_ref()
            .expect("worker completion role entered Running");
        let attempt = running.attempt.clone();
        let verification_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&harness.sprint_id)
                .expect("next verification-boundary sequence"),
            event_id: format!("task-verifying-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some(attempt.worker_lease.task_id.clone()),
            worker_id: Some(attempt.worker_lease.worker_id.clone()),
            causation_id: Some(running.transition_event_id.clone()),
            correlation_id: format!("task-attempt-{suffix}"),
            policy_hash: Some(worker_launch.policy_hash.clone()),
            occurred_at_unix_ms: start,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: "Verifying".into(),
            },
        };
        let verification_boundary = TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("task-verification-boundary-{suffix}"),
            attempt: attempt.clone(),
            runner_launch_id: worker_launch.launch_id.clone(),
            runner_session_id: worker_session.session_id.clone(),
            change_set_id: fixture.change_set.change_set_id.clone(),
            sealed_snapshot: fixture.change_set.result_snapshot.clone(),
            transition_event_id: verification_event.event_id.clone(),
            terminal_non_cleanup_effects: Vec::new(),
            sealed_at_unix_ms: start,
        };
        ledger
            .transition_task_attempt_to_verifying(&verification_boundary, &verification_event)
            .expect("seal exact task attempt for verification");
        let candidate_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&harness.sprint_id)
                .expect("next candidate-boundary sequence"),
            event_id: format!("task-candidate-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some(attempt.worker_lease.task_id.clone()),
            worker_id: Some(attempt.worker_lease.worker_id.clone()),
            causation_id: Some(verification_event.event_id.clone()),
            correlation_id: format!("task-attempt-{suffix}"),
            policy_hash: Some(worker_launch.policy_hash.clone()),
            occurred_at_unix_ms: start + 1,
            payload: AgentEventKind::TaskStateChanged {
                from: "Verifying".into(),
                to: "Candidate".into(),
            },
        };
        let candidate_boundary = TaskAttemptCandidateBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("task-candidate-boundary-{suffix}"),
            attempt: attempt.clone(),
            verification_boundary_id: verification_boundary.boundary_id.clone(),
            change_set_id: fixture.change_set.change_set_id.clone(),
            sealed_snapshot: fixture.change_set.result_snapshot.clone(),
            formal_check_ids: Vec::new(),
            verification_receipt_ids: Vec::new(),
            transition_event_id: candidate_event.event_id.clone(),
            admitted_at_unix_ms: start + 1,
        };
        ledger
            .transition_task_attempt_to_candidate(&candidate_boundary, &candidate_event)
            .expect("admit exact human-only task candidate");

        let integration_artifact = fixture
            .bundle
            .to_core_integration_artifact()
            .expect("map durable integration artifact");
        let integration_request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: fixture.change_set.clone(),
            artifact: integration_artifact.clone(),
        };
        let integration_request_bytes =
            serde_json::to_vec(&integration_request).expect("encode integration request");
        let integration_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-integration".into(),
            idempotency_key: "key-integration".into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: worker_session.worker_lease.clone(),
            causation_event_id: Some(candidate_event.event_id.clone()),
            correlation_id: "correlation-integration".into(),
            kind: EffectKind::IntegrateChangeSet,
            request_digest: Digest::sha256(&integration_request_bytes),
            policy_hash: worker_launch.policy_hash.clone(),
            input_snapshot: fixture.change_set.base_snapshot.clone(),
            created_at_unix_ms: start + 2,
        };
        let integration_proposal = proposal(
            &integration_intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next integration proposal sequence"),
        );
        let integration_admission = TaskAttemptIntegrationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("task-integration-admission-{suffix}"),
            candidate_boundary: candidate_boundary.clone(),
            effect_id: integration_intent.effect_id.clone(),
            runner_launch_id: worker_launch.launch_id.clone(),
            runner_session_id: worker_session.session_id.clone(),
            input_snapshot: fixture.change_set.base_snapshot.clone(),
            result_snapshot: fixture.change_set.result_snapshot.clone(),
            admitted_at_unix_ms: start + 2,
        };
        let TaskIntegrationDispatchAdmission::Fresh {
            permit: integration_permit,
            ..
        } = ledger
            .admit_task_attempt_integration_for_dispatch(
                &integration_admission,
                &integration_intent,
                &integration_request,
                &integration_proposal,
            )
            .expect("pre-admit exact candidate integration effect")
        else {
            panic!("new fixture integration admission must mint one fresh permit")
        };
        let (_claimed_integration, integration_transport_permit) = ledger
            .claim_task_attempt_integration_dispatch(integration_permit, &integration_request_bytes)
            .expect("claim exact fixture integration dispatch");
        let integration_observation_authority = integration_transport_permit
            .validate_transport_request(
                &integration_intent,
                &integration_request_bytes,
                &worker_launch,
                &worker_session,
                None,
                &integration_request_bytes,
            )
            .expect("validate exact fixture integration transport authority");
        let integration_evidence = TaskIntegrationEvidence {
            contract_version: CONTRACT_VERSION,
            artifact: integration_artifact.clone(),
            validation: TaskIntegrationValidationEvidence {
                mode: TaskIntegrationValidationMode::WorkerPublication,
                runner_launch_id: worker_launch.launch_id.clone(),
                runner_session_id: worker_session.session_id.clone(),
                policy_hash: worker_session.policy_hash.clone(),
                grant_hash: worker_session.grant_hash.clone(),
                private_state_digest: worker_session.private_state_digest.clone(),
            },
            receipt: TaskIntegrationReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: "integration-task".into(),
                sprint_id: harness.sprint_id.clone(),
                task_id: "task-1".into(),
                worker_id: "worker-1".into(),
                worker_lease: worker_session.worker_lease.clone(),
                worker_launch_id: worker_launch.launch_id.clone(),
                worker_session_id: worker_session.session_id.clone(),
                worker_policy_hash: worker_session.policy_hash.clone(),
                effect_id: integration_intent.effect_id.clone(),
                observation_id: "observation-integration".into(),
                change_set_id: fixture.change_set.change_set_id.clone(),
                input_snapshot: fixture.change_set.base_snapshot.clone(),
                result_snapshot: fixture.change_set.result_snapshot.clone(),
                task_verification_receipt_ids: candidate_boundary.verification_receipt_ids.clone(),
                integration_ordinal: 0,
                integrated_at_unix_ms: start + 3,
            },
        };
        let integration_evidence_bytes =
            serde_json::to_vec(&integration_evidence).expect("encode integration evidence");
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
        let integration_transition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: integration_terminal.sequence + 1,
            event_id: format!("task-integrated-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some(attempt.worker_lease.task_id.clone()),
            worker_id: Some(attempt.worker_lease.worker_id.clone()),
            causation_id: Some(integration_terminal.event_id.clone()),
            correlation_id: format!("task-attempt-{suffix}"),
            policy_hash: Some(worker_launch.policy_hash.clone()),
            occurred_at_unix_ms: start + 4,
            payload: AgentEventKind::TaskStateChanged {
                from: "Candidate".into(),
                to: "Integrated".into(),
            },
        };
        let integration_disposition =
            TaskAttemptDisposition::Integrated(TaskAttemptIntegratedDisposition {
                metadata: TaskAttemptDispositionMetadata {
                    contract_version: CONTRACT_VERSION,
                    disposition_id: format!("task-integrated-disposition-{suffix}"),
                    attempt,
                    from_state: TaskState::Candidate,
                    state_transition_event_id: integration_transition.event_id.clone(),
                    disposed_at_unix_ms: start + 4,
                },
                candidate_boundary,
                integration_receipt: integration_evidence.receipt.clone(),
                evidence: TaskAttemptEvidence::new(
                    format!("task-integration-evidence-{suffix}"),
                    TaskAttemptEvidenceKind::Integrated,
                    integration_evidence_bytes.clone(),
                )
                .expect("construct exact typed integration evidence"),
            });
        ledger
            .integrate_claimed_task_attempt(
                integration_observation_authority,
                &integration_disposition,
                &integration_observation,
                &integration_terminal,
                &integration_evidence,
                &integration_transition,
            )
            .expect("atomically persist integration and task disposition");

        persist_cleanup_evidence(
            ledger,
            &worker_cleanup,
            &worker_session,
            Some(integration_disposition.metadata().disposition_id.as_str()),
            "cleanup-worker",
            start + 5,
        );

        let (final_verification, final_verification_terminal, criterion_evidence) =
            persist_claimed_final_verification_evidence_v12(
                ledger,
                &final_launch,
                &final_session,
                &final_policy,
                &harness.authority,
                &harness.private_state,
                match final_cleanup.cleanup_request.platform_backend {
                    WorkerCleanupBackend::MacOsDedicatedIdentity => {
                        CommandDomainBackend::MacOsDedicatedIdentity
                    }
                    WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
                    WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                        panic!("final verifier cannot use trusted-Applier cleanup")
                    }
                },
                &format!("command-cleanup-{suffix}-final"),
                "verify-final",
                suffix,
                &fixture.change_set.result_snapshot,
                start + 7,
                start + 8,
            );
        let final_cleanup_at_unix_ms = final_verification
            .finished_at_unix_ms
            .saturating_add(1)
            .max(start + 9);
        persist_cleanup_evidence(
            ledger,
            &final_cleanup,
            &final_session,
            None,
            "cleanup-final",
            final_cleanup_at_unix_ms,
        );

        let application_phase_at_unix_ms =
            final_cleanup_at_unix_ms.saturating_add(2).max(start + 11);
        let preparation = ledger
            .assess_sprint_application_preparation(
                &harness.sprint_id,
                &final_verification.receipt_id,
                &format!("application-assembly-{suffix}"),
                application_phase_at_unix_ms,
            )
            .expect("derive exact post-completion application assembly");
        let SprintApplicationPreparation::Ready(assembly) = preparation else {
            panic!("one nonempty integrated winner must produce a ready application assembly")
        };
        assert_eq!(assembly.change_set, fixture.change_set);
        assert_eq!(assembly.artifact, integration_artifact);
        assert_eq!(assembly.sources.len(), 1);
        assert_eq!(assembly.sources[0].source_ordinal, 0);

        fixture.application.receipt.applied_at_unix_ms =
            application_phase_at_unix_ms.saturating_add(1);
        fixture.rollback_reference.reference.validated_at_unix_ms =
            application_phase_at_unix_ms.saturating_add(2);
        let application_request = ApplicationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: assembly.change_set.clone(),
            artifact: assembly.artifact.clone(),
        };
        if matches!(
            mode,
            AuthoritativePostCompletionFixtureMode::StopBeforeApplicationAdmission { .. }
        ) {
            return AuthoritativePostCompletionPreparation::UnadmittedApplication(
                UnadmittedApplicationPreparation {
                    policy: applier_policy,
                    final_verification_receipt_id: final_verification.receipt_id,
                    final_verification_terminal,
                    application: application_cleanup,
                    request: application_request,
                    stage_bundle: fixture.bundle,
                    artifact_assembly_id: assembly.assembly_id,
                },
            );
        }
        let application_request_bytes =
            serde_json::to_vec(&application_request).expect("encode application request");
        let application_phase_sequence = ledger
            .next_sequence(&harness.sprint_id)
            .expect("next application phase sequence");
        let application_phase_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: application_phase_sequence,
            event_id: format!("sprint-applying-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(final_verification_terminal.event_id.clone()),
            correlation_id: format!("correlation-application-{suffix}"),
            policy_hash: Some(application_launch.policy_hash.clone()),
            occurred_at_unix_ms: application_phase_at_unix_ms,
            payload: AgentEventKind::SprintStateChanged {
                from: "FinalVerification".into(),
                to: "Applying".into(),
            },
        };
        let application_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: fixture.application.receipt.effect_id.clone(),
            idempotency_key: format!("key-application-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(application_phase_event.event_id.clone()),
            correlation_id: application_phase_event.correlation_id.clone(),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&application_request_bytes),
            policy_hash: application_launch.policy_hash.clone(),
            input_snapshot: application_request.change_set.base_snapshot.clone(),
            created_at_unix_ms: application_phase_at_unix_ms,
        };
        let application_proposal = proposal(&application_intent, application_phase_sequence + 1);
        let application_admission = SprintApplicationAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("application-admission-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            sprint_phase_event_id: application_phase_event.event_id.clone(),
            final_verification_receipt_id: final_verification.receipt_id.clone(),
            artifact_assembly_id: assembly.assembly_id.clone(),
            effect_id: application_intent.effect_id.clone(),
            runner_launch_id: application_launch.launch_id.clone(),
            runner_session_id: application_session.session_id.clone(),
            request: application_request.clone(),
            admitted_at_unix_ms: application_intent.created_at_unix_ms,
        };
        let SprintApplicationDispatchAdmission::Fresh {
            admission: stored_admission,
            assembly: stored_assembly,
            effect: stored_effect,
            permit,
        } = ledger
            .admit_sprint_application_for_dispatch(
                &application_admission,
                &application_phase_event,
                &application_intent,
                &application_proposal,
            )
            .expect("atomically admit exact post-completion application")
        else {
            panic!("new post-completion application fixture must mint one fresh permit")
        };
        assert_eq!(stored_admission, application_admission);
        assert_eq!(stored_assembly, assembly);
        assert_eq!(stored_effect.intent, application_intent);
        assert!(matches!(
            ledger.admit_sprint_application_for_dispatch(
                &application_admission,
                &application_phase_event,
                &application_intent,
                &application_proposal,
            ),
            Ok(SprintApplicationDispatchAdmission::Existing {
                admission: ref replay_admission,
                assembly: ref replay_assembly,
                ref effect,
            }) if replay_admission == &application_admission
                && replay_assembly == &assembly
                && effect.dispatch_claim.is_none()
        ));
        let (_, application_transport) = ledger
            .claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintApplication(permit),
                &application_request_bytes,
            )
            .expect("claim exact post-completion application dispatch");
        let application_authority = application_transport
            .validate_transport_request(
                &application_intent,
                &application_request_bytes,
                &application_launch,
                &application_session,
                None,
                &application_request_bytes,
            )
            .expect("validate exact post-completion application transport");
        let application_evidence_bytes =
            serde_json::to_vec(&fixture.application).expect("encode application evidence");
        let application_observation = observation(
            &application_intent,
            fixture.application.receipt.observation_id.clone(),
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&application_evidence_bytes),
            },
            fixture.application.receipt.applied_at_unix_ms,
        );
        let application_terminal = terminal_event(
            ledger,
            &application_intent,
            &application_proposal.event_id,
            &application_observation,
        );
        ledger
            .record_claimed_application_effect_observation_with_rollback(
                application_authority,
                &application_observation,
                &application_terminal,
                &fixture.application,
                &fixture.rollback_reference,
            )
            .expect("persist claimed application and rollback-reference evidence");

        let application_cleanup_at_unix_ms = application_phase_at_unix_ms
            .saturating_add(4)
            .max(start + 15);
        persist_cleanup_evidence(
            ledger,
            &application_cleanup,
            &application_session,
            None,
            "cleanup-applier",
            application_cleanup_at_unix_ms,
        );

        let live_state_policy = read_only_policy(harness, &format!("{suffix}-live-state"));
        let persisted_before_capture = ledger
            .load_sprint(&harness.sprint_id)
            .expect("load exact pre-capture high-water cut");
        let source_event = persisted_before_capture
            .events
            .last()
            .expect("applier cleanup leaves a latest durable event");
        let plan = ledger
            .derive_applied_live_state_capture_plan(
                SprintLiveStateCapturePlanCut {
                    plan_id: format!("live-state-plan-{suffix}"),
                    source_event_id: source_event.event_id.clone(),
                    source_event_sequence: source_event.sequence,
                    planned_at_unix_ms: source_event
                        .occurred_at_unix_ms
                        .max(application_cleanup_at_unix_ms.saturating_add(1))
                        .max(start + 16),
                },
                &live_state_policy,
                &harness.sprint_id,
                &final_verification.receipt_id,
                &fixture.application.receipt.receipt_id,
                &fixture.rollback_reference.reference.reference_id,
            )
            .expect("derive exact applied live-state capture plan");
        if mode == AuthoritativePostCompletionFixtureMode::StopBeforeLiveStateLaunch {
            return AuthoritativePostCompletionPreparation::UnlaunchedLiveState(
                UnlaunchedLiveStatePreparation {
                    policy: live_state_policy,
                    plan,
                },
            );
        }
        let live_state = launch_live_state_completion_role(
            harness,
            ledger,
            &live_state_policy,
            &plan,
            &format!("{suffix}-live-state"),
        );
        let capture_request = SprintLiveStateCaptureRequest::from_plan(plan.clone())
            .expect("construct exact applied live-state request");
        let capture_request_bytes =
            serde_json::to_vec(&capture_request).expect("encode applied live-state request");
        let capture_intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("live-state-effect-{suffix}"),
            idempotency_key: format!("live-state-key-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: Some(live_state.cleanup_proposed_event_id.clone()),
            correlation_id: format!("live-state-correlation-{suffix}"),
            kind: EffectKind::CaptureWorkspaceState,
            request_digest: Digest::sha256(&capture_request_bytes),
            policy_hash: plan.policy_hash.clone(),
            input_snapshot: plan.expected_snapshot.clone(),
            created_at_unix_ms: live_state
                .session
                .registered_at_unix_ms
                .saturating_add(1)
                .max(plan.planned_at_unix_ms.saturating_add(1)),
        };
        let capture_proposal = proposal(
            &capture_intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next applied live-state proposal sequence"),
        );
        let capture_admission = SprintLiveStateCaptureAdmission {
            contract_version: CONTRACT_VERSION,
            admission_id: format!("live-state-admission-{suffix}"),
            plan: plan.clone(),
            request: capture_request,
            effect_id: capture_intent.effect_id.clone(),
            runner_launch_id: live_state.launch.launch_id.clone(),
            runner_session_id: live_state.session.session_id.clone(),
            admitted_at_unix_ms: capture_intent.created_at_unix_ms,
        };
        let SprintLiveStateCaptureDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_live_state_capture_for_dispatch(
                &capture_admission,
                &capture_intent,
                &capture_proposal,
            )
            .expect("admit exact applied live-state capture")
        else {
            panic!("new applied live-state capture must mint one fresh permit")
        };
        let opaque_capture_transport = format!("opaque-live-state-transport-{suffix}").into_bytes();
        let (claimed_capture, transport) = ledger
            .claim_sprint_live_state_capture_dispatch(permit, &opaque_capture_transport)
            .expect("claim exact applied live-state capture dispatch");
        if mode == AuthoritativePostCompletionFixtureMode::StopAfterLiveStateClaim {
            drop(transport);
            return AuthoritativePostCompletionPreparation::ClaimedLiveState(
                ClaimedLiveStateRestartPreparation {
                    policy: live_state_policy,
                    plan,
                    verifier: live_state,
                    admission: capture_admission,
                    intent: capture_intent,
                    proposed_event: capture_proposal,
                    claimed: claimed_capture,
                },
            );
        }
        let capture_authority = transport
            .validate_transport_request(
                &capture_intent,
                &capture_request_bytes,
                &live_state.launch,
                &live_state.session,
                None,
                &opaque_capture_transport,
            )
            .expect("validate exact applied live-state transport request");
        let capture_started_at_unix_ms = capture_intent.created_at_unix_ms.saturating_add(1);
        let captured_at_unix_ms = capture_started_at_unix_ms.saturating_add(1);
        let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            harness.authority.contract().grant_hash.clone(),
            capture_started_at_unix_ms,
            captured_at_unix_ms,
            vec![DescriptorRelativeManifestEntry {
                path: format!("src/{suffix}.rs"),
                content_digest: Digest::sha256(
                    format!("post-completion-result-{suffix}").as_bytes(),
                ),
                byte_length: 1,
                unix_mode: 0o600,
            }],
        )
        .expect("capture exact descriptor-relative applied result");
        assert_eq!(manifest.manifest_digest, plan.expected_snapshot);
        let dispatch_claim = claimed_capture
            .dispatch_claim
            .as_ref()
            .expect("claimed capture retains dispatch custody");
        let capture_evidence = LiveStateCaptureEvidence {
            contract_version: CONTRACT_VERSION,
            receipt: LiveStateCaptureReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!("live-state-receipt-{suffix}"),
                admission_id: capture_admission.admission_id.clone(),
                effect_id: capture_intent.effect_id.clone(),
                observation_id: format!("live-state-observation-{suffix}"),
                dispatch_claim_id: dispatch_claim.dispatch_claim_id.clone(),
                sprint_id: harness.sprint_id.clone(),
                plan_id: plan.plan_id.clone(),
                plan_digest: plan.plan_digest().expect("digest applied capture plan"),
                request_digest: capture_admission
                    .request
                    .request_digest()
                    .expect("digest applied capture request"),
                branch: plan.branch.clone(),
                expected_snapshot: plan.expected_snapshot.clone(),
                observed_snapshot: manifest.manifest_digest.clone(),
                runner_launch_id: live_state.launch.launch_id.clone(),
                runner_session_id: live_state.session.session_id.clone(),
                policy_hash: plan.policy_hash.clone(),
                grant_hash: plan.grant_hash.clone(),
                policy_version: plan.policy_version,
                manifest_digest: manifest.manifest_digest.clone(),
                capture_started_at_unix_ms,
                captured_at_unix_ms,
            },
            manifest,
        };
        let capture_evidence_bytes =
            serde_json::to_vec(&capture_evidence).expect("encode applied capture evidence");
        let capture_observation = observation(
            &capture_intent,
            capture_evidence.receipt.observation_id.clone(),
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&capture_evidence_bytes),
            },
            captured_at_unix_ms,
        );
        let capture_terminal = terminal_event(
            ledger,
            &capture_intent,
            &capture_proposal.event_id,
            &capture_observation,
        );
        ledger
            .record_claimed_live_state_capture_observation(
                capture_authority,
                &capture_observation,
                &capture_evidence,
                &capture_terminal,
            )
            .expect("persist exact applied live-state evidence");
        let live_state_cleanup_receipt_id = format!("cleanup-{suffix}-live-state");
        persist_cleanup_evidence(
            ledger,
            &live_state,
            &live_state.session,
            None,
            &live_state_cleanup_receipt_id,
            captured_at_unix_ms.saturating_add(2),
        );

        let body = format!("authoritative post-completion dispatch fixture {suffix}");
        let report = FinalReport {
            report_id: format!("report-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            final_snapshot: fixture.change_set.result_snapshot.clone(),
            content_digest: FinalReport::digest_body(&body),
            body,
            created_at_unix_ms: captured_at_unix_ms.saturating_add(3),
        };
        let mut worker_cleanup_receipt_ids = plan.required_cleanup_receipt_ids.clone();
        worker_cleanup_receipt_ids.push(live_state_cleanup_receipt_id);
        worker_cleanup_receipt_ids.sort();
        let completion = CompletionReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: format!("completion-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            grant_hash: harness.authority.contract().grant_hash.clone(),
            policy_version: harness.authority.contract().policy_version,
            final_snapshot: fixture.change_set.result_snapshot.clone(),
            final_verification_receipt_id: final_verification.receipt_id.clone(),
            application: CompletionApplication::Applied {
                application_receipt_id: fixture.application.receipt.receipt_id.clone(),
                rollback_reference_id: fixture.rollback_reference.reference.reference_id.clone(),
            },
            worker_cleanup_receipt_ids,
            satisfied_criterion_ids: vec![criterion_evidence.criterion_id().to_owned()],
            criterion_evidence_receipt_ids: vec![criterion_evidence.receipt_id().to_owned()],
            task_integration_receipt_ids: vec![integration_evidence.receipt.receipt_id],
            verification_receipts: vec![final_verification.receipt_id],
            provider_backend: "test-provider".into(),
            provider_model: "test-model".into(),
            final_report_id: report.report_id.clone(),
            completed_at_unix_ms: report.created_at_unix_ms.saturating_add(1),
        };
        let completion_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence(&harness.sprint_id)
                .expect("next completion sequence"),
            event_id: format!("event-completion-{suffix}"),
            sprint_id: harness.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: Some(capture_terminal.event_id.clone()),
            correlation_id: format!("correlation-completion-{suffix}"),
            policy_hash: None,
            occurred_at_unix_ms: completion.completed_at_unix_ms,
            payload: AgentEventKind::CompletionRecorded(completion.receipt_id.clone()),
        };
        ledger
            .record_successful_completion_from_live_state_capture(
                &report,
                &completion,
                &capture_evidence.receipt.receipt_id,
                &completion_event,
            )
            .expect("record successful completion");
        fixture.operation = ledger
            .build_post_completion_rollback_intent(
                &harness.sprint_id,
                format!("operation-{suffix}"),
                format!("idempotency-{suffix}"),
                format!("rollback-effect-{suffix}"),
                completion.completed_at_unix_ms.saturating_add(1),
            )
            .expect("build rollback intent from durable completion");
        ledger
            .record_post_completion_rollback_intent(&fixture.operation)
            .expect("record authoritative rollback operation");
        AuthoritativePostCompletionPreparation::Complete(fixture, applier_policy)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the operation-local launch fixture exposes every authority and transport identity"
    )]
    fn launch_post_completion_test_client(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        fixture: &PostCompletionDispatchFixture,
        policy: &CompiledExecutionPolicy,
        suffix: &str,
        role: PostCompletionRollbackApplierRole,
        created_at_unix_ms: u64,
        exchange_count: Rc<Cell<u64>>,
    ) -> RunnerLifecycleClient {
        let mut launch = harness.launch(suffix);
        launch.role = RunnerRole::Applier;
        launch.worker_id = None;
        launch.worker_lease = None;
        launch.shadow_root = None;
        launch.expected_base_snapshot = fixture.change_set.result_snapshot.clone();
        launch.created_at_unix_ms = created_at_unix_ms;
        let client = RunnerLifecycleClient::launch_post_completion_rollback_with_spawner(
            ledger,
            &harness.authority,
            policy,
            &fixture.operation,
            role,
            launch,
            transport_with_exchange_count(
                unique_nonce(suffix),
                harness.identity(),
                ScriptMode::Good,
                false,
                Vec::new(),
                exchange_count,
            ),
        )
        .expect("launch operation-local rollback applier");
        client
            .send_control(RunnerRequest::ApplierRecoverPending)
            .expect("complete mandatory rollback-applier recovery")
            .0
    }

    fn launch_post_completion_test_client_with_response(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        fixture: &PostCompletionDispatchFixture,
        policy: &CompiledExecutionPolicy,
        suffix: &str,
        response: RunnerResponse,
        exchange_count: Rc<Cell<u64>>,
    ) -> RunnerLifecycleClient {
        let mut launch = harness.launch(suffix);
        launch.role = RunnerRole::Applier;
        launch.worker_id = None;
        launch.worker_lease = None;
        launch.shadow_root = None;
        launch.expected_base_snapshot = fixture.change_set.result_snapshot.clone();
        launch.created_at_unix_ms = fixture.operation.created_at_unix_ms + 1;
        let client = RunnerLifecycleClient::launch_post_completion_rollback_with_spawner(
            ledger,
            &harness.authority,
            policy,
            &fixture.operation,
            PostCompletionRollbackApplierRole::Executor,
            launch,
            transport_with_rollback_response(
                unique_nonce(suffix),
                harness.identity(),
                response,
                exchange_count,
            ),
        )
        .expect("launch response-shape rollback executor");
        client
            .send_control(RunnerRequest::ApplierRecoverPending)
            .expect("complete response-shape executor recovery")
            .0
    }

    fn expect_launch_failure(
        result: Result<RunnerLifecycleClient, RunnerLaunchFailure>,
        message: &str,
    ) -> RunnerLaunchFailure {
        match result {
            Err(failure) => failure,
            Ok(client) => {
                drop(client);
                panic!("{message}");
            }
        }
    }

    fn expect_effect_session_failure<T>(
        result: Result<(RunnerLifecycleClient, T), RunnerEffectSessionFailure>,
        message: &str,
    ) -> RunnerEffectSessionFailure {
        match result {
            Err(failure) => failure,
            Ok((client, _)) => {
                drop(client);
                panic!("{message}");
            }
        }
    }

    #[test]
    fn initialization_wire_forwards_exact_durable_lease_and_never_fabricates_one() {
        let (harness, _ledger) = TestHarness::new("initialization-worker-lease");
        let worker_launch = harness.launch("initialization-worker-lease");
        let worker_prepared = prepare_launch(&harness.authority, &harness.policy, &worker_launch)
            .expect("prepare worker initialization");
        let worker_initialization = initialization_envelope(&worker_launch, &worker_prepared);
        let RunnerRequest::InitializeSession {
            logical_worker_id,
            worker_lease,
            role,
            ..
        } = worker_initialization.request
        else {
            unreachable!()
        };
        assert_eq!(role, RunnerRole::Worker);
        assert_eq!(logical_worker_id.as_deref(), Some("worker-1"));
        assert_eq!(worker_lease, Some(harness.worker_lease.clone()));

        let mut verifier_launch = harness.launch("initialization-verifier-no-lease");
        verifier_launch.role = RunnerRole::FinalVerifier;
        verifier_launch.worker_id = None;
        verifier_launch.worker_lease = None;
        let verifier_policy = read_only_policy(&harness, "initialization-verifier-no-lease");
        let verifier_prepared =
            prepare_launch(&harness.authority, &verifier_policy, &verifier_launch)
                .expect("prepare verifier initialization");
        let verifier_initialization = initialization_envelope(&verifier_launch, &verifier_prepared);
        let RunnerRequest::InitializeSession {
            logical_worker_id,
            worker_lease,
            role,
            ..
        } = verifier_initialization.request
        else {
            unreachable!()
        };
        assert_eq!(role, RunnerRole::FinalVerifier);
        assert!(logical_worker_id.is_none());
        assert!(worker_lease.is_none());
    }

    #[test]
    fn desktop_rejects_canonical_substituted_effect_lease_before_send() {
        let (harness, mut ledger) = TestHarness::new("substituted-effect-lease");
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("substituted-effect-lease"),
            transport(
                unique_nonce("substituted-effect-lease"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
            ),
        )
        .expect("initialize exact worker session");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let idempotency_key = "key-substituted-lease";
        let request_bytes =
            provider_read_request_bytes(&harness, idempotency_key, "README.md", 1_024);
        let substituted_lease = WorkerLease::new(
            harness.sprint_id.clone(),
            harness.worker_lease.lease_epoch + 1,
            "task-1".into(),
            "worker-1".into(),
            harness.worker_lease.path_scopes.clone(),
            harness.worker_lease.acquired_at_unix_ms,
        )
        .expect("construct canonical substituted desktop lease");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-substituted-lease".into(),
            idempotency_key: idempotency_key.into(),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(substituted_lease),
            causation_event_id: None,
            correlation_id: "correlation-substituted-lease".into(),
            kind: EffectKind::ReadRelativeFile,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: harness.policy.contract().policy_hash.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            created_at_unix_ms: client.session().registered_at_unix_ms + 1,
        };
        assert!(
            client
                .validate_effect_request(
                    &intent,
                    &request_bytes,
                    &RunnerRequest::WorkerReadFile {
                        path: "README.md".into(),
                        max_bytes: 1_024,
                    },
                )
                .is_err()
        );
        client.shutdown().expect("shutdown untouched test session");
    }

    #[test]
    fn precommitted_effect_dispatches_once_without_a_second_intent_write() {
        let (harness, mut ledger) = TestHarness::new("precommitted-once");
        let expected_bytes =
            fs::read(harness.workspace.join("README.md")).expect("read fixture bytes");
        let exchange_count = Rc::new(Cell::new(0));
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("precommitted-once"),
            transport_with_exchange_count(
                unique_nonce("precommitted-once"),
                harness.identity(),
                ScriptMode::Good,
                true,
                expected_bytes.clone(),
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize counted precommitted worker");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let (persisted, permit, intent, request_bytes, request) =
            precommit_worker_read(&harness, &mut ledger, &client, "once");
        let next_sequence_after_commit = ledger
            .next_sequence(&harness.sprint_id)
            .expect("read sequence after fresh commit");
        assert_eq!(exchange_count.get(), 1);

        let (client, exchange) = client
            .send_precommitted_effect(&mut ledger, permit, &intent, &request_bytes, request)
            .expect("transport the already committed read exactly once");

        assert_eq!(exchange_count.get(), 2);
        let claimed = ledger
            .load_effect(&intent.effect_id)
            .expect("reload exact claimed precommitted effect");
        assert_eq!(claimed.intent, persisted.intent);
        assert_eq!(claimed.request_bytes, persisted.request_bytes);
        assert_eq!(claimed.proposed_event, persisted.proposed_event);
        assert!(claimed.observation.is_none());
        let claim = claimed
            .dispatch_claim
            .as_ref()
            .expect("transport commits one immutable dispatch claim");
        assert_eq!(
            claim.opaque_transport_request_digest,
            Digest::sha256(
                &encode_request_frame(&exchange.exchange().request)
                    .expect("re-encode exact claimed runner frame")
            )
        );
        assert_eq!(
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("read sequence after transport"),
            next_sequence_after_commit
        );
        assert!(matches!(
            exchange.exchange().response.response,
            RunnerResponse::FileRead { ref bytes, .. } if bytes == &expected_bytes
        ));
        client.shutdown().expect("shutdown precommitted worker");
        assert_eq!(exchange_count.get(), 3);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression matrix exact-compares byte progress, claim evidence, cleanup, authority, and durable outcomes"
    )]
    fn claimed_effect_write_progress_maps_only_zero_bytes_to_failed_before_effect() {
        let cases = [
            ("zero", ScriptWriteProgress::None, 0_usize, true),
            ("one", ScriptWriteProgress::One, 1, false),
            (
                "all-but-one",
                ScriptWriteProgress::AllButOne,
                usize::MAX,
                false,
            ),
            ("all", ScriptWriteProgress::All, usize::MAX, false),
        ];
        for (label, scripted_progress, fixed_expected, failed_before_effect) in cases {
            let fixture_label = format!("claimed-write-progress-{label}");
            let (harness, mut ledger) = TestHarness::new(&fixture_label);
            let mut client = RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                harness.launch(&fixture_label),
                transport(
                    unique_nonce(&fixture_label),
                    harness.identity(),
                    ScriptMode::WriteFailureAt(1, scripted_progress),
                    true,
                    Vec::new(),
                ),
            )
            .expect("initialize write-progress worker");
            client.shadow_created = true;
            client.shadow_snapshot = Some(harness.base_snapshot.clone());
            let (persisted, permit, intent, request_bytes, request) =
                precommit_worker_read(&harness, &mut ledger, &client, label);

            let failure = expect_effect_session_failure(
                client.send_precommitted_effect(
                    &mut ledger,
                    permit,
                    &intent,
                    &request_bytes,
                    request,
                ),
                "scripted write failure must consume the claimed session",
            );
            assert!(
                matches!(failure.error(), RunnerClientError::Io(error) if error.kind() == io::ErrorKind::TimedOut)
            );
            assert!(failure.claimed_effect().is_some());
            let (_error, cleanup, claimed_failure) = failure.into_parts();
            assert_eq!(
                cleanup
                    .session()
                    .expect("claimed failure cleanup retains registered session")
                    .sprint_id,
                harness.sprint_id
            );
            let claimed_failure = claimed_failure.expect("post-claim failure retains authority");
            assert!(claimed_failure.exchange().is_none());
            let evidence_value: serde_json::Value =
                serde_json::from_slice(claimed_failure.evidence_bytes())
                    .expect("decode canonical claimed failure evidence");
            let total = usize::try_from(
                evidence_value["request_frame_bytes"]
                    .as_u64()
                    .expect("frame byte count"),
            )
            .expect("bounded frame length");
            let expected_written = match scripted_progress {
                ScriptWriteProgress::None | ScriptWriteProgress::One => fixed_expected,
                ScriptWriteProgress::AllButOne => total - 1,
                ScriptWriteProgress::All => total,
            };
            assert_eq!(
                evidence_value["accepted_request_bytes"].as_u64(),
                Some(u64::try_from(expected_written).expect("bounded accepted count"))
            );
            assert_eq!(
                evidence_value["dispatch_claim_id"].as_str(),
                ledger
                    .load_effect(&intent.effect_id)
                    .expect("reload claimed effect")
                    .dispatch_claim
                    .as_ref()
                    .map(|claim| claim.dispatch_claim_id.as_str())
            );
            let (phase, _exchange, evidence, _claimed_effect, observation_authority) =
                claimed_failure.into_parts();
            match phase {
                RunnerEffectFailurePhase::NoRequestBytesWritten => {
                    assert!(failed_before_effect);
                    assert_eq!(expected_written, 0);
                }
                RunnerEffectFailurePhase::RequestWriteStarted {
                    written_request_bytes,
                    total_request_bytes,
                } => {
                    assert!(!failed_before_effect);
                    assert_eq!(written_request_bytes.get(), expected_written);
                    assert_eq!(total_request_bytes.get(), total);
                }
                RunnerEffectFailurePhase::CorrelatedResponseRejected => {
                    panic!("write failure cannot retain a correlated response")
                }
            }
            let outcome = if failed_before_effect {
                EffectOutcome::FailedBeforeEffect {
                    evidence_digest: Digest::sha256(&evidence),
                }
            } else {
                EffectOutcome::Unknown {
                    evidence_digest: Digest::sha256(&evidence),
                }
            };
            let observation = observation(
                &intent,
                format!("observation-{label}"),
                outcome.clone(),
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
                    &evidence,
                    &terminal,
                )
                .expect("persist exact phase-bound claimed failure evidence");
            assert_eq!(
                completed.observation.as_ref().map(|value| &value.outcome),
                Some(&outcome)
            );
            assert_eq!(
                completed.evidence_bytes.as_deref(),
                Some(evidence.as_slice())
            );
        }
    }

    #[test]
    fn claimed_effect_response_failures_distinguish_ambiguity_from_semantic_rejection() {
        let cases = [
            ("full-eof", ScriptMode::EofAt(1), false),
            ("uncorrelated", ScriptMode::UncorrelatedAt(1), false),
            (
                "semantic-rejection",
                ScriptMode::SemanticRejectionAt(1),
                true,
            ),
        ];
        for (label, mode, correlated_rejection) in cases {
            let fixture_label = format!("claimed-response-failure-{label}");
            let (harness, mut ledger) = TestHarness::new(&fixture_label);
            let mut client = RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                harness.launch(&fixture_label),
                transport(
                    unique_nonce(&fixture_label),
                    harness.identity(),
                    mode,
                    true,
                    b"response bytes".to_vec(),
                ),
            )
            .expect("initialize response-failure worker");
            client.shadow_created = true;
            client.shadow_snapshot = Some(harness.base_snapshot.clone());
            let (_persisted, permit, intent, request_bytes, request) =
                precommit_worker_read(&harness, &mut ledger, &client, label);
            let failure = expect_effect_session_failure(
                client.send_precommitted_effect(
                    &mut ledger,
                    permit,
                    &intent,
                    &request_bytes,
                    request,
                ),
                "response failure must retain claimed authority",
            );
            let (_error, cleanup, claimed_failure) = failure.into_parts();
            assert!(cleanup.session().is_some());
            let claimed_failure = claimed_failure.expect("failure occurred after claim validation");
            let evidence: serde_json::Value =
                serde_json::from_slice(claimed_failure.evidence_bytes())
                    .expect("decode response failure evidence");
            if correlated_rejection {
                assert_eq!(
                    claimed_failure.phase(),
                    RunnerEffectFailurePhase::CorrelatedResponseRejected
                );
                assert!(claimed_failure.exchange().is_some());
                assert!(
                    evidence["correlated_response_frame_digest"]
                        .as_str()
                        .is_some()
                );
            } else {
                assert!(matches!(
                    claimed_failure.phase(),
                    RunnerEffectFailurePhase::RequestWriteStarted {
                        written_request_bytes,
                        total_request_bytes,
                    } if written_request_bytes == total_request_bytes
                ));
                assert!(claimed_failure.exchange().is_none());
                assert!(evidence["correlated_response_frame_digest"].is_null());
            }
        }
    }

    #[test]
    fn correlated_typed_before_effect_failure_is_a_normal_claimed_response() {
        let (harness, mut ledger) = TestHarness::new("typed-before-effect-normal");
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("typed-before-effect-normal"),
            transport(
                unique_nonce("typed-before-effect-normal"),
                harness.identity(),
                ScriptMode::BeforeEffectAt(1),
                true,
                Vec::new(),
            ),
        )
        .expect("initialize typed-refusal worker");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let (_persisted, permit, intent, request_bytes, request) =
            precommit_worker_read(&harness, &mut ledger, &client, "typed-normal");
        let (_client, claimed) = client
            .send_precommitted_effect(&mut ledger, permit, &intent, &request_bytes, request)
            .expect("typed BeforeEffect is a correlated normal response");
        assert!(matches!(
            claimed.exchange().response.response,
            RunnerResponse::Failed {
                class: WireFailureClass::BeforeEffect,
                reconciliation: None,
                ..
            }
        ));
    }

    #[test]
    fn response_stream_and_sequence_are_prechecked_before_dispatch_claim() {
        for (label, mode, overflow_sequence) in [
            (
                "missing-response-stream",
                ScriptMode::MissingResponseStream,
                false,
            ),
            ("sequence-overflow", ScriptMode::Good, true),
        ] {
            let fixture_label = format!("effect-precheck-{label}");
            let (harness, mut ledger) = TestHarness::new(&fixture_label);
            let exchange_count = Rc::new(Cell::new(0));
            let mut client = RunnerLifecycleClient::launch_with_spawner(
                &mut ledger,
                &harness.authority,
                &harness.policy,
                harness.launch(&fixture_label),
                transport_with_exchange_count(
                    unique_nonce(&fixture_label),
                    harness.identity(),
                    mode,
                    true,
                    Vec::new(),
                    Rc::clone(&exchange_count),
                ),
            )
            .expect("initialize precheck worker");
            client.shadow_created = true;
            client.shadow_snapshot = Some(harness.base_snapshot.clone());
            if overflow_sequence {
                client.next_sequence = u64::MAX;
            }
            let (_persisted, permit, intent, request_bytes, request) =
                precommit_worker_read(&harness, &mut ledger, &client, label);
            let failure = expect_effect_session_failure(
                client.send_precommitted_effect(
                    &mut ledger,
                    permit,
                    &intent,
                    &request_bytes,
                    request,
                ),
                "effect precheck must consume client before claim",
            );
            assert!(failure.claimed_effect().is_none());
            let (_error, cleanup, claimed_effect) = failure.into_parts();
            assert!(cleanup.session().is_some());
            assert!(claimed_effect.is_none());
            assert_eq!(exchange_count.get(), 1);
            assert!(
                ledger
                    .load_effect(&intent.effect_id)
                    .expect("reload prechecked pristine effect")
                    .dispatch_claim
                    .is_none()
            );
        }
    }

    #[test]
    fn precommitted_effect_refuses_stale_permit_after_competing_terminal_observation() {
        let (harness, mut ledger) = TestHarness::new("precommitted-stale-permit");
        let exchange_count = Rc::new(Cell::new(0));
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("precommitted-stale-permit"),
            transport_with_exchange_count(
                unique_nonce("precommitted-stale-permit"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize stale-permit worker");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let (persisted, permit, intent, request_bytes, request) =
            precommit_worker_read(&harness, &mut ledger, &client, "stale-permit");

        let evidence = b"competing terminal reconciliation";
        let observation = observation(
            &intent,
            "observation-precommitted-stale-permit",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: Digest::sha256(evidence),
            },
            intent.created_at_unix_ms + 1,
        );
        let mut competing = EventLedger::open(&harness.database)
            .expect("open independent competing ledger connection");
        let terminal = terminal_event(
            &competing,
            &intent,
            &persisted.proposed_event.event_id,
            &observation,
        );
        competing
            .record_effect_observation(&observation, evidence, &terminal)
            .expect("competing connection terminalizes before dispatch claim");

        let failure = expect_effect_session_failure(
            client.send_precommitted_effect(&mut ledger, permit, &intent, &request_bytes, request),
            "stale permit must fail before transport after competing terminalization",
        );
        assert!(matches!(failure.error(), RunnerClientError::Ledger(_)));
        assert_eq!(exchange_count.get(), 1);
        let terminalized = ledger
            .load_effect(&intent.effect_id)
            .expect("reload competing terminal observation");
        assert_eq!(terminalized.observation.as_ref(), Some(&observation));
        assert!(terminalized.dispatch_claim.is_none());
    }

    #[test]
    fn precommitted_effect_rejects_same_kind_wire_substitution_before_transport() {
        let (harness, mut ledger) = TestHarness::new("precommitted-request-cross");
        let exchange_count = Rc::new(Cell::new(0));
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("precommitted-request-cross"),
            transport_with_exchange_count(
                unique_nonce("precommitted-request-cross"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize request-cross worker");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let (_, permit, intent, request_bytes, _) =
            precommit_worker_read(&harness, &mut ledger, &client, "request-cross");

        let failure = expect_effect_session_failure(
            client.send_precommitted_effect(
                &mut ledger,
                permit,
                &intent,
                &request_bytes,
                RunnerRequest::WorkerReadFile {
                    path: "DIFFERENT.md".into(),
                    max_bytes: 2_048,
                },
            ),
            "same-kind wire substitution must consume the client before transport",
        );
        assert!(matches!(
            failure.error(),
            RunnerClientError::InvalidLifecycle(message)
                if message.contains("exact canonical provider tool call")
        ));
        assert_eq!(exchange_count.get(), 1);
    }

    #[test]
    fn precommitted_effect_rejects_crossed_session_before_transport() {
        let (harness, mut ledger) = TestHarness::new("precommitted-session-cross");
        let exchange_count = Rc::new(Cell::new(0));
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("precommitted-session-cross"),
            transport_with_exchange_count(
                unique_nonce("precommitted-session-cross"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize session-cross worker");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let (_, permit, intent, request_bytes, request) =
            precommit_worker_read(&harness, &mut ledger, &client, "session-cross");
        client.session.session_id = "crossed-session-precommitted".into();

        let failure = expect_effect_session_failure(
            client.send_precommitted_effect(&mut ledger, permit, &intent, &request_bytes, request),
            "crossed session must consume the client before transport",
        );
        assert!(matches!(failure.error(), RunnerClientError::Ledger(_)));
        assert_eq!(exchange_count.get(), 1);
    }

    #[test]
    fn precommitted_effect_rejects_crossed_lease_before_transport() {
        let (harness, mut ledger) = TestHarness::new("precommitted-lease-cross");
        let exchange_count = Rc::new(Cell::new(0));
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("precommitted-lease-cross"),
            transport_with_exchange_count(
                unique_nonce("precommitted-lease-cross"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize lease-cross worker");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let (_, permit, intent, request_bytes, request) =
            precommit_worker_read(&harness, &mut ledger, &client, "lease-cross");
        let crossed_lease = WorkerLease::new(
            harness.sprint_id.clone(),
            harness.worker_lease.lease_epoch + 1,
            "task-1".into(),
            "worker-1".into(),
            harness.worker_lease.path_scopes.clone(),
            harness.worker_lease.acquired_at_unix_ms,
        )
        .expect("construct canonical crossed lease");
        let mut crossed_intent = intent;
        // The crossed intent is internally consistent — its lease-scoped
        // idempotency key derives from the crossed lease — so the desktop's own
        // provider-call validation admits it and the durable claim stays the
        // authority that refuses the substitution.
        crossed_intent.idempotency_key = task_lease_provider_call_effect_key(
            &crossed_lease.lease_id,
            "key-precommitted-read-lease-cross",
        );
        crossed_intent.worker_lease = Some(crossed_lease.clone());
        client.launch.worker_lease = Some(crossed_lease.clone());
        client.session.worker_lease = Some(crossed_lease);

        let failure = expect_effect_session_failure(
            client.send_precommitted_effect(
                &mut ledger,
                permit,
                &crossed_intent,
                &request_bytes,
                request,
            ),
            "crossed lease must consume the client before transport",
        );
        assert!(matches!(failure.error(), RunnerClientError::Ledger(_)));
        assert_eq!(exchange_count.get(), 1);
    }

    #[test]
    fn precommitted_command_is_refused_before_transport() {
        let (harness, mut ledger) = TestHarness::new("precommitted-command-disabled");
        let exchange_count = Rc::new(Cell::new(0));
        let mut client = RunnerLifecycleClient::launch_with_spawner(
            &mut ledger,
            &harness.authority,
            &harness.policy,
            harness.launch("precommitted-command-disabled"),
            transport_with_exchange_count(
                unique_nonce("precommitted-command-disabled"),
                harness.identity(),
                ScriptMode::Good,
                true,
                Vec::new(),
                Rc::clone(&exchange_count),
            ),
        )
        .expect("initialize command-disabled worker");
        client.shadow_created = true;
        client.shadow_snapshot = Some(harness.base_snapshot.clone());
        let (persisted, permit, intent, request_bytes, _) =
            precommit_worker_read(&harness, &mut ledger, &client, "command-disabled");
        let command = CommandSpec {
            program: "true".into(),
            arguments: Vec::new(),
            working_directory: PathBuf::new(),
        };
        let command_bytes = serde_json::to_vec(&command).expect("encode core command request");
        let capture_effect = EffectIntent {
            effect_id: Digest::sha256(b"request-only precommitted command capture")
                .as_str()
                .to_owned(),
            idempotency_key: "request-only-precommitted-command-key".into(),
            correlation_id: "request-only-precommitted-command-correlation".into(),
            kind: EffectKind::RunCommand,
            request_digest: Digest::sha256(&command_bytes),
            ..intent.clone()
        };
        let capture_intent = fresh_command_output_capture_intent(
            &capture_effect,
            &client.launch,
            &client.session,
            &harness.policy,
        )
        .expect("construct request-only command capture intent");
        let store = CapabilityCommandOutputStore::open(&harness.private_state)
            .expect("open private command store");
        let dispatch_claim_id = grok_build_core::current_final_verification_dispatch_claim_id(
            &capture_effect.effect_id,
        )
        .expect("derive request-only command dispatch claim");
        let acquired = store
            .reserve_anchored_capture(
                &capture_intent,
                &dispatch_claim_id,
                capture_effect.created_at_unix_ms,
            )
            .expect("reserve request-only command capture")
            .into_acquired_anchor_for_handoff()
            .expect("synchronize request-only command capture");
        let wire_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired)
            .expect("construct exact request-only wire capture");

        let failure = expect_effect_session_failure(
            client.send_precommitted_effect(
                &mut ledger,
                permit,
                &intent,
                &request_bytes,
                RunnerRequest::WorkerRunCommand {
                    command: WireCommandSpec {
                        program: command.program,
                        arguments: command.arguments,
                        working_directory: String::new(),
                    },
                    output_capture: wire_capture,
                },
            ),
            "precommitted v11 command must fail before its dispatch claim",
        );
        assert!(matches!(
            failure.error(),
            RunnerClientError::InvalidLifecycle(message)
                if message.contains("additive-v12 command boundary")
        ));
        assert_eq!(
            exchange_count.get(),
            1,
            "only initialization may cross transport"
        );
        let readback = ledger
            .load_effect(&intent.effect_id)
            .expect("precommitted noncommand intent remains readable");
        assert_eq!(readback, persisted);
        assert!(readback.dispatch_claim.is_none());
        assert!(readback.observation.is_none());
        assert!(
            ledger
                .load_command_output_capture_for_effect(&intent.effect_id)
                .is_err()
        );
    }
