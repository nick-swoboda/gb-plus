    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the launch restart matrix keeps canonical parsing and every independent authority substitution in one auditable proof"
    )]
    fn contained_capture_launch_restart_decoder_binds_every_authority() {
        let command = WireCommandSpec {
            program: "/usr/bin/true".into(),
            arguments: Vec::new(),
            working_directory: String::new(),
        };
        let request = effect_request(
            "request-launch-restart-decode",
            1,
            worker_command_request(1, command.clone()),
        );
        let request_effect = request.effect.as_ref().expect("effect request");
        let RunnerRequest::WorkerRunCommand { output_capture, .. } = &request.request else {
            unreachable!()
        };
        let acquired = output_capture.acquired();
        let grant_hash = digest(70);
        let authority = test_command_effect_authority(&request, &grant_hash)
            .expect("command authority fixture")
            .expect("worker command authority");
        let authority_digest = Digest::sha256(
            &serde_json::to_vec(&authority).expect("canonical command authority bytes"),
        );
        let effect = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: request_effect.effect_id.clone(),
            idempotency_key: request_effect.idempotency_key.clone(),
            sprint_id: request_effect.sprint_id.clone(),
            task_id: request_effect.task_id.clone(),
            worker_id: request_effect.worker_id.clone(),
            worker_lease: request_effect.worker_lease.clone(),
            causation_event_id: Some("event-launch-restart".into()),
            correlation_id: "correlation-launch-restart".into(),
            kind: EffectKind::RunCommand,
            request_digest: request_effect.request_digest.clone(),
            policy_hash: request_effect.policy_hash.clone(),
            input_snapshot: request_effect.input_snapshot.clone(),
            created_at_unix_ms: 2,
        };
        let session = RunnerSessionPolicyRecord {
            contract_version: CONTRACT_VERSION,
            sprint_id: request_effect.sprint_id.clone(),
            launch_id: request_effect.launch_id.clone(),
            session_id: request.session_id.clone(),
            purpose: RunnerSessionPurpose::TaskWorker,
            worker_id: request_effect.worker_id.clone(),
            worker_lease: request_effect.worker_lease.clone(),
            policy_hash: request_effect.policy_hash.clone(),
            session_nonce: request.runner_nonce.clone().expect("runner nonce"),
            runner_binary_digest: digest(71),
            protocol_digest: digest(72),
            private_state_digest: acquired.private_state_digest.clone(),
            grant_hash: grant_hash.clone(),
            policy_version: 1,
            registered_at_unix_ms: 2,
        };
        let running_boundary_id = "running-boundary-launch-restart".to_string();
        let dispatch_claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: acquired.dispatch_claim_id.clone(),
            effect_id: request_effect.effect_id.clone(),
            sprint_id: request_effect.sprint_id.clone(),
            launch_id: request_effect.launch_id.clone(),
            session_id: request.session_id.clone(),
            running_boundary_id: Some(running_boundary_id.clone()),
            authority: RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id,
            },
            request_digest: request_effect.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(
                &encode_request_frame(&request).expect("canonical request frame"),
            ),
            policy_hash: request_effect.policy_hash.clone(),
            input_snapshot: request_effect.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        let binding = DecodedContainedCaptureLaunchBinding {
            schema_version: 1,
            command_effect_authority_digest: authority_digest,
            role: RunnerRole::Worker,
            grant_hash: grant_hash.clone(),
            runner_session_id: request.session_id.clone(),
            runner_nonce: request.runner_nonce.clone(),
            request_sequence: request.sequence,
            request_id: request.request_id.clone(),
            effect_contract_version: request_effect.contract_version,
            runner_launch_id: request_effect.launch_id.clone(),
            effect_id: request_effect.effect_id.clone(),
            idempotency_key: request_effect.idempotency_key.clone(),
            sprint_id: request_effect.sprint_id.clone(),
            task_id: request_effect.task_id.clone(),
            worker_id: request_effect.worker_id.clone(),
            policy_hash: request_effect.policy_hash.clone(),
            input_snapshot: request_effect.input_snapshot.clone(),
            command_request_digest: request_effect.request_digest.clone(),
            transport_commitment_digest: request_effect.transport_commitment_digest.clone(),
            capture_id: acquired.capture_id.clone(),
            capture_intent_digest: acquired.intent_digest.clone(),
            capture_acquired_anchor_digest: acquired.acquired_anchor_digest.clone(),
            capture_acquired_store_head: acquired.store_head.clone(),
            capture_dispatch_claim_id: acquired.dispatch_claim_id.clone(),
            capture_private_state_digest: acquired.private_state_digest.clone(),
            capture_max_aggregate_output_bytes: acquired.max_aggregate_output_bytes,
            launch_digest: digest(73),
            preflight_digest: digest(74),
            command_domain_backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            backend_id: "linux-cgroup-v2-launch-restart".into(),
            backend_implementation_digest: digest(75),
            closed_exec_descriptors: [0, 1, 2],
        };
        let bytes = serde_json::to_vec(&binding).expect("canonical launch binding");
        let launch_head = CommandOutputCaptureStoreHeadV1 {
            generation: acquired.store_head.generation + 2,
            record_digest: digest(76),
        };
        let decoded = decode_contained_capture_launch_binding(
            &bytes,
            &launch_head,
            &effect,
            &dispatch_claim,
            &session,
            &command,
            output_capture,
            &grant_hash,
        )
        .expect("strict launch restart decode");
        assert_eq!(decoded.request(), &request);
        assert_eq!(decoded.launch_intended_store_head(), &launch_head);
        assert_eq!(decoded.canonical_bytes_digest(), &Digest::sha256(&bytes));
        assert_eq!(decoded.launch_digest(), &binding.launch_digest);
        assert_eq!(decoded.preflight_digest(), &binding.preflight_digest);
        assert_eq!(
            decoded.backend().command_domain_backend,
            binding.command_domain_backend
        );
        assert_eq!(
            decoded.command_domain_binding().command_effect_id(),
            effect.effect_id
        );
        assert_eq!(decoded.closed_exec_descriptors(), &[0, 1, 2]);

        assert!(matches!(
            decode_contained_capture_launch_binding(
                &bytes[..bytes.len() - 1],
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                output_capture,
                &grant_hash,
            ),
            Err(WireProtocolError::InvalidJson(_))
        ));
        let mut extra = bytes[..bytes.len() - 1].to_vec();
        extra.extend_from_slice(b",\"unknown\":true}");
        assert!(matches!(
            decode_contained_capture_launch_binding(
                &extra,
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                output_capture,
                &grant_hash,
            ),
            Err(WireProtocolError::InvalidJson(_))
        ));
        let mut noncanonical = bytes.clone();
        noncanonical.insert(1, b' ');
        assert!(matches!(
            decode_contained_capture_launch_binding(
                &noncanonical,
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                output_capture,
                &grant_hash,
            ),
            Err(WireProtocolError::NonCanonical)
        ));

        let mut substituted = binding;
        substituted.capture_id = digest(77).as_str().to_owned();
        let substituted = serde_json::to_vec(&substituted).expect("canonical substitution");
        assert!(
            decode_contained_capture_launch_binding(
                &substituted,
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                output_capture,
                &grant_hash,
            )
            .is_err()
        );

        let stale_head = CommandOutputCaptureStoreHeadV1 {
            generation: acquired.store_head.generation + 1,
            record_digest: digest(78),
        };
        assert!(
            decode_contained_capture_launch_binding(
                &bytes,
                &stale_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                output_capture,
                &grant_hash,
            )
            .is_err()
        );

        let mut crossed_command = command.clone();
        crossed_command.arguments.push("crossed".into());
        assert!(
            decode_contained_capture_launch_binding(
                &bytes,
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &crossed_command,
                output_capture,
                &grant_hash,
            )
            .is_err()
        );

        let other_request = effect_request(
            "request-launch-restart-other-acquired",
            2,
            worker_command_request(2, command.clone()),
        );
        let RunnerRequest::WorkerRunCommand {
            output_capture: other_capture,
            ..
        } = &other_request.request
        else {
            unreachable!()
        };
        assert!(
            decode_contained_capture_launch_binding(
                &bytes,
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                other_capture,
                &grant_hash,
            )
            .is_err()
        );

        assert!(
            decode_contained_capture_launch_binding(
                &bytes,
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                output_capture,
                &digest(79),
            )
            .is_err()
        );

        let mut malformed_backend: DecodedContainedCaptureLaunchBinding =
            serde_json::from_slice(&bytes).expect("decode backend substitution");
        malformed_backend.closed_exec_descriptors = [0, 1, 3];
        let malformed_backend =
            serde_json::to_vec(&malformed_backend).expect("encode backend substitution");
        assert!(
            decode_contained_capture_launch_binding(
                &malformed_backend,
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                output_capture,
                &grant_hash,
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the v12 restart proof keeps policy, frame, launch authority, and no-fallback negatives adjacent"
    )]
    fn contained_capture_launch_v12_restart_binds_policy_and_exact_frame_without_fallback() {
        let command = WireCommandSpec {
            program: "/usr/bin/true".into(),
            arguments: Vec::new(),
            working_directory: String::new(),
        };
        let request = effect_request_v12(
            "request-launch-v12-restart-decode",
            1,
            worker_command_request(1, command.clone()),
        );
        let request_effect = &request.effect;
        let RunnerRequest::WorkerRunCommand { output_capture, .. } =
            request.request.command_request()
        else {
            unreachable!()
        };
        let acquired = output_capture.acquired();
        let detector_policy = request.detector_policy().clone();
        let grant_hash = digest(80);
        let authority = CommandEffectAuthorityV2 {
            schema_version: COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION,
            contract_version: CONTRACT_VERSION,
            grant_hash: grant_hash.clone(),
            role: RunnerRole::Worker,
            envelope: request.clone(),
        };
        authority
            .validate_integrity()
            .expect("v12 command authority fixture");
        let authority_digest = Digest::sha256(
            &serde_json::to_vec(&authority).expect("canonical v12 command authority bytes"),
        );
        let effect = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: request_effect.effect_id.clone(),
            idempotency_key: request_effect.idempotency_key.clone(),
            sprint_id: request_effect.sprint_id.clone(),
            task_id: request_effect.task_id.clone(),
            worker_id: request_effect.worker_id.clone(),
            worker_lease: request_effect.worker_lease.clone(),
            causation_event_id: Some("event-launch-v12-restart".into()),
            correlation_id: "correlation-launch-v12-restart".into(),
            kind: EffectKind::RunCommand,
            request_digest: request_effect.request_digest.clone(),
            policy_hash: request_effect.policy_hash.clone(),
            input_snapshot: request_effect.input_snapshot.clone(),
            created_at_unix_ms: 2,
        };
        let session = RunnerSessionPolicyRecord {
            contract_version: CONTRACT_VERSION,
            sprint_id: request_effect.sprint_id.clone(),
            launch_id: request_effect.launch_id.clone(),
            session_id: request.session_id.clone(),
            purpose: RunnerSessionPurpose::TaskWorker,
            worker_id: request_effect.worker_id.clone(),
            worker_lease: request_effect.worker_lease.clone(),
            policy_hash: request_effect.policy_hash.clone(),
            session_nonce: request.runner_nonce.clone(),
            runner_binary_digest: digest(81),
            protocol_digest: digest(82),
            private_state_digest: acquired.private_state_digest.clone(),
            grant_hash: grant_hash.clone(),
            policy_version: 1,
            registered_at_unix_ms: 2,
        };
        let running_boundary_id = "running-boundary-launch-v12-restart".to_string();
        let dispatch_claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: acquired.dispatch_claim_id.clone(),
            effect_id: request_effect.effect_id.clone(),
            sprint_id: request_effect.sprint_id.clone(),
            launch_id: request_effect.launch_id.clone(),
            session_id: request.session_id.clone(),
            running_boundary_id: Some(running_boundary_id.clone()),
            authority: RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id,
            },
            request_digest: request_effect.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(
                &encode_request_frame_v12(&request).expect("canonical v12 request frame"),
            ),
            policy_hash: request_effect.policy_hash.clone(),
            input_snapshot: request_effect.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        let binding = DecodedContainedCaptureLaunchBinding {
            schema_version: 1,
            command_effect_authority_digest: authority_digest,
            role: RunnerRole::Worker,
            grant_hash: grant_hash.clone(),
            runner_session_id: request.session_id.clone(),
            runner_nonce: Some(request.runner_nonce.clone()),
            request_sequence: request.sequence,
            request_id: request.request_id.clone(),
            effect_contract_version: request_effect.contract_version,
            runner_launch_id: request_effect.launch_id.clone(),
            effect_id: request_effect.effect_id.clone(),
            idempotency_key: request_effect.idempotency_key.clone(),
            sprint_id: request_effect.sprint_id.clone(),
            task_id: request_effect.task_id.clone(),
            worker_id: request_effect.worker_id.clone(),
            policy_hash: request_effect.policy_hash.clone(),
            input_snapshot: request_effect.input_snapshot.clone(),
            command_request_digest: request_effect.request_digest.clone(),
            transport_commitment_digest: request_effect.transport_commitment_digest.clone(),
            capture_id: acquired.capture_id.clone(),
            capture_intent_digest: acquired.intent_digest.clone(),
            capture_acquired_anchor_digest: acquired.acquired_anchor_digest.clone(),
            capture_acquired_store_head: acquired.store_head.clone(),
            capture_dispatch_claim_id: acquired.dispatch_claim_id.clone(),
            capture_private_state_digest: acquired.private_state_digest.clone(),
            capture_max_aggregate_output_bytes: acquired.max_aggregate_output_bytes,
            launch_digest: digest(83),
            preflight_digest: digest(84),
            command_domain_backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            backend_id: "linux-cgroup-v2-launch-v12-restart".into(),
            backend_implementation_digest: digest(85),
            closed_exec_descriptors: [0, 1, 2],
        };
        let bytes = serde_json::to_vec(&binding).expect("canonical v12 launch binding");
        let launch_head = CommandOutputCaptureStoreHeadV1 {
            generation: acquired.store_head.generation + 2,
            record_digest: digest(86),
        };
        let decoded = decode_contained_capture_launch_binding_v12(
            &bytes,
            &launch_head,
            &effect,
            &dispatch_claim,
            &session,
            &command,
            output_capture,
            &detector_policy,
            &grant_hash,
        )
        .expect("strict v12 launch restart decode");
        assert_eq!(decoded.request(), &request);
        assert_eq!(decoded.launch_intended_store_head(), &launch_head);
        assert_eq!(decoded.canonical_bytes_digest(), &Digest::sha256(&bytes));
        assert_eq!(decoded.launch_digest(), &binding.launch_digest);
        assert_eq!(decoded.preflight_digest(), &binding.preflight_digest);
        assert_eq!(decoded.closed_exec_descriptors(), &[0, 1, 2]);

        let mut crossed_policy = detector_policy.clone();
        crossed_policy.policy_id.push_str("-crossed");
        assert!(
            decode_contained_capture_launch_binding_v12(
                &bytes,
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                output_capture,
                &crossed_policy,
                &grant_hash,
            )
            .is_err()
        );

        let mut crossed_claim = dispatch_claim.clone();
        crossed_claim.opaque_transport_request_digest = digest(87);
        assert!(
            decode_contained_capture_launch_binding_v12(
                &bytes,
                &launch_head,
                &effect,
                &crossed_claim,
                &session,
                &command,
                output_capture,
                &detector_policy,
                &grant_hash,
            )
            .is_err()
        );

        assert!(
            decode_contained_capture_launch_binding(
                &bytes,
                &launch_head,
                &effect,
                &dispatch_claim,
                &session,
                &command,
                output_capture,
                &grant_hash,
            )
            .is_err(),
            "v12 launch authority must never fall back to the v11 decoder"
        );
    }

    #[test]
    fn wire_v11_command_capture_reconciliation_is_path_free_and_request_exact() {
        let request = effect_request(
            "request-capture-reconciliation",
            1,
            worker_command_request(
                1,
                WireCommandSpec {
                    program: "/usr/bin/true".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
            ),
        );
        let acquired = match &request.request {
            RunnerRequest::WorkerRunCommand { output_capture, .. } => output_capture.acquired(),
            _ => unreachable!(),
        };
        let reference = WireReconciliationReference::CommandOutputCapture {
            capture_id: acquired.capture_id.clone(),
            acquired_anchor_digest: acquired.acquired_anchor_digest.clone(),
            last_known_store_head: acquired.store_head.clone(),
            expected_output_artifacts: None,
        };
        let response = response_for(
            &request,
            RunnerResponse::failed_requiring_reconciliation(
                "capture_reconciliation",
                reference.clone(),
                "exact capture journal requires readback",
            ),
        );
        response
            .validate_correlation(&request)
            .expect("exact capture reconciliation correlates");
        let encoded = serde_json::to_string(&reference).expect("encode reconciliation reference");
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains("path"));

        let mut crossed_id = reference.clone();
        let WireReconciliationReference::CommandOutputCapture { capture_id, .. } = &mut crossed_id
        else {
            unreachable!()
        };
        *capture_id = digest(94).as_str().to_owned();
        let crossed_id = response_for(
            &request,
            RunnerResponse::failed_requiring_reconciliation(
                "capture_reconciliation",
                crossed_id,
                "crossed capture",
            ),
        );
        assert!(crossed_id.validate_correlation(&request).is_err());

        let mut crossed_head = reference;
        let WireReconciliationReference::CommandOutputCapture {
            last_known_store_head,
            ..
        } = &mut crossed_head
        else {
            unreachable!()
        };
        last_known_store_head.record_digest = digest(95);
        let crossed_head = response_for(
            &request,
            RunnerResponse::failed_requiring_reconciliation(
                "capture_reconciliation",
                crossed_head,
                "crossed same-generation head",
            ),
        );
        assert!(crossed_head.validate_correlation(&request).is_err());
    }

    #[test]
    fn command_output_capture_maximum_has_exact_closed_bounds() {
        assert_eq!(
            COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES,
            COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES_V1
        );
        assert_eq!(
            MAX_COMMAND_OUTPUT_ARTIFACT_BYTES,
            grok_build_core::MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES
        );
        assert!(command_output_capture_maximum(0).is_err());
        let largest_policy =
            MAX_COMMAND_OUTPUT_ARTIFACT_BYTES - COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES;
        assert_eq!(
            command_output_capture_maximum(largest_policy).expect("exact store ceiling"),
            MAX_COMMAND_OUTPUT_ARTIFACT_BYTES
        );
        assert_eq!(
            command_output_capture_maximum(largest_policy).expect("runner delegation"),
            current_command_output_capture_maximum_v1(largest_policy)
                .expect("core authority formula")
        );
        assert!(command_output_capture_maximum(largest_policy + 1).is_err());
        assert!(command_output_capture_maximum(u64::MAX).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the core/runner parity table enumerates every current direct-exec boundary"
    )]
    fn runner_command_validation_delegates_to_exact_current_core_boundary() {
        let admitted = WireCommandSpec {
            program: "/usr/bin/cargo".into(),
            arguments: vec!["test".into()],
            working_directory: "src".into(),
        };
        let expected = CommandSpec {
            program: admitted.program.clone(),
            arguments: admitted.arguments.clone(),
            working_directory: PathBuf::from(&admitted.working_directory),
        };
        assert_eq!(
            validate_current_runner_command_v13(&admitted).expect("shared direct-exec command"),
            expected
        );
        validate_current_direct_exec_command_v1(&expected).expect("same core admission");

        let rejected = [
            (
                WireCommandSpec {
                    program: "/usr/bin/BaSh".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
                "shell and command-wrapper programs are forbidden",
            ),
            (
                WireCommandSpec {
                    program: "nu".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
                "shell and command-wrapper programs are forbidden",
            ),
            (
                WireCommandSpec {
                    program: "/usr/bin/xonsh".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
                "shell and command-wrapper programs are forbidden",
            ),
            (
                WireCommandSpec {
                    program: "./cargo".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
                "program must be an absolute path or a bare executable name",
            ),
            (
                WireCommandSpec {
                    program: "bin/tool".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
                "program must be an absolute path or a bare executable name",
            ),
            (
                WireCommandSpec {
                    program: "../tool".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
                "program must be an absolute path or a bare executable name",
            ),
            (
                WireCommandSpec {
                    program: "true".into(),
                    arguments: vec!["x".into(); 257],
                    working_directory: String::new(),
                },
                "command program or argument count is outside bounds",
            ),
            (
                WireCommandSpec {
                    program: "true".into(),
                    arguments: Vec::new(),
                    working_directory: "src/.GiT/objects".into(),
                },
                "protected .git paths are forbidden case-insensitively",
            ),
            (
                WireCommandSpec {
                    program: "true".into(),
                    arguments: Vec::new(),
                    working_directory: "src/../tests".into(),
                },
                "path contains a non-normal component",
            ),
            (
                WireCommandSpec {
                    program: "   ".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
                "command.program: must not be blank",
            ),
        ];
        for (wire_command, expected_message) in rejected {
            let core_command = CommandSpec {
                program: wire_command.program.clone(),
                arguments: wire_command.arguments.clone(),
                working_directory: PathBuf::from(&wire_command.working_directory),
            };
            let core_error = validate_current_direct_exec_command_v1(&core_command)
                .expect_err("core rejects crossed command");
            let expected_core_message = if core_error
                .field()
                .starts_with("current_direct_exec_command_v1")
            {
                core_error.message().to_owned()
            } else {
                core_error.to_string()
            };
            assert_eq!(expected_core_message, expected_message);

            let runner_error = validate_current_runner_command_v13(&wire_command)
                .expect_err("runner rejects the same crossed command");
            assert_eq!(
                runner_error.to_string(),
                format!("invalid runner contract: {expected_message}")
            );
        }
    }

    #[test]
    fn frozen_v11_v12_command_validation_does_not_inherit_v13_rules() {
        for program in ["./cargo", "bin/tool", "../tool", "nu", "xonsh"] {
            let command = WireCommandSpec {
                program: program.into(),
                arguments: vec!["--version".into()],
                working_directory: String::new(),
            };
            validate_legacy_runner_command_v11_v12(&command)
                .expect("frozen v11 command validator retains its exact historical behavior");
            let legacy = worker_command_request(1, command.clone());
            legacy
                .validate()
                .expect("frozen v11 request retains its exact historical behavior");
            RunnerRequestV12::RunCommand {
                request: legacy,
                detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            }
            .validate()
            .expect("frozen v12 wrapper retains the nested v11 command behavior");
            assert!(
                validate_current_runner_command_v13(&command).is_err(),
                "current V13 must reject legacy-only program shape {program}",
            );
        }
    }

    #[test]
    fn command_cleanup_proof_is_bound_to_response_effect_and_backend() {
        let request = effect_request(
            "request-cleanup-binding",
            1,
            worker_command_request(
                1,
                WireCommandSpec {
                    program: "/usr/bin/true".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
            ),
        );
        let valid = response_for(
            &request,
            RunnerResponse::CommandCompleted {
                evidence: command_terminal_for(&request),
            },
        );
        encode_response_frame(&valid).expect("exact cleanup binding validates");

        let mut crossed_session = valid.clone();
        crossed_session.session_id = "session-crossed".into();
        assert!(encode_response_frame(&crossed_session).is_err());

        let mut crossed_effect = valid.clone();
        crossed_effect
            .effect
            .as_mut()
            .expect("command response effect")
            .effect_id = "effect-crossed".into();
        assert!(encode_response_frame(&crossed_effect).is_err());

        let mut crossed_request_digest = valid.clone();
        crossed_request_digest
            .effect
            .as_mut()
            .expect("command response effect")
            .request_digest = digest(99);
        assert!(encode_response_frame(&crossed_request_digest).is_err());

        let mut crossed_backend = valid.clone();
        let RunnerResponse::CommandCompleted { evidence } = &mut crossed_backend.response else {
            unreachable!()
        };
        evidence.backend.command_domain_backend =
            CommandDomainCleanupBackend::MacOsDedicatedIdentity;
        assert!(encode_response_frame(&crossed_backend).is_err());

        let mut altered_bytes = valid.clone();
        let RunnerResponse::CommandCompleted { evidence } = &mut altered_bytes.response else {
            unreachable!()
        };
        evidence.cleanup_proof.os_evidence_bytes[0] ^= 1;
        assert!(encode_response_frame(&altered_bytes).is_err());

        let mut redigested_bytes = valid.clone();
        let RunnerResponse::CommandCompleted { evidence } = &mut redigested_bytes.response else {
            unreachable!()
        };
        let last = evidence.cleanup_proof.os_evidence_bytes.len() - 1;
        evidence.cleanup_proof.os_evidence_bytes[last] ^= 1;
        evidence.cleanup_proof.os_evidence_digest =
            Digest::sha256(&evidence.cleanup_proof.os_evidence_bytes);
        assert!(encode_response_frame(&redigested_bytes).is_err());

        let mut missing_effect = valid;
        missing_effect.effect = None;
        assert!(matches!(
            encode_response_frame(&missing_effect),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[test]
    fn command_request_digest_and_response_kind_are_exactly_correlated() {
        let mut request = effect_request(
            "request-command-correlation",
            1,
            worker_command_request(
                1,
                WireCommandSpec {
                    program: "/usr/bin/true".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
            ),
        );
        request
            .effect
            .as_mut()
            .expect("command effect")
            .request_digest = digest(99);
        request
            .bind_transport_commitment_digest()
            .expect("bind forged command digest");
        assert!(encode_request_frame(&request).is_err());

        let read_request = effect_request(
            "request-read-command-confusion",
            2,
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1_024,
            },
        );
        let terminal_source_request = effect_request(
            "request-terminal-source",
            2,
            worker_command_request(
                2,
                WireCommandSpec {
                    program: "/usr/bin/true".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
            ),
        );
        let confused = response_for(
            &read_request,
            RunnerResponse::CommandCompleted {
                evidence: command_terminal_for(&terminal_source_request),
            },
        );
        assert!(confused.validate_correlation(&read_request).is_err());

        let command_request = effect_request(
            "request-command-kind",
            3,
            worker_command_request(
                3,
                WireCommandSpec {
                    program: "/usr/bin/true".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
            ),
        );
        let wrong_result = response_for(
            &command_request,
            RunnerResponse::FileRead {
                path: "src/lib.rs".into(),
                digest: Digest::sha256(b"x"),
                bytes: b"x".to_vec(),
            },
        );
        assert!(wrong_result.validate_correlation(&command_request).is_err());

        assert!(
            serde_json::from_slice::<RunnerResponse>(
                br#"{"kind":"command_completed","exit_status":0,"output":{}}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn shutdown_acknowledgement_contains_no_terminal_cleanup_claim() {
        let acknowledgement = ShutdownPreparedAcknowledgement::new(
            "session-1",
            digest(9),
            RunnerRole::Worker,
            2,
            0,
            true,
        );
        acknowledgement.validate().expect("local acknowledgement");
        let json = serde_json::to_string(&acknowledgement).expect("serialize acknowledgement");
        for forbidden in [
            "cleanup",
            "descendant",
            "journal",
            "synchronized",
            "completed",
            "completion",
        ] {
            assert!(
                !json.to_ascii_lowercase().contains(forbidden),
                "acknowledgement must not claim {forbidden}: {json}"
            );
        }
        assert!(json.contains("\"runner_exit_pending\":true"));
        assert!(json.contains("\"state_disposition\":\"unproven\""));
        assert!(json.contains("\"command_effects_admitted\":0"));
        assert!(!json.contains("commands_started"));

        let legacy = json.replace("command_effects_admitted", "commands_started");
        assert!(serde_json::from_str::<ShutdownPreparedAcknowledgement>(&legacy).is_err());
    }

    #[test]
    fn shutdown_command_admission_count_is_role_and_request_bound() {
        for role in [RunnerRole::Worker, RunnerRole::FinalVerifier] {
            ShutdownPreparedAcknowledgement::new("session-1", digest(9), role, 3, 1, true)
                .validate()
                .expect("command-capable role may admit one of three accepted requests");
        }
        for role in [RunnerRole::Applier, RunnerRole::LiveStateVerifier] {
            ShutdownPreparedAcknowledgement::new("session-1", digest(9), role, 2, 0, false)
                .validate()
                .expect("non-command role reports zero admitted command effects");
            assert!(
                ShutdownPreparedAcknowledgement::new("session-1", digest(9), role, 3, 1, false,)
                    .validate()
                    .is_err()
            );
        }
        assert!(
            ShutdownPreparedAcknowledgement::new(
                "session-1",
                digest(9),
                RunnerRole::Worker,
                2,
                1,
                true,
            )
            .validate()
            .is_err()
        );
        assert!(
            ShutdownPreparedAcknowledgement::new(
                "session-1",
                digest(9),
                RunnerRole::Worker,
                1,
                0,
                true,
            )
            .validate()
            .is_err()
        );
    }

    #[test]
    fn application_evidence_allows_unrelated_live_edits_and_binds_reference() {
        let bundle = sample_bundle();
        let live_manifest_digest = digest(25);
        assert_ne!(live_manifest_digest, bundle.result_snapshot);
        let evidence = WireApplicationEvidence {
            bundle: bundle.clone(),
            change_set_id: "changeset-1".into(),
            base_snapshot: bundle.base_snapshot.clone(),
            result_snapshot: bundle.result_snapshot.clone(),
            transaction_id: "transaction-1".into(),
            live_manifest_digest,
            applied_operations_digest: digest(7),
            touched_path_endpoints_digest: digest(8),
            touched_target_set_digest: digest(24),
            rollback: sample_rollback_reference(1),
        };
        evidence
            .validate()
            .expect("unrelated live edits may change full manifest snapshot");

        let mut forged = evidence;
        forged.base_snapshot = digest(99);
        assert!(forged.validate().is_err());
    }

    #[test]
    fn explicit_rollback_evidence_exactly_correlates_bundle_artifact_and_transaction() {
        let evidence = sample_explicit_rollback_evidence();
        evidence
            .validate()
            .expect("valid explicit rollback evidence");
        evidence
            .validate_against(
                &evidence.bundle,
                &evidence.rollback,
                &sample_two_operation_change_set(),
            )
            .expect("independent change-set validation succeeds");
        let request = effect_request(
            "request-explicit-rollback",
            1,
            RunnerRequest::ApplierRollback {
                bundle: evidence.bundle.clone(),
                rollback: evidence.rollback.clone(),
            },
        );
        let response = response_for(
            &request,
            RunnerResponse::RollbackCompletedWithEvidence {
                evidence: evidence.clone(),
            },
        );
        response
            .validate_correlation(&request)
            .expect("exact v4 rollback evidence correlates");
        let frame = encode_response_frame(&response).expect("bounded response encodes");
        assert_eq!(decode_response_frame(&frame).unwrap(), response);

        let mut crossed_bundle = response.clone();
        let RunnerResponse::RollbackCompletedWithEvidence { evidence } =
            &mut crossed_bundle.response
        else {
            unreachable!()
        };
        evidence.bundle.bundle_digest = digest(90);
        assert!(crossed_bundle.validate_correlation(&request).is_err());

        let mut crossed_artifact = response.clone();
        let RunnerResponse::RollbackCompletedWithEvidence { evidence } =
            &mut crossed_artifact.response
        else {
            unreachable!()
        };
        evidence.rollback.transaction_id = "transaction-crossed".into();
        evidence.rollback.artifacts_digest = Digest::sha256(&evidence.rollback.canonical_bytes());
        evidence.transaction_id = evidence.rollback.transaction_id.clone();
        assert!(crossed_artifact.validate_correlation(&request).is_err());

        let mut crossed_transaction = response;
        let RunnerResponse::RollbackCompletedWithEvidence { evidence } =
            &mut crossed_transaction.response
        else {
            unreachable!()
        };
        evidence.transaction_id = "transaction-substituted".into();
        assert!(crossed_transaction.validate_correlation(&request).is_err());
    }

    #[test]
    fn explicit_rollback_rejects_contract_observation_digest_and_time_substitution() {
        let evidence = sample_explicit_rollback_evidence();

        let mut reordered_contract = evidence.clone();
        reordered_contract.target_contract.reverse();
        reordered_contract.pre_effect_observations.reverse();
        reordered_contract.post_restore_observations.reverse();
        assert!(reordered_contract.validate().is_err());

        let mut recomputed_reorder = reordered_contract;
        recomputed_reorder.expected_application_endpoints_digest =
            wire_expected_application_endpoints_digest(&recomputed_reorder.target_contract)
                .unwrap();
        recomputed_reorder.pre_effect_observations_digest =
            rollback_observations_digest(&recomputed_reorder.pre_effect_observations).unwrap();
        recomputed_reorder.post_restore_observations_digest =
            rollback_observations_digest(&recomputed_reorder.post_restore_observations).unwrap();
        recomputed_reorder.restored_base_endpoints_digest =
            wire_restored_base_endpoints_digest(&recomputed_reorder.target_contract).unwrap();
        recomputed_reorder.touched_target_set_digest =
            wire_rollback_target_set_digest(&recomputed_reorder.target_contract).unwrap();
        assert!(
            recomputed_reorder.validate().is_err(),
            "the immutable rollback reference prevents recomputed path reordering"
        );

        let mut reordered_observation = evidence.clone();
        reordered_observation.pre_effect_observations.reverse();
        assert!(reordered_observation.validate().is_err());
        let mut crossed_digest = evidence.clone();
        crossed_digest.pre_effect_observations_digest = digest(91);
        assert!(crossed_digest.validate().is_err());
        let mut crossed_restored = evidence.clone();
        crossed_restored.restored_base_endpoints_digest = digest(92);
        assert!(crossed_restored.validate().is_err());
        let mut zero_start = evidence.clone();
        zero_start.effect_started_at_unix_ms = 0;
        assert!(zero_start.validate().is_err());
        let mut reversed_time = evidence;
        reversed_time.final_live_manifest_observed_at_unix_ms =
            reversed_time.effect_started_at_unix_ms - 1;
        assert!(reversed_time.validate().is_err());
    }

    #[test]
    fn retained_rollback_reference_rejects_consistent_mode_substitution() {
        let change_set = sample_two_operation_change_set();
        let success = sample_explicit_rollback_evidence();
        let retained_bundle = success.bundle.clone();
        let retained_rollback = success.rollback.clone();
        let mut forged_success = success;
        let WireRollbackExpectedEndpoint::Regular { mode, .. } =
            &mut forged_success.target_contract[0].application
        else {
            unreachable!()
        };
        *mode = 0o644;
        let WireRollbackExpectedEndpoint::Regular { mode, .. } =
            &mut forged_success.target_contract[1].restored_base
        else {
            unreachable!()
        };
        *mode = 0o600;
        let WireRollbackObservedEndpoint::Regular { mode, .. } =
            &mut forged_success.pre_effect_observations[0].endpoint
        else {
            unreachable!()
        };
        *mode = 0o644;
        let WireRollbackObservedEndpoint::Regular { mode, .. } =
            &mut forged_success.post_restore_observations[1].endpoint
        else {
            unreachable!()
        };
        *mode = 0o600;
        forged_success.expected_application_endpoints_digest =
            wire_expected_application_endpoints_digest(&forged_success.target_contract).unwrap();
        forged_success.pre_effect_observations_digest =
            rollback_observations_digest(&forged_success.pre_effect_observations).unwrap();
        forged_success.post_restore_observations_digest =
            rollback_observations_digest(&forged_success.post_restore_observations).unwrap();

        assert!(
            forged_success.validate().is_err(),
            "response-local digest substitutions cannot replace journal authority"
        );
        forged_success.rollback.target_contract_digest =
            wire_rollback_target_contract_digest(&forged_success.target_contract).unwrap();
        forged_success.rollback.artifacts_digest =
            Digest::sha256(&forged_success.rollback.canonical_bytes());
        forged_success
            .validate()
            .expect("the forged response is internally self-consistent");
        assert!(
            forged_success
                .validate_against(&retained_bundle, &retained_rollback, &change_set)
                .is_err(),
            "independently retained rollback authority must reject a consistently recomputed mode substitution"
        );

        let conflict = sample_rollback_live_conflict();
        let retained_bundle = conflict.bundle.clone();
        let retained_rollback = conflict.rollback.clone();
        let mut forged_conflict = conflict;
        let WireRollbackExpectedEndpoint::Regular { mode, .. } =
            &mut forged_conflict.target_contract[0].application
        else {
            unreachable!()
        };
        *mode = 0o644;
        let WireRollbackExpectedEndpoint::Regular { mode, .. } =
            &mut forged_conflict.target_contract[1].restored_base
        else {
            unreachable!()
        };
        *mode = 0o600;
        forged_conflict.expected_application_endpoints_digest =
            wire_expected_application_endpoints_digest(&forged_conflict.target_contract).unwrap();
        forged_conflict.rollback.target_contract_digest =
            wire_rollback_target_contract_digest(&forged_conflict.target_contract).unwrap();
        forged_conflict.rollback.artifacts_digest =
            Digest::sha256(&forged_conflict.rollback.canonical_bytes());
        forged_conflict
            .validate()
            .expect("the forged conflict is internally self-consistent");
        assert!(
            forged_conflict
                .validate_against(&retained_bundle, &retained_rollback, &change_set)
                .is_err(),
            "retained authority must also reject consistently recomputed conflict modes"
        );
    }

    #[test]
    fn live_conflict_is_complete_exact_and_never_mode_only_authority() {
        let conflict = sample_rollback_live_conflict();
        conflict
            .validate()
            .expect("complete stable conflict validates");
        conflict
            .validate_against(
                &conflict.bundle,
                &conflict.rollback,
                &sample_two_operation_change_set(),
            )
            .expect("independent conflict validation succeeds");
        assert_eq!(conflict.conflicts[0].expected_endpoint_digest, digest(23));
        assert_eq!(
            conflict.conflicts[0].observed_endpoint_digest,
            Digest::sha256(ABSENT_ROLLBACK_ENDPOINT_DOMAIN)
        );
        let request = effect_request(
            "request-live-conflict",
            1,
            RunnerRequest::ApplierRollback {
                bundle: conflict.bundle.clone(),
                rollback: conflict.rollback.clone(),
            },
        );
        response_for(
            &request,
            RunnerResponse::RollbackLiveConflict {
                conflict: conflict.clone(),
            },
        )
        .validate_correlation(&request)
        .expect("exact typed conflict correlates");

        let mut mutation_claim = conflict.clone();
        mutation_claim.rollback_mutation_started = true;
        assert!(mutation_claim.validate().is_err());
        let mut missing_conflict = conflict.clone();
        missing_conflict.conflicts.clear();
        assert!(missing_conflict.validate().is_err());
        let mut crossed_observation = conflict.clone();
        crossed_observation.observations[0].path = "crossed/path".into();
        assert!(crossed_observation.validate().is_err());
        let mut crossed_digest = conflict.clone();
        crossed_digest.observed_endpoints_digest = digest(93);
        assert!(crossed_digest.validate().is_err());
        let mut reversed_time = conflict.clone();
        reversed_time.observed_at_unix_ms = reversed_time.manifest_observed_at_unix_ms - 1;
        assert!(reversed_time.validate().is_err());

        let mut mode_only = conflict;
        mode_only.observations[0] = WireRollbackPathObservation {
            path: mode_only.target_contract[0].path.clone(),
            endpoint: WireRollbackObservedEndpoint::Regular {
                digest: digest(23),
                length: 1,
                mode: 0o644,
            },
        };
        mode_only.observed_endpoints_digest =
            rollback_observations_digest(&mode_only.observations).unwrap();
        assert!(mode_only.validate().is_err());
    }

    #[test]
    fn legacy_rollback_dto_remains_readable_and_request_shape_is_unchanged() {
        let bundle = sample_bundle();
        let rollback = sample_rollback_reference(1);
        let request = effect_request(
            "request-legacy-rollback",
            1,
            RunnerRequest::ApplierRollback {
                bundle: bundle.clone(),
                rollback: rollback.clone(),
            },
        );
        let request_json = serde_json::to_value(&request.request).unwrap();
        let object = request_json.as_object().unwrap();
        assert_eq!(object.len(), 3);
        assert!(object.contains_key("kind"));
        assert!(object.contains_key("bundle"));
        assert!(object.contains_key("rollback"));
        let mut uncommitted_request = request_json;
        uncommitted_request
            .get_mut("rollback")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove("target_contract_digest");
        assert!(
            serde_json::from_value::<RunnerRequest>(uncommitted_request).is_err(),
            "new rollback requests fail closed without a mode-bearing target commitment"
        );
        let legacy = response_for(
            &request,
            RunnerResponse::RollbackCompleted {
                evidence: WireRollbackEvidence {
                    bundle,
                    transaction_id: rollback.transaction_id.clone(),
                    change_set_id: rollback.change_set_id.clone(),
                    base_snapshot: rollback.base_snapshot.clone(),
                    live_manifest_digest: digest(94),
                    restored_base_endpoints_digest: digest(95),
                    touched_target_set_digest: rollback.touched_target_set_digest.clone(),
                },
            },
        );
        let frame = encode_response_frame(&legacy).expect("legacy DTO remains encodable");
        let decoded = decode_response_frame(&frame).expect("legacy DTO remains readable");
        decoded
            .validate_correlation(&request)
            .expect("legacy DTO correlation remains readable");
    }

    #[test]
    fn maximum_rollback_reference_has_a_proven_complete_frame_bound() {
        let bundle = sample_bundle();
        let rollback = sample_rollback_reference(MAX_ROLLBACK_ARTIFACTS);
        rollback.validate().expect("maximum reference is canonical");
        let rollback_request = effect_request(
            "request-rollback-max",
            1,
            RunnerRequest::ApplierRollback {
                bundle: bundle.clone(),
                rollback: rollback.clone(),
            },
        );
        let request_frame = encode_request_frame(&rollback_request)
            .expect("maximum rollback request fits one frame");
        assert!(request_frame.len() <= MAX_WIRE_FRAME_BYTES + 4);

        let request = effect_request(
            "request-apply-max",
            1,
            RunnerRequest::ApplierApplyBundle {
                bundle: bundle.clone(),
            },
        );
        let evidence = WireApplicationEvidence {
            bundle: bundle.clone(),
            change_set_id: bundle.change_set_id.clone(),
            base_snapshot: bundle.base_snapshot.clone(),
            result_snapshot: bundle.result_snapshot.clone(),
            transaction_id: rollback.transaction_id.clone(),
            live_manifest_digest: digest(30),
            applied_operations_digest: digest(31),
            touched_path_endpoints_digest: digest(32),
            touched_target_set_digest: rollback.touched_target_set_digest.clone(),
            rollback,
        };
        let response = response_for(&request, RunnerResponse::ApplicationApplied { evidence });
        let frame = encode_response_frame(&response).expect("maximum evidence fits one frame");
        assert!(frame.len() <= MAX_WIRE_FRAME_BYTES + 4);

        let mut oversized = sample_rollback_reference(MAX_ROLLBACK_ARTIFACTS);
        let operation_index = u32::try_from(MAX_ROLLBACK_ARTIFACTS).expect("bound fits u32");
        oversized.artifacts.push(WireRollbackArtifact {
            kind: WireRollbackArtifactKind::BaseBlob { operation_index },
            name: format!("base-{operation_index:06}"),
            length: 0,
            mode: 0o600,
            digest: digest(33),
            device: 1,
            inode: 999_999,
            owner_uid: 3,
            modified_seconds: 4,
            modified_nanoseconds: 5,
            changed_seconds: 6,
            changed_nanoseconds: 7,
        });
        oversized.artifacts_digest = Digest::sha256(&oversized.canonical_bytes());
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn explicit_rollback_response_enforces_target_and_frame_bounds() {
        let mut over_count = sample_explicit_rollback_evidence();
        let target = over_count.target_contract[0].clone();
        let pre = over_count.pre_effect_observations[0].clone();
        let post = over_count.post_restore_observations[0].clone();
        over_count.target_contract = vec![target; MAX_ROLLBACK_EVIDENCE_TARGETS + 1];
        over_count.pre_effect_observations = vec![pre; MAX_ROLLBACK_EVIDENCE_TARGETS + 1];
        over_count.post_restore_observations = vec![post; MAX_ROLLBACK_EVIDENCE_TARGETS + 1];
        assert!(over_count.validate().is_err());

        let mut oversized = sample_explicit_rollback_evidence();
        oversized.target_contract.clear();
        oversized.pre_effect_observations.clear();
        oversized.post_restore_observations.clear();
        for index in 0..900 {
            let path = format!("{index:04}-{}", "x".repeat(MAX_PATH_BYTES - 6));
            oversized.target_contract.push(WireRollbackTargetContract {
                path: path.clone(),
                application: WireRollbackExpectedEndpoint::Regular {
                    digest: digest(30),
                    mode: 0o600,
                },
                restored_base: WireRollbackExpectedEndpoint::Absent,
            });
            oversized
                .pre_effect_observations
                .push(WireRollbackPathObservation {
                    path: path.clone(),
                    endpoint: WireRollbackObservedEndpoint::Regular {
                        digest: digest(30),
                        length: 1,
                        mode: 0o600,
                    },
                });
            oversized
                .post_restore_observations
                .push(WireRollbackPathObservation {
                    path,
                    endpoint: WireRollbackObservedEndpoint::Absent,
                });
        }
        oversized.expected_application_endpoints_digest =
            wire_expected_application_endpoints_digest(&oversized.target_contract).unwrap();
        oversized.restored_base_endpoints_digest =
            wire_restored_base_endpoints_digest(&oversized.target_contract).unwrap();
        oversized.touched_target_set_digest =
            wire_rollback_target_set_digest(&oversized.target_contract).unwrap();
        oversized.rollback.touched_target_set_digest = oversized.touched_target_set_digest.clone();
        oversized.rollback.target_contract_digest =
            wire_rollback_target_contract_digest(&oversized.target_contract).unwrap();
        oversized.rollback.artifacts_digest = Digest::sha256(&oversized.rollback.canonical_bytes());
        oversized.pre_effect_observations_digest =
            rollback_observations_digest(&oversized.pre_effect_observations).unwrap();
        oversized.post_restore_observations_digest =
            rollback_observations_digest(&oversized.post_restore_observations).unwrap();
        assert!(matches!(
            oversized.validate(),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("bounded runner response frame")
        ));
    }
