    use std::path::PathBuf;

    use grok_build_core::{
        AcceptanceCriterion, AcceptanceKind, CommandOutputArtifactSourceV1, CommandSpec,
        ExecutionOrigin, FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1,
        FinalVerificationAttemptPredecessorV1, FinalVerificationAttemptProvenanceV1, PathScope,
        ProviderProfile, SPRINT_AUTHORITY_CONTRACT_VERSION_V2, SprintBudget, SprintBudgetV2,
        SprintSpec, SprintSpecV2, TaskAttempt, TaskGraphV2, TaskPurposeV2, TaskSpecV2, WorkerLease,
        WorkspaceGrant, WorkspaceNetworkPolicy, WorkspacePermissions,
    };

    use super::*;
    use crate::service::test_decode_service_request_frame;
    use crate::wire::{command_output_capture_maximum, test_command_output_capture_anchor};
    use crate::{
        RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequest, RunnerRequestEnvelopeV12,
        RunnerRequestV12, decode_request_frame, decode_request_frame_v12, decode_response_frame,
        decode_response_frame_v12, encode_request_frame, encode_request_frame_v12,
        sprint_spec_digest,
    };

    fn digest(character: char) -> Digest {
        Digest::parse(character.to_string().repeat(64)).expect("valid fixture digest")
    }

    fn criterion() -> AcceptanceCriterion {
        AcceptanceCriterion {
            criterion_id: "tests-pass".into(),
            description: "Focused tests pass".into(),
            kind: AcceptanceKind::Automated(CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            }),
        }
    }

    fn provider() -> ProviderProfile {
        ProviderProfile {
            backend_id: "fake".into(),
            model_id: "deterministic-v2".into(),
            execution_origin: ExecutionOrigin::HostIsolated,
        }
    }

    fn grant() -> WorkspaceGrant {
        WorkspaceGrant {
            grant_id: "grant-v13-1".into(),
            canonical_root: PathBuf::from("/work/project"),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: digest('a'),
        }
    }

    fn repair_task(slot_ordinal: u8, dependencies: &[&str]) -> TaskSpecV2 {
        TaskSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            task_id: format!("repair-{slot_ordinal}"),
            purpose: TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal },
            goal: format!("Repair final verification attempt {slot_ordinal}"),
            dependencies: dependencies.iter().map(ToString::to_string).collect(),
            path_scopes: vec![PathScope::Workspace],
            acceptance_checks: vec!["tests-pass".into()],
            base_snapshot: digest('b'),
            required: false,
        }
    }

    fn v2_pair(objective: &str) -> (SprintSpecV2, TaskGraphV2) {
        let tasks = vec![
            TaskSpecV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                task_id: "ordinary-1".into(),
                purpose: TaskPurposeV2::Ordinary,
                goal: "Implement feature".into(),
                dependencies: Vec::new(),
                path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                acceptance_checks: vec!["tests-pass".into()],
                base_snapshot: digest('b'),
                required: true,
            },
            repair_task(1, &["ordinary-1"]),
            repair_task(2, &["ordinary-1", "repair-1"]),
        ];
        let mut graph = TaskGraphV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            graph_id: "graph-v13-1".into(),
            sprint_id: "sprint-v13-1".into(),
            sprint_spec_digest: digest('0'),
            repair_slot_reserve_digest: digest('0'),
            tasks,
        };
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("compute repair reserve");
        let spec = SprintSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: graph.sprint_id.clone(),
            objective: objective.into(),
            acceptance_criteria: vec![criterion()],
            provider: provider(),
            budget: SprintBudgetV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                max_tasks: graph.tasks.len(),
                max_attempts_per_task: 3,
                max_final_verification_attempts: 3,
                max_tool_calls: 100,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: grant(),
            base_snapshot: digest('b'),
            task_graph_id: graph.graph_id.clone(),
            task_graph_payload_digest: graph.payload_digest().expect("graph payload"),
            repair_slot_reserve_digest: graph.repair_slot_reserve_digest.clone(),
        };
        graph.sprint_spec_digest = spec.canonical_digest().expect("core V2 sprint digest");
        graph
            .validate_for_sprint(&spec)
            .expect("valid fixture V2 pair");
        (spec, graph)
    }

    fn request() -> RunnerSprintAuthorityRequestEnvelopeV13 {
        let (sprint_spec, task_graph) = v2_pair("Implement feature");
        RunnerSprintAuthorityRequestEnvelopeV13 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            request_id: "request-v13-1".into(),
            request: RunnerSprintAuthorityRequestV13::ValidateSprintAuthority {
                expected_sprint_spec_digest: sprint_spec_digest_v2(&sprint_spec, &task_graph)
                    .expect("runner V2 sprint digest"),
                expected_task_graph_digest: task_graph
                    .canonical_digest_for_sprint(&sprint_spec)
                    .expect("core V2 graph digest"),
                expected_task_graph_payload_digest: sprint_spec.task_graph_payload_digest.clone(),
                expected_repair_slot_reserve_digest: sprint_spec.repair_slot_reserve_digest.clone(),
                sprint_spec: Box::new(sprint_spec),
                task_graph: Box::new(task_graph),
            },
        }
    }

    fn command_pair() -> (CommandSpec, WireCommandSpec) {
        (
            CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            },
            WireCommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: String::new(),
            },
        )
    }

    fn worker_command_request() -> RunnerCommandRequestEnvelopeV13 {
        let (sprint_spec, task_graph) = v2_pair("Implement feature");
        let (core_command, wire_command) = command_pair();
        let request_digest = Digest::sha256(
            &serde_json::to_vec(&core_command).expect("encode exact worker command"),
        );
        let lease = WorkerLease::new(
            sprint_spec.sprint_id.clone(),
            1,
            task_graph.tasks[0].task_id.clone(),
            "worker-v13-1".into(),
            task_graph.tasks[0].path_scopes.clone(),
            10,
        )
        .expect("construct worker lease");
        let attempt = TaskAttempt::new(lease.clone(), 1, "opening-event-v13-1".into())
            .expect("construct worker attempt");
        let running_boundary = TaskAttemptRunningBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "running-boundary-v13-1".into(),
            attempt,
            runner_launch_id: "launch-v13-1".into(),
            runner_session_id: "session-v13-1".into(),
            transition_event_id: "running-event-v13-1".into(),
            started_at_unix_ms: 11,
        };
        running_boundary
            .validate()
            .expect("validate worker running boundary");
        let output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: sprint_spec.sprint_id.clone(),
                runner_launch_id: "launch-v13-1".into(),
                runner_session_id: "session-v13-1".into(),
                effect_id: "effect-v13-1".into(),
                request_digest: request_digest.clone(),
            },
            digest('e'),
            command_output_capture_maximum(1_048_576).expect("capture maximum"),
            1,
        );
        let mut request = RunnerCommandRequestEnvelopeV13 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            session_id: "session-v13-1".into(),
            runner_nonce: digest('f'),
            sequence: 1,
            request_id: "command-request-v13-1".into(),
            sprint_spec: Box::new(sprint_spec),
            task_graph: Box::new(task_graph.clone()),
            effect: WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "launch-v13-1".into(),
                effect_id: "effect-v13-1".into(),
                idempotency_key: "idempotency-v13-1".into(),
                sprint_id: task_graph.sprint_id.clone(),
                task_id: Some(task_graph.tasks[0].task_id.clone()),
                worker_id: Some("worker-v13-1".into()),
                worker_lease: Some(lease),
                policy_hash: digest('c'),
                input_snapshot: digest('d'),
                request_digest,
                transport_commitment_digest: digest('0'),
            },
            request: RunnerCommandRequestV13::WorkerRunCommand {
                command: wire_command,
                output_capture,
                detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
                task: Box::new(task_graph.tasks[0].clone()),
                running_boundary: Box::new(running_boundary),
            },
        };
        request
            .bind_transport_commitment_digest()
            .expect("bind worker V13 command commitment");
        request
    }

    fn final_verifier_command_request() -> RunnerCommandRequestEnvelopeV13 {
        let (sprint_spec, task_graph) = v2_pair("Implement feature");
        let (core_command, wire_command) = command_pair();
        let request_digest =
            Digest::sha256(&serde_json::to_vec(&core_command).expect("encode exact final command"));
        let final_verification_attempt = FinalVerificationAttemptAuthorityV1 {
            authority_version: FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1,
            attempt_id: "final-attempt-v13-1".into(),
            sprint_id: sprint_spec.sprint_id.clone(),
            attempt_ordinal: 1,
            max_final_verification_attempts: sprint_spec.budget.max_final_verification_attempts,
            final_verification_admission_id: "final-admission-v13-1".into(),
            input_snapshot: digest('d'),
            complete_task_done_set_digest: digest('1'),
            complete_criterion_evidence_set_digest: digest('2'),
            final_verification_check: core_command,
            execution_policy_digest: digest('c'),
            provenance: FinalVerificationAttemptProvenanceV1 {
                coordinator_instance_id: "coordinator-v13-1".into(),
                admission_event_id: "final-admission-event-v13-1".into(),
                admission_event_sequence: 21,
                admitted_at_unix_ms: 30,
            },
            predecessor: FinalVerificationAttemptPredecessorV1::Initial,
        };
        final_verification_attempt
            .validate()
            .expect("validate final attempt authority");
        let output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: sprint_spec.sprint_id.clone(),
                runner_launch_id: "final-launch-v13-1".into(),
                runner_session_id: "final-session-v13-1".into(),
                effect_id: "final-effect-v13-1".into(),
                request_digest: request_digest.clone(),
            },
            digest('e'),
            command_output_capture_maximum(1_048_576).expect("capture maximum"),
            2,
        );
        let mut request = RunnerCommandRequestEnvelopeV13 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            session_id: "final-session-v13-1".into(),
            runner_nonce: digest('f'),
            sequence: 1,
            request_id: "final-command-request-v13-1".into(),
            sprint_spec: Box::new(sprint_spec),
            task_graph: Box::new(task_graph.clone()),
            effect: WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "final-launch-v13-1".into(),
                effect_id: "final-effect-v13-1".into(),
                idempotency_key: "final-idempotency-v13-1".into(),
                sprint_id: task_graph.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: None,
                policy_hash: digest('c'),
                input_snapshot: digest('d'),
                request_digest,
                transport_commitment_digest: digest('0'),
            },
            request: RunnerCommandRequestV13::FinalVerifierRunCommand {
                command: wire_command,
                output_capture,
                detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
                final_verification_attempt: Box::new(final_verification_attempt),
            },
        };
        request
            .bind_transport_commitment_digest()
            .expect("bind final-verifier V13 command commitment");
        request
    }

    fn final_verifier_initialization_request() -> RunnerFinalVerifierInitializationRequestV13 {
        let command = final_verifier_command_request();
        let RunnerCommandRequestV13::FinalVerifierRunCommand {
            output_capture,
            detector_policy,
            final_verification_attempt,
            ..
        } = &command.request
        else {
            unreachable!()
        };
        let mut request = RunnerFinalVerifierInitializationRequestV13 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V13,
            session_id: command.session_id.clone(),
            sequence: 0,
            request_id: "final-initialization-v13-1".into(),
            launch_id: command.effect.launch_id.clone(),
            sprint_spec: command.sprint_spec.clone(),
            task_graph: command.task_graph.clone(),
            expected_sprint_spec_digest: sprint_spec_digest_v2(
                &command.sprint_spec,
                &command.task_graph,
            )
            .expect("runner V2 sprint digest"),
            expected_task_graph_digest: command
                .task_graph
                .canonical_digest_for_sprint(&command.sprint_spec)
                .expect("current graph digest"),
            expected_task_graph_payload_digest: command
                .sprint_spec
                .task_graph_payload_digest
                .clone(),
            expected_repair_slot_reserve_digest: command
                .sprint_spec
                .repair_slot_reserve_digest
                .clone(),
            final_verification_attempt: final_verification_attempt.clone(),
            output_capture: output_capture.clone(),
            detector_policy: detector_policy.clone(),
            expected_grant_hash: command.sprint_spec.workspace_grant.grant_hash.clone(),
            expected_input_snapshot: command.effect.input_snapshot.clone(),
            expected_policy_hash: command.effect.policy_hash.clone(),
            expected_private_state_digest: output_capture.acquired().private_state_digest.clone(),
            expected_private_state_identity: WireRootIdentity {
                device_id: 7,
                inode: 700,
            },
            expected_binary_digest: digest('3'),
            expected_binary_identity: WireBinaryIdentity {
                device_id: 8,
                inode: 800,
                byte_length: 4_096,
                mode: 0o100_555,
                owner_uid: 501,
                link_count: 1,
            },
            expected_protocol_digest: runner_protocol_digest_v13(),
            request_commitment_digest: digest('0'),
        };
        request
            .bind_request_commitment_digest()
            .expect("bind dormant initialization request");
        request
    }

    type DormantTranscript = (
        RunnerFinalVerifierInitializationRequestV13,
        RunnerFinalVerifierInitializationReceiptV13,
        RunnerCommandRequestEnvelopeV13,
        RunnerRawTerminalResponseV13,
        RunnerShutdownRequestV13,
        RunnerShutdownReceiptV13,
    );

    fn dormant_transcript() -> DormantTranscript {
        let initialization = final_verifier_initialization_request();
        let mut service = DormantFinalVerifierServiceSessionV13::from_fixture_entropy([0x51; 32]);
        let initialization_receipt = service
            .emit_initialization_receipt(&initialization)
            .expect("derive service-owned dormant initialization readback");
        let mut command = final_verifier_command_request();
        command.runner_nonce = initialization_receipt.runner_nonce.clone();
        command
            .bind_transport_commitment_digest()
            .expect("bind command to the service-derived runner nonce");
        let terminal = service
            .emit_raw_terminal_response(
                &command,
                RunnerRawTerminalOutcomeV13::Exited { exit_code: 0 },
            )
            .expect("derive service-owned dormant raw terminal readback");
        let shutdown =
            RunnerShutdownRequestV13::for_terminal(&terminal, "final-shutdown-request-v13-1")
                .expect("derive dormant shutdown request");
        let shutdown_receipt = service
            .emit_shutdown_receipt(&shutdown)
            .expect("derive service-owned dormant shutdown readback");
        assert!(service.is_closed());
        (
            initialization,
            initialization_receipt,
            command,
            terminal,
            shutdown,
            shutdown_receipt,
        )
    }

    #[test]
    fn v13_service_protocol_descriptor_is_runner_owned_and_router_closed() {
        let protocol_digest = runner_protocol_digest_v13();
        assert_eq!(
            protocol_digest,
            Digest::parse("63cb4552922340cabea5c9852a4b4672cec0fa9c0eca9df0ff4717eb9152daa7")
                .expect("fixed V13 runner-owned protocol descriptor digest")
        );
        assert_ne!(protocol_digest, crate::runner_protocol_digest());
        let descriptor = std::str::from_utf8(SERVICE_PROTOCOL_DESCRIPTOR_V13)
            .expect("V13 service descriptor is UTF-8 apart from embedded NUL separators");
        for required in [
            "caller-expected-protocol-digest=comparison-only",
            "runner-nonce=service-session-state-plus-initialization-request",
            "v11-v12=no-promotion",
            "production-router=closed",
            "native-origin=missing",
            "no-launch",
            "no-dispatch",
        ] {
            assert!(
                descriptor.contains(required),
                "V13 descriptor omitted {required}"
            );
        }

        let initialization = final_verifier_initialization_request();
        let frame = encode_final_verifier_initialization_request_frame_v13(&initialization)
            .expect("encode exact V13 initialization");
        assert!(matches!(
            test_decode_service_request_frame(&frame),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("canonical v11 or v12")
        ));
    }

    #[test]
    fn v13_dormant_service_capabilities_have_no_public_constructor_mint_or_reexport() {
        let source = include_str!("../../wire_v13.rs");
        let lib = include_str!("../../lib.rs");
        for forbidden in [
            ["pub", "enum RunnerOwnedProtocolIdentityV13"].join(" "),
            ["pub", "struct RunnerOwnedProtocolIdentityV13"].join(" "),
            ["pub", "fn from_service_protocol_descriptor"].join(" "),
            ["pub", "struct DormantFinalVerifierServiceSessionV13"].join(" "),
            ["pub", "fn from_fixture_entropy"].join(" "),
            ["pub", "fn restarted_without_authenticated_native_origin"].join(" "),
            ["pub", "fn from_service_session"].join(" "),
            ["pub", "fn correlation_projection_for"].join(" "),
            ["pub", "fn dormant_readback_for"].join(" "),
        ] {
            assert!(
                !source.contains(&forbidden),
                "V13 dormant service boundary exposed {forbidden}"
            );
        }
        assert!(
            !lib.contains("RunnerOwnedProtocolIdentityV13")
                && !lib.contains("DormantFinalVerifierServiceSessionV13"),
            "crate root must not re-export a dormant service capability"
        );
    }

    #[test]
    fn v13_protocol_identity_is_compiler_guarded_move_only_and_nonserializable() {
        // These ambiguity assertions compile only while the token implements
        // neither trait. Adding `Clone` or `Serialize` introduces a second
        // applicable implementation and makes this test target fail to build.
        trait AmbiguousIfClone<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}

        trait AmbiguousIfSerialize<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
        impl<T: ?Sized + Serialize> AmbiguousIfSerialize<u8> for T {}

        <RunnerOwnedProtocolIdentityV13 as AmbiguousIfClone<_>>::marker();
        <RunnerOwnedProtocolIdentityV13 as AmbiguousIfSerialize<_>>::marker();

        let identity = RunnerOwnedProtocolIdentityV13::from_service_protocol_descriptor();
        assert_eq!(identity.protocol_digest(), runner_protocol_digest_v13());
    }

    #[test]
    fn v13_expected_protocol_digest_is_comparison_only() {
        let mut crossed = final_verifier_initialization_request();
        crossed.expected_protocol_digest = digest('9');
        assert!(matches!(
            crossed.bind_request_commitment_digest(),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("runner-owned V13 descriptor")
        ));

        let request = final_verifier_initialization_request();
        let mut service = DormantFinalVerifierServiceSessionV13::from_fixture_entropy([0x41; 32]);
        let receipt = service
            .emit_initialization_receipt(&request)
            .expect("service derives exact protocol identity");
        assert_eq!(receipt.protocol_digest, runner_protocol_digest_v13());
        assert_eq!(
            receipt.protocol_digest, request.expected_protocol_digest,
            "caller input is compared, never used as the response source"
        );
    }

    #[test]
    fn v13_fixture_session_state_derives_request_session_and_response_identities() {
        let initialization = final_verifier_initialization_request();
        let mut service_a = DormantFinalVerifierServiceSessionV13::from_fixture_entropy([0x41; 32]);
        let mut service_b = DormantFinalVerifierServiceSessionV13::from_fixture_entropy([0x42; 32]);
        let receipt_a = service_a
            .emit_initialization_receipt(&initialization)
            .expect("fixture session A initializes");
        let receipt_b = service_b
            .emit_initialization_receipt(&initialization)
            .expect("fixture session B initializes");
        assert_ne!(receipt_a.runner_nonce, receipt_b.runner_nonce);
        assert_ne!(
            receipt_a.receipt_commitment_digest,
            receipt_b.receipt_commitment_digest
        );

        let mut substituted_initialization = initialization.clone();
        substituted_initialization.request_id = "substituted-initialization-v13".into();
        substituted_initialization
            .bind_request_commitment_digest()
            .expect("bind individually valid substituted initialization");
        let mut substituted_service =
            DormantFinalVerifierServiceSessionV13::from_fixture_entropy([0x41; 32]);
        let substituted_receipt = substituted_service
            .emit_initialization_receipt(&substituted_initialization)
            .expect("same fixture entropy binds the substituted request independently");
        assert_ne!(receipt_a.runner_nonce, substituted_receipt.runner_nonce);

        let mut command_a = final_verifier_command_request();
        command_a.runner_nonce = receipt_a.runner_nonce.clone();
        command_a
            .bind_transport_commitment_digest()
            .expect("bind request identity to session A");
        let mut command_b = final_verifier_command_request();
        command_b.runner_nonce = receipt_b.runner_nonce.clone();
        command_b
            .bind_transport_commitment_digest()
            .expect("bind request identity to session B");
        assert_ne!(
            command_a.effect.transport_commitment_digest,
            command_b.effect.transport_commitment_digest
        );

        let terminal_a = service_a
            .emit_raw_terminal_response(
                &command_a,
                RunnerRawTerminalOutcomeV13::Exited { exit_code: 0 },
            )
            .expect("emit session A response");
        let terminal_b = service_b
            .emit_raw_terminal_response(
                &command_b,
                RunnerRawTerminalOutcomeV13::Exited { exit_code: 0 },
            )
            .expect("emit session B response");
        assert_ne!(
            terminal_a.response_commitment_digest,
            terminal_b.response_commitment_digest
        );
    }

    #[test]
    fn v13_service_session_replay_and_restart_without_native_origin_fail_closed() {
        let request = final_verifier_initialization_request();
        let mut service = DormantFinalVerifierServiceSessionV13::from_fixture_entropy([0x41; 32]);
        service
            .emit_initialization_receipt(&request)
            .expect("first initialization consumes fixture session state");
        assert!(matches!(
            service.emit_initialization_receipt(&request),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("no one-session source")
        ));

        let mut restarted =
            DormantFinalVerifierServiceSessionV13::restarted_without_authenticated_native_origin();
        assert!(matches!(
            restarted.emit_initialization_receipt(&request),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("authenticated native-origin")
        ));
    }

    #[test]
    fn v13_service_session_rejects_crossing_without_consuming_exact_command_slot() {
        let initialization = final_verifier_initialization_request();
        let mut service = DormantFinalVerifierServiceSessionV13::from_fixture_entropy([0x43; 32]);
        let receipt = service
            .emit_initialization_receipt(&initialization)
            .expect("initialize service fixture");
        let mut exact = final_verifier_command_request();
        exact.runner_nonce = receipt.runner_nonce.clone();
        exact
            .bind_transport_commitment_digest()
            .expect("bind exact service command");

        let mut crossed = exact.clone();
        let RunnerCommandRequestV13::FinalVerifierRunCommand {
            final_verification_attempt,
            ..
        } = &mut crossed.request
        else {
            unreachable!()
        };
        final_verification_attempt
            .provenance
            .coordinator_instance_id = "crossed-v13-coordinator".into();
        crossed
            .bind_transport_commitment_digest()
            .expect("crossed command remains intrinsically well formed");
        assert!(
            service
                .emit_raw_terminal_response(
                    &crossed,
                    RunnerRawTerminalOutcomeV13::Exited { exit_code: 0 },
                )
                .is_err()
        );
        service
            .emit_raw_terminal_response(
                &exact,
                RunnerRawTerminalOutcomeV13::Exited { exit_code: 0 },
            )
            .expect("crossed input did not consume exact command slot");
    }

    #[test]
    fn v13_service_identity_frames_reject_unknown_size_and_sequence_substitution() {
        let request = final_verifier_initialization_request();
        let canonical = serde_json::to_vec(&request).expect("canonical initialization bytes");
        let unknown = String::from_utf8(canonical)
            .expect("V13 initialization is UTF-8")
            .replacen(
                "\"protocol_version\":",
                "\"unknown\":true,\"protocol_version\":",
                1,
            );
        assert!(matches!(
            decode_final_verifier_initialization_request_frame_v13(&framed_payload(
                unknown.as_bytes()
            )),
            Err(WireProtocolError::InvalidJson(_))
        ));

        let oversized = u32::try_from(crate::MAX_WIRE_FRAME_BYTES + 1)
            .expect("wire maximum fits u32")
            .to_be_bytes();
        assert!(matches!(
            decode_final_verifier_initialization_request_frame_v13(&oversized),
            Err(WireProtocolError::InvalidLength(_))
        ));

        let mut wrong_sequence = request;
        wrong_sequence.sequence = 1;
        assert!(wrong_sequence.bind_request_commitment_digest().is_err());
    }

    #[derive(Clone, Copy)]
    enum InvalidWireCommandMutation {
        Shell,
        Wrapper,
        OversizedProgram,
        TooManyArguments,
        OversizedArgument,
        ProgramNul,
        ArgumentNul,
        AbsoluteWorkingDirectory,
        ParentWorkingDirectory,
        WorkingDirectoryNul,
        OversizedWorkingDirectory,
    }

    impl InvalidWireCommandMutation {
        fn apply(self, command: &mut WireCommandSpec) {
            match self {
                Self::Shell => command.program = "/bin/sh".into(),
                Self::Wrapper => command.program = "/usr/bin/env".into(),
                Self::OversizedProgram => command.program = "x".repeat(8_192),
                Self::TooManyArguments => command.arguments = vec!["x".into(); 300],
                Self::OversizedArgument => command.arguments = vec!["x".repeat(8_192)],
                Self::ProgramNul => command.program = "cargo\0substituted".into(),
                Self::ArgumentNul => command.arguments = vec!["test\0substituted".into()],
                Self::AbsoluteWorkingDirectory => command.working_directory = "/tmp".into(),
                Self::ParentWorkingDirectory => command.working_directory = "../src".into(),
                Self::WorkingDirectoryNul => command.working_directory = "src\0other".into(),
                Self::OversizedWorkingDirectory => {
                    command.working_directory = "x".repeat(8_192);
                }
            }
        }

        const fn expected_message(self) -> &'static str {
            match self {
                Self::Shell | Self::Wrapper => "shell and command-wrapper programs are forbidden",
                Self::OversizedProgram | Self::TooManyArguments | Self::ProgramNul => {
                    "command program or argument count is outside bounds"
                }
                Self::OversizedArgument | Self::ArgumentNul => {
                    "command argument is outside the text bound"
                }
                Self::AbsoluteWorkingDirectory => "path must be normalized and workspace-relative",
                Self::ParentWorkingDirectory => "path contains a non-normal component",
                Self::WorkingDirectoryNul | Self::OversizedWorkingDirectory => {
                    "working directory is oversized or contains NUL"
                }
            }
        }
    }

    fn mutate_v13_command(
        request: &mut RunnerCommandRequestEnvelopeV13,
        mutation: InvalidWireCommandMutation,
    ) {
        let command = match &mut request.request {
            RunnerCommandRequestV13::WorkerRunCommand { command, .. }
            | RunnerCommandRequestV13::FinalVerifierRunCommand { command, .. } => command,
        };
        mutation.apply(command);
    }

    fn v12_substitution_for(request: &RunnerCommandRequestEnvelopeV13) -> RunnerRequestEnvelopeV12 {
        let (command, output_capture, detector_policy) = match &request.request {
            RunnerCommandRequestV13::WorkerRunCommand {
                command,
                output_capture,
                detector_policy,
                ..
            }
            | RunnerCommandRequestV13::FinalVerifierRunCommand {
                command,
                output_capture,
                detector_policy,
                ..
            } => (
                command.clone(),
                output_capture.clone(),
                detector_policy.clone(),
            ),
        };
        let legacy_request = match request.request.role() {
            RunnerRole::Worker => RunnerRequest::WorkerRunCommand {
                command,
                output_capture,
            },
            RunnerRole::FinalVerifier => RunnerRequest::FinalVerifierRunCommand {
                command,
                output_capture,
            },
            RunnerRole::Applier | RunnerRole::LiveStateVerifier => unreachable!(),
        };
        let mut envelope = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: request.session_id.clone(),
            runner_nonce: request.runner_nonce.clone(),
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            effect: request.effect.clone(),
            request: RunnerRequestV12::RunCommand {
                request: legacy_request,
                detector_policy,
            },
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind exact V12 substitution fixture");
        envelope
    }

    fn legacy_sprint() -> SprintSpec {
        SprintSpec {
            sprint_id: "sprint-v13-1".into(),
            objective: "Implement feature".into(),
            acceptance_criteria: vec![criterion()],
            provider: provider(),
            budget: SprintBudget {
                max_tasks: 3,
                max_attempts_per_task: 3,
                max_tool_calls: 100,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: grant(),
            base_snapshot: digest('b'),
        }
    }

    fn framed_payload(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("fixture payload fits u32")
                .to_be_bytes(),
        );
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn v13_request_and_response_round_trip_with_exact_readback() {
        let request = request();
        let request_frame = encode_sprint_authority_request_frame_v13(&request)
            .expect("encode V13 authority request");
        assert_eq!(
            decode_sprint_authority_request_frame_v13(&request_frame)
                .expect("decode V13 authority request"),
            request
        );

        let response = RunnerSprintAuthorityResponseEnvelopeV13::readback_for(&request)
            .expect("derive V13 readback");
        response
            .validate_correlation(&request)
            .expect("correlate exact V13 readback");
        let response_frame = encode_sprint_authority_response_frame_v13(&response)
            .expect("encode V13 authority response");
        let decoded = decode_sprint_authority_response_frame_v13(&response_frame)
            .expect("decode V13 authority response");
        decoded
            .validate_correlation(&request)
            .expect("read back exact V13 response");
        assert_eq!(decoded, response);
    }

    #[test]
    fn v13_golden_frames_and_v1_digest_remain_byte_exact() {
        let request = request();
        let request_frame =
            encode_sprint_authority_request_frame_v13(&request).expect("encode golden V13 request");
        let response = RunnerSprintAuthorityResponseEnvelopeV13::readback_for(&request)
            .expect("derive golden V13 response");
        let response_frame = encode_sprint_authority_response_frame_v13(&response)
            .expect("encode golden V13 response");
        assert_eq!(
            Digest::sha256(&request_frame),
            Digest::parse("836df2f487b17a1d5a0ec597c8ded2f63b5f2ab05a7349979547325f38e65a2f")
                .expect("valid golden V13 request-frame digest")
        );
        assert_eq!(
            Digest::sha256(&response_frame),
            Digest::parse("dde15b66050b34f075a6eae8429beb3ed1f4647e3d759ef1d5b1fcec0fffb7e6")
                .expect("valid golden V13 response-frame digest")
        );
        assert_eq!(
            sprint_spec_digest(&legacy_sprint()).expect("legacy sprint digest"),
            Digest::parse("f80d0ab639ff9ec147287d118ba75f88b4ecf1d039adf99964916bae2914b74b")
                .expect("valid frozen sprint-digest-V1 fixture")
        );
    }

    #[test]
    fn v13_rejects_wrong_domains_and_crossed_graph_spec_and_reserve() {
        let baseline = request();
        let RunnerSprintAuthorityRequestV13::ValidateSprintAuthority {
            sprint_spec,
            task_graph,
            expected_sprint_spec_digest,
            expected_task_graph_digest,
            expected_task_graph_payload_digest,
            expected_repair_slot_reserve_digest,
        } = &baseline.request;
        let legacy_domain_over_current_bytes = unframed_domain_digest(
            b"grok-build/sprint-spec/v1\0",
            &sprint_spec.canonical_bytes().expect("current sprint bytes"),
        );
        assert_ne!(
            *expected_sprint_spec_digest,
            legacy_domain_over_current_bytes
        );
        assert_ne!(
            *expected_sprint_spec_digest,
            sprint_spec
                .canonical_digest()
                .expect("core V2 sprint digest")
        );
        assert_ne!(
            *expected_task_graph_digest,
            *expected_task_graph_payload_digest
        );
        assert_ne!(
            *expected_task_graph_digest,
            *expected_repair_slot_reserve_digest
        );
        task_graph
            .validate_for_sprint(sprint_spec)
            .expect("baseline pair validates");

        let mut wrong_sprint_domain = baseline.clone();
        let RunnerSprintAuthorityRequestV13::ValidateSprintAuthority {
            expected_sprint_spec_digest,
            sprint_spec,
            ..
        } = &mut wrong_sprint_domain.request;
        *expected_sprint_spec_digest = sprint_spec.canonical_digest().expect("wrong core domain");
        assert!(encode_sprint_authority_request_frame_v13(&wrong_sprint_domain).is_err());

        let mut wrong_graph_domain = baseline.clone();
        let RunnerSprintAuthorityRequestV13::ValidateSprintAuthority {
            expected_task_graph_digest,
            expected_task_graph_payload_digest,
            ..
        } = &mut wrong_graph_domain.request;
        expected_task_graph_digest.clone_from(expected_task_graph_payload_digest);
        assert!(encode_sprint_authority_request_frame_v13(&wrong_graph_domain).is_err());

        let mut crossed_pair = baseline.clone();
        let (other_spec, _) = v2_pair("Crossed objective");
        let RunnerSprintAuthorityRequestV13::ValidateSprintAuthority { sprint_spec, .. } =
            &mut crossed_pair.request;
        **sprint_spec = other_spec;
        assert!(encode_sprint_authority_request_frame_v13(&crossed_pair).is_err());

        let mut crossed_reserve = baseline;
        let RunnerSprintAuthorityRequestV13::ValidateSprintAuthority {
            expected_repair_slot_reserve_digest,
            ..
        } = &mut crossed_reserve.request;
        *expected_repair_slot_reserve_digest = digest('f');
        assert!(encode_sprint_authority_request_frame_v13(&crossed_reserve).is_err());
    }

    #[test]
    fn v13_rejects_unknown_noncanonical_legacy_and_cross_version_bytes() {
        let request = request();
        let canonical = serde_json::to_vec(&request).expect("canonical V13 request payload");

        let mut whitespace = canonical.clone();
        whitespace.insert(1, b' ');
        assert!(matches!(
            decode_sprint_authority_request_frame_v13(&framed_payload(&whitespace)),
            Err(WireProtocolError::NonCanonical)
        ));

        let unknown = String::from_utf8(canonical.clone())
            .expect("V13 request is UTF-8")
            .replacen("\"request\":", "\"unknown\":true,\"request\":", 1);
        assert!(matches!(
            decode_sprint_authority_request_frame_v13(&framed_payload(unknown.as_bytes())),
            Err(WireProtocolError::InvalidJson(_))
        ));

        let nested_unknown = String::from_utf8(canonical.clone())
            .expect("V13 request is UTF-8")
            .replacen(
                "\"objective\":\"Implement feature\",",
                "\"objective\":\"Implement feature\",\"unknown\":true,",
                1,
            );
        assert!(matches!(
            decode_sprint_authority_request_frame_v13(&framed_payload(nested_unknown.as_bytes())),
            Err(WireProtocolError::InvalidJson(_))
        ));

        let mut wrong_version = request.clone();
        wrong_version.protocol_version = 12;
        let wrong_version_payload =
            serde_json::to_vec(&wrong_version).expect("wrong-version V13 payload");
        assert!(matches!(
            decode_sprint_authority_request_frame_v13(&framed_payload(&wrong_version_payload)),
            Err(WireProtocolError::Version {
                expected: 13,
                actual: 12
            })
        ));

        let legacy_sprint_payload =
            serde_json::to_vec(&legacy_sprint()).expect("canonical legacy sprint payload");
        assert!(
            decode_sprint_authority_request_frame_v13(&framed_payload(&legacy_sprint_payload))
                .is_err()
        );

        let v13_frame = encode_sprint_authority_request_frame_v13(&request)
            .expect("canonical V13 request frame");
        assert!(decode_request_frame(&v13_frame).is_err());
        assert!(decode_request_frame_v12(&v13_frame).is_err());
    }

    #[test]
    fn v13_response_rejects_crossed_readback_and_noncanonical_bytes() {
        let request = request();
        let mut crossed = RunnerSprintAuthorityResponseEnvelopeV13::readback_for(&request)
            .expect("derive V13 response");
        let RunnerSprintAuthorityResponseV13::SprintAuthorityReadback { readback } =
            &mut crossed.response;
        readback.task_graph_digest = digest('f');
        assert!(crossed.validate_correlation(&request).is_err());

        let response = RunnerSprintAuthorityResponseEnvelopeV13::readback_for(&request)
            .expect("derive V13 response");
        let mut payload = serde_json::to_vec(&response).expect("canonical V13 response payload");
        payload.push(b'\n');
        assert!(matches!(
            decode_sprint_authority_response_frame_v13(&framed_payload(&payload)),
            Err(WireProtocolError::NonCanonical)
        ));

        let mut wrong_version = response.clone();
        wrong_version.protocol_version = 12;
        let wrong_version_payload =
            serde_json::to_vec(&wrong_version).expect("wrong-version V13 response payload");
        assert!(matches!(
            decode_sprint_authority_response_frame_v13(&framed_payload(&wrong_version_payload)),
            Err(WireProtocolError::Version {
                expected: 13,
                actual: 12
            })
        ));

        let response_frame = encode_sprint_authority_response_frame_v13(&response)
            .expect("canonical V13 response frame");
        assert!(decode_response_frame(&response_frame).is_err());
        assert!(decode_response_frame_v12(&response_frame).is_err());
    }

    #[test]
    fn v13_role_exact_commands_round_trip_and_correlate_without_dispatch_authority() {
        for request in [worker_command_request(), final_verifier_command_request()] {
            let frame = encode_command_request_frame_v13(&request)
                .expect("encode exact V13 command request");
            assert_eq!(
                decode_command_request_frame_v13(&frame).expect("decode exact V13 command request"),
                request
            );
            let response = RunnerCommandResponseEnvelopeV13::readback_for(&request)
                .expect("derive exact V13 command readback");
            response
                .validate_correlation(&request)
                .expect("correlate exact V13 command readback");
            let response_frame = encode_command_response_frame_v13(&response)
                .expect("encode exact V13 command response");
            decode_command_response_frame_v13(&response_frame)
                .expect("decode exact V13 command response")
                .validate_correlation(&request)
                .expect("correlate decoded V13 command response");

            let authority = test_command_effect_authority_v13(
                request.clone(),
                request.sprint_spec.workspace_grant.grant_hash.clone(),
            )
            .expect("mint test-only service-validated V13 command authority");
            authority
                .validate_integrity()
                .expect("revalidate exact V13 command authority");
            assert_eq!(authority.envelope().request.role(), request.request.role());
            assert_eq!(authority.effect(), &request.effect);
        }
    }

    #[test]
    fn v13_role_exact_command_frame_pairs_remain_byte_exact() {
        for (request, expected_request_digest, expected_response_digest) in [
            (
                worker_command_request(),
                "7b00866818929757a269b3fb891761433b39d040492fc2eb56b42775e73e85e1",
                "983b5b3cb464887a1dff7630e5eb8cba599c44dd673e16df33e2dad3b383a100",
            ),
            (
                final_verifier_command_request(),
                "050fafc6e21d01293ac947214023da0626c5c7e7f8989f39b943d09e3209af11",
                "a1ac0c403b0abb1c777334b237a4bd7d354f9aace3150d532196a90f5be004be",
            ),
        ] {
            let request_frame = encode_command_request_frame_v13(&request)
                .expect("encode golden V13 command request");
            let response = RunnerCommandResponseEnvelopeV13::readback_for(&request)
                .expect("derive golden V13 command response");
            let response_frame = encode_command_response_frame_v13(&response)
                .expect("encode golden V13 command response");
            assert_eq!(
                Digest::sha256(&request_frame),
                Digest::parse(expected_request_digest)
                    .expect("valid golden V13 command request-frame digest"),
                "{:?} request-frame bytes changed",
                request.request.role()
            );
            assert_eq!(
                Digest::sha256(&response_frame),
                Digest::parse(expected_response_digest)
                    .expect("valid golden V13 command response-frame digest"),
                "{:?} response-frame bytes changed",
                request.request.role()
            );
        }
    }

    #[test]
    fn v13_worker_rejects_nonmember_crossed_attempt_lease_and_dormant_repair() {
        let baseline = worker_command_request();

        let mut nonexistent = baseline.clone();
        let RunnerCommandRequestV13::WorkerRunCommand { task, .. } = &mut nonexistent.request
        else {
            unreachable!()
        };
        task.task_id = "not-in-graph".into();
        assert!(nonexistent.bind_transport_commitment_digest().is_err());

        let mut crossed_member = baseline.clone();
        let RunnerCommandRequestV13::WorkerRunCommand { task, .. } = &mut crossed_member.request
        else {
            unreachable!()
        };
        task.goal = "caller-crossed task semantics".into();
        assert!(crossed_member.bind_transport_commitment_digest().is_err());

        let mut crossed_attempt = baseline.clone();
        let RunnerCommandRequestV13::WorkerRunCommand {
            running_boundary, ..
        } = &mut crossed_attempt.request
        else {
            unreachable!()
        };
        running_boundary.runner_session_id = "crossed-session".into();
        assert!(crossed_attempt.bind_transport_commitment_digest().is_err());

        let mut crossed_lease = baseline.clone();
        let RunnerCommandRequestV13::WorkerRunCommand {
            running_boundary, ..
        } = &mut crossed_lease.request
        else {
            unreachable!()
        };
        running_boundary.attempt.worker_lease.path_scopes = vec![PathScope::Workspace];
        assert!(crossed_lease.bind_transport_commitment_digest().is_err());

        let mut dormant_repair = baseline;
        let repair_task = dormant_repair.task_graph.tasks[1].clone();
        let RunnerCommandRequestV13::WorkerRunCommand { task, .. } = &mut dormant_repair.request
        else {
            unreachable!()
        };
        **task = repair_task;
        assert!(dormant_repair.bind_transport_commitment_digest().is_err());
    }

    #[test]
    fn v13_final_verifier_rejects_attempt_snapshot_command_policy_and_scope_crossings() {
        let baseline = final_verifier_command_request();
        for mutation in 0..5 {
            let mut crossed = baseline.clone();
            let RunnerCommandRequestV13::FinalVerifierRunCommand {
                final_verification_attempt,
                ..
            } = &mut crossed.request
            else {
                unreachable!()
            };
            match mutation {
                0 => final_verification_attempt.sprint_id = "crossed-sprint".into(),
                1 => final_verification_attempt.input_snapshot = digest('a'),
                2 => {
                    final_verification_attempt
                        .final_verification_check
                        .arguments = vec!["check".into()];
                }
                3 => final_verification_attempt.execution_policy_digest = digest('a'),
                4 => crossed.effect.task_id = Some("caller-task".into()),
                _ => unreachable!(),
            }
            assert!(
                crossed.bind_transport_commitment_digest().is_err(),
                "final-verifier crossing {mutation} must fail closed"
            );
        }
    }

    #[test]
    fn v13_worker_and_final_verifier_share_every_strict_runner_command_rejection() {
        let mutations = [
            InvalidWireCommandMutation::Shell,
            InvalidWireCommandMutation::Wrapper,
            InvalidWireCommandMutation::OversizedProgram,
            InvalidWireCommandMutation::TooManyArguments,
            InvalidWireCommandMutation::OversizedArgument,
            InvalidWireCommandMutation::ProgramNul,
            InvalidWireCommandMutation::ArgumentNul,
            InvalidWireCommandMutation::AbsoluteWorkingDirectory,
            InvalidWireCommandMutation::ParentWorkingDirectory,
            InvalidWireCommandMutation::WorkingDirectoryNul,
            InvalidWireCommandMutation::OversizedWorkingDirectory,
        ];
        for baseline in [worker_command_request(), final_verifier_command_request()] {
            for mutation in mutations {
                let mut request = baseline.clone();
                mutate_v13_command(&mut request, mutation);
                let error = request
                    .bind_transport_commitment_digest()
                    .expect_err("strict runner command mutation must fail before commitment");
                let WireProtocolError::InvalidContract(message) = error else {
                    panic!("strict runner command mutation returned the wrong error class");
                };
                assert_eq!(message, mutation.expected_message());
            }
        }
    }

    #[test]
    fn v13_command_rejects_v12_substitution_unknown_fields_and_reordered_bytes() {
        let request = worker_command_request();
        let v13_frame =
            encode_command_request_frame_v13(&request).expect("encode exact V13 command frame");
        assert!(decode_request_frame_v12(&v13_frame).is_err());
        assert!(decode_request_frame(&v13_frame).is_err());

        let v12 = v12_substitution_for(&request);
        let v12_frame = encode_request_frame_v12(&v12).expect("encode exact V12 substitution");
        assert!(decode_command_request_frame_v13(&v12_frame).is_err());

        let canonical = serde_json::to_vec(&request).expect("encode canonical V13 command payload");
        let unknown = String::from_utf8(canonical.clone())
            .expect("V13 command payload is UTF-8")
            .replacen("\"request\":", "\"unknown\":true,\"request\":", 1);
        assert!(matches!(
            decode_command_request_frame_v13(&framed_payload(unknown.as_bytes())),
            Err(WireProtocolError::InvalidJson(_))
        ));

        let value: serde_json::Value =
            serde_json::from_slice(&canonical).expect("decode canonical V13 command value");
        let reordered = serde_json::to_vec(&value).expect("encode reordered object keys");
        assert_ne!(
            reordered, canonical,
            "fixture must actually reorder object keys"
        );
        assert!(matches!(
            decode_command_request_frame_v13(&framed_payload(&reordered)),
            Err(WireProtocolError::NonCanonical)
        ));
    }

    #[test]
    fn v13_dormant_session_frames_round_trip_and_close_exactly() {
        let (initialization, initialization_receipt, command, terminal, shutdown, receipt) =
            dormant_transcript();

        let initialization_frame =
            encode_final_verifier_initialization_request_frame_v13(&initialization)
                .expect("encode initialization");
        assert_eq!(
            decode_final_verifier_initialization_request_frame_v13(&initialization_frame)
                .expect("decode initialization"),
            initialization
        );
        let initialization_receipt_frame =
            encode_final_verifier_initialization_receipt_frame_v13(&initialization_receipt)
                .expect("encode initialization receipt");
        let decoded_initialization_receipt =
            decode_final_verifier_initialization_receipt_frame_v13(&initialization_receipt_frame)
                .expect("decode initialization receipt");
        decoded_initialization_receipt
            .validate_correlation(&initialization)
            .expect("correlate initialization receipt");
        assert_eq!(decoded_initialization_receipt, initialization_receipt);

        let terminal_frame =
            encode_raw_terminal_response_frame_v13(&terminal).expect("encode raw terminal");
        let decoded_terminal =
            decode_raw_terminal_response_frame_v13(&terminal_frame).expect("decode raw terminal");
        decoded_terminal
            .validate_correlation(&command)
            .expect("correlate raw terminal");
        assert_eq!(decoded_terminal, terminal);

        let shutdown_frame =
            encode_shutdown_request_frame_v13(&shutdown).expect("encode shutdown request");
        assert_eq!(
            decode_shutdown_request_frame_v13(&shutdown_frame).expect("decode shutdown request"),
            shutdown
        );
        let receipt_frame =
            encode_shutdown_receipt_frame_v13(&receipt).expect("encode shutdown receipt");
        let decoded_receipt =
            decode_shutdown_receipt_frame_v13(&receipt_frame).expect("decode shutdown receipt");
        decoded_receipt
            .validate_correlation(&shutdown)
            .expect("correlate shutdown receipt");
        assert_eq!(decoded_receipt, receipt);

        let mut validator = DormantFinalVerifierSessionValidatorV13::new();
        validator
            .accept_initialization_request(&initialization)
            .expect("accept initialization");
        validator
            .accept_initialization_receipt(&initialization_receipt)
            .expect("accept initialization receipt");
        validator
            .accept_command_request(&command)
            .expect("accept sole command");
        validator
            .accept_terminal_response(&terminal)
            .expect("accept raw terminal");
        validator
            .accept_shutdown_request(&shutdown)
            .expect("accept shutdown");
        validator
            .accept_shutdown_receipt(&receipt)
            .expect("accept shutdown receipt");
        assert!(validator.is_closed());
    }

    #[test]
    fn v13_dormant_session_frame_digests_remain_byte_exact() {
        let (initialization, initialization_receipt, _, terminal, shutdown, receipt) =
            dormant_transcript();
        let actual = [
            Digest::sha256(
                &encode_final_verifier_initialization_request_frame_v13(&initialization)
                    .expect("encode golden initialization request"),
            ),
            Digest::sha256(
                &encode_final_verifier_initialization_receipt_frame_v13(&initialization_receipt)
                    .expect("encode golden initialization receipt"),
            ),
            Digest::sha256(
                &encode_raw_terminal_response_frame_v13(&terminal)
                    .expect("encode golden raw terminal response"),
            ),
            Digest::sha256(
                &encode_shutdown_request_frame_v13(&shutdown)
                    .expect("encode golden shutdown request"),
            ),
            Digest::sha256(
                &encode_shutdown_receipt_frame_v13(&receipt)
                    .expect("encode golden shutdown receipt"),
            ),
        ];
        let expected = [
            "bb17cd46ad2d742c711cec432f14172e093e8c219236538a239b1c68c7dd9704",
            "0f937d11ce282967f6210e82b6e6f405483a6b05f1f45e0cd4cf0007f8fb62f2",
            "cf5ddd86a978e68cab6c310b4aaf7d66e651bd9afd79bbb36bae5bccb632a967",
            "51d2184ba2456cc7366fdba02c67d6f071b868c8acc30cf567d77fe32fb1a6cc",
            "8a78b9e3951593087fe91bb8a812e045f6bef3f5d07f08bc7a1c41ec7f9d6509",
        ]
        .map(|value| Digest::parse(value).expect("valid fixed V13 session-frame digest"));
        assert_eq!(actual, expected);
    }

    #[test]
    fn v13_every_raw_terminal_variant_has_a_fixed_frame_digest() {
        let command = final_verifier_command_request();
        let capture_ceiling = command
            .request
            .output_capture()
            .acquired()
            .max_aggregate_output_bytes;
        let limit = capture_ceiling
            .checked_sub(COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES)
            .expect("fixture capture ceiling contains the bounded drain");
        assert_eq!(
            command_output_capture_maximum(limit).expect("fixture policy-plus-drain ceiling"),
            capture_ceiling
        );
        let outcomes = [
            RunnerRawTerminalOutcomeV13::Exited { exit_code: 0 },
            RunnerRawTerminalOutcomeV13::Signaled {
                signal: 9,
                core_dumped: true,
            },
            RunnerRawTerminalOutcomeV13::TimedOut,
            RunnerRawTerminalOutcomeV13::OutputLimitExceeded {
                limit_bytes: limit,
                observed_at_least_bytes: limit,
            },
            RunnerRawTerminalOutcomeV13::RunnerCanceled,
            RunnerRawTerminalOutcomeV13::ProvenNoEffect {
                proof_id: "no-effect-proof-v13-1".into(),
                proof_digest: digest('5'),
            },
            RunnerRawTerminalOutcomeV13::Unknown {
                reason: RunnerRawTerminalUnknownReasonV13::EffectBoundaryUncertain,
                reconciliation_id: "reconciliation-v13-1".into(),
            },
        ];
        let actual = outcomes.map(|outcome| {
            let response =
                RunnerRawTerminalResponseV13::correlation_projection_for(&command, outcome)
                    .expect("construct golden raw terminal variant");
            let frame = encode_raw_terminal_response_frame_v13(&response)
                .expect("encode golden raw terminal variant");
            Digest::sha256(&frame)
        });
        let expected = [
            "1eb46eecd6e9cf7978ca9be1ec56119bb82ece387359a29ee3f3d65388c4a02b",
            "a4049fb606109afb8d1ab8d14a7cd7804762de50397cbfcc592d7d8753676864",
            "94e05df6ee3b52c1dbfce2a1c95366892428da6458d5c48e78e8dbd85e7f6282",
            "8183339f88427fbc0272c188731996bc39eee476d5d255015f390062461500d8",
            "81563d84bb8c240acdf67bc31dcf22c9ecd585c9f120ddc018f78c7569ab05b3",
            "d3f95b8f4e5369f897c91cc9d1dc6464e859607352bdc2d3f44b973fa5e82f9b",
            "a5b48dd32b7898c5508bb24225ea5767fa482ed57cfc68728d431fded4a67d8f",
        ]
        .map(|value| Digest::parse(value).expect("valid fixed raw-terminal frame digest"));
        assert_eq!(actual, expected);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the V13 terminal matrix exhaustively crosses bounded raw outcomes and capture custody"
    )]
    fn v13_raw_terminal_closed_outcomes_are_bounded_and_non_authorizing() {
        let command = final_verifier_command_request();
        let capture_ceiling = command
            .request
            .output_capture()
            .acquired()
            .max_aggregate_output_bytes;
        let limit = capture_ceiling
            .checked_sub(COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES)
            .expect("fixture capture ceiling contains the bounded drain");
        let outcomes = [
            RunnerRawTerminalOutcomeV13::Exited { exit_code: 0 },
            RunnerRawTerminalOutcomeV13::Exited { exit_code: 255 },
            RunnerRawTerminalOutcomeV13::Signaled {
                signal: 9,
                core_dumped: false,
            },
            RunnerRawTerminalOutcomeV13::TimedOut,
            RunnerRawTerminalOutcomeV13::OutputLimitExceeded {
                limit_bytes: limit,
                observed_at_least_bytes: limit,
            },
            RunnerRawTerminalOutcomeV13::RunnerCanceled,
            RunnerRawTerminalOutcomeV13::ProvenNoEffect {
                proof_id: "no-effect-proof-v13-1".into(),
                proof_digest: digest('5'),
            },
            RunnerRawTerminalOutcomeV13::Unknown {
                reason: RunnerRawTerminalUnknownReasonV13::EffectBoundaryUncertain,
                reconciliation_id: "reconciliation-v13-1".into(),
            },
        ];
        for outcome in outcomes {
            let response =
                RunnerRawTerminalResponseV13::correlation_projection_for(&command, outcome.clone())
                    .expect("construct closed raw outcome");
            let frame = encode_raw_terminal_response_frame_v13(&response)
                .expect("encode closed raw outcome");
            let decoded =
                decode_raw_terminal_response_frame_v13(&frame).expect("decode closed raw outcome");
            decoded
                .validate_correlation(&command)
                .expect("correlate closed raw outcome");
            assert_eq!(decoded.outcome, outcome);
        }

        for observed_at_least_bytes in [
            limit,
            capture_ceiling
                .checked_sub(1)
                .expect("capture ceiling exceeds zero"),
            capture_ceiling,
        ] {
            RunnerRawTerminalResponseV13::correlation_projection_for(
                &command,
                RunnerRawTerminalOutcomeV13::OutputLimitExceeded {
                    limit_bytes: limit,
                    observed_at_least_bytes,
                },
            )
            .expect("observation from policy limit through capture ceiling is bounded");
        }

        for invalid_outcome in [
            RunnerRawTerminalOutcomeV13::Signaled {
                signal: 0,
                core_dumped: false,
            },
            RunnerRawTerminalOutcomeV13::OutputLimitExceeded {
                limit_bytes: limit.saturating_sub(1),
                observed_at_least_bytes: limit,
            },
            RunnerRawTerminalOutcomeV13::OutputLimitExceeded {
                limit_bytes: limit,
                observed_at_least_bytes: limit.saturating_sub(1),
            },
            RunnerRawTerminalOutcomeV13::OutputLimitExceeded {
                limit_bytes: capture_ceiling,
                observed_at_least_bytes: capture_ceiling,
            },
            RunnerRawTerminalOutcomeV13::OutputLimitExceeded {
                limit_bytes: limit,
                observed_at_least_bytes: capture_ceiling
                    .checked_add(1)
                    .expect("fixture capture ceiling is below u64::MAX"),
            },
            RunnerRawTerminalOutcomeV13::ProvenNoEffect {
                proof_id: String::new(),
                proof_digest: digest('5'),
            },
            RunnerRawTerminalOutcomeV13::Unknown {
                reason: RunnerRawTerminalUnknownReasonV13::CleanupUnresolved,
                reconciliation_id: String::new(),
            },
        ] {
            assert!(
                RunnerRawTerminalResponseV13::correlation_projection_for(
                    &command,
                    invalid_outcome,
                )
                .is_err()
            );
        }

        let source = command.request.output_capture().acquired().source.clone();
        let private_state_digest = command
            .request
            .output_capture()
            .acquired()
            .private_state_digest
            .clone();
        let mut noninvertible_capture = command.clone();
        let replacement = test_command_output_capture_anchor(
            source,
            private_state_digest,
            COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES,
            99,
        );
        let RunnerCommandRequestV13::FinalVerifierRunCommand { output_capture, .. } =
            &mut noninvertible_capture.request
        else {
            unreachable!()
        };
        *output_capture = replacement;
        noninvertible_capture
            .bind_transport_commitment_digest()
            .expect("bind otherwise-valid capture ceiling");
        assert!(matches!(
            RunnerRawTerminalResponseV13::correlation_projection_for(
                &noninvertible_capture,
                RunnerRawTerminalOutcomeV13::OutputLimitExceeded {
                    limit_bytes: 1,
                    observed_at_least_bytes: 1,
                },
            ),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("cannot encode a positive execution-policy output ceiling")
        ));

        let mut directly_forged = RunnerRawTerminalResponseV13::correlation_projection_for(
            &command,
            RunnerRawTerminalOutcomeV13::Exited { exit_code: 0 },
        )
        .expect("baseline terminal response");
        directly_forged.outcome = RunnerRawTerminalOutcomeV13::Signaled {
            signal: 0,
            core_dumped: false,
        };
        directly_forged.response_commitment_digest = directly_forged
            .computed_response_commitment_digest()
            .expect("rebind attacker-selected malformed outcome");
        assert!(encode_raw_terminal_response_frame_v13(&directly_forged).is_err());
        let payload = serde_json::to_vec(&directly_forged).expect("malformed terminal payload");
        assert!(decode_raw_terminal_response_frame_v13(&framed_payload(&payload)).is_err());
    }

    #[test]
    fn v13_dormant_session_rejects_every_replay_and_order_violation() {
        let (initialization, initialization_receipt, command, terminal, shutdown, receipt) =
            dormant_transcript();

        let mut before_init = DormantFinalVerifierSessionValidatorV13::new();
        assert!(before_init.accept_terminal_response(&terminal).is_err());
        assert!(before_init.accept_command_request(&command).is_err());
        assert!(before_init.accept_shutdown_request(&shutdown).is_err());
        assert!(before_init.accept_shutdown_receipt(&receipt).is_err());

        let mut validator = DormantFinalVerifierSessionValidatorV13::new();
        validator
            .accept_initialization_request(&initialization)
            .expect("accept initialization");
        assert!(
            validator
                .accept_initialization_request(&initialization)
                .is_err()
        );
        assert!(validator.accept_command_request(&command).is_err());
        validator
            .accept_initialization_receipt(&initialization_receipt)
            .expect("accept receipt");
        assert!(
            validator
                .accept_initialization_receipt(&initialization_receipt)
                .is_err()
        );
        assert!(validator.accept_terminal_response(&terminal).is_err());
        validator
            .accept_command_request(&command)
            .expect("accept command");
        assert!(validator.accept_command_request(&command).is_err());
        assert!(validator.accept_shutdown_request(&shutdown).is_err());
        validator
            .accept_terminal_response(&terminal)
            .expect("accept terminal");
        assert!(validator.accept_terminal_response(&terminal).is_err());
        validator
            .accept_shutdown_request(&shutdown)
            .expect("accept shutdown");
        assert!(validator.accept_shutdown_request(&shutdown).is_err());
        validator
            .accept_shutdown_receipt(&receipt)
            .expect("accept shutdown receipt");
        assert!(validator.accept_shutdown_receipt(&receipt).is_err());
        assert!(
            validator
                .accept_initialization_request(&initialization)
                .is_err()
        );
        assert!(validator.accept_command_request(&command).is_err());
        assert!(validator.accept_terminal_response(&terminal).is_err());
    }

    #[test]
    fn v13_dormant_session_rejects_every_wrong_sequence() {
        let (initialization, initialization_receipt, command, terminal, shutdown, receipt) =
            dormant_transcript();

        let mut wrong_initialization = initialization.clone();
        wrong_initialization.sequence = 1;
        assert!(
            wrong_initialization
                .bind_request_commitment_digest()
                .is_err()
        );

        let mut wrong_initialization_receipt = initialization_receipt;
        wrong_initialization_receipt.sequence = 1;
        wrong_initialization_receipt.receipt_commitment_digest = wrong_initialization_receipt
            .computed_receipt_commitment_digest()
            .expect("rebind wrong initialization receipt sequence");
        assert!(wrong_initialization_receipt.validate_shape().is_err());

        let mut wrong_command = command;
        wrong_command.sequence = 2;
        wrong_command
            .bind_transport_commitment_digest()
            .expect("existing V13 envelope permits a positive dormant sequence");
        let exact_initialization = final_verifier_initialization_request();
        let exact_receipt =
            RunnerFinalVerifierInitializationReceiptV13::correlation_projection_for(
                &exact_initialization,
                wrong_command.runner_nonce.clone(),
            )
            .expect("exact initialization receipt");
        let mut validator = DormantFinalVerifierSessionValidatorV13::new();
        validator
            .accept_initialization_request(&exact_initialization)
            .expect("accept initialization");
        validator
            .accept_initialization_receipt(&exact_receipt)
            .expect("accept initialization receipt");
        assert!(validator.accept_command_request(&wrong_command).is_err());

        let mut wrong_terminal = terminal;
        wrong_terminal.sequence = 2;
        wrong_terminal.response_commitment_digest = wrong_terminal
            .computed_response_commitment_digest()
            .expect("rebind wrong terminal sequence");
        assert!(wrong_terminal.validate_shape().is_err());

        let mut wrong_shutdown = shutdown;
        wrong_shutdown.sequence = 3;
        wrong_shutdown.request_commitment_digest = wrong_shutdown
            .computed_request_commitment_digest()
            .expect("rebind wrong shutdown sequence");
        assert!(wrong_shutdown.validate().is_err());

        let mut wrong_shutdown_receipt = receipt;
        wrong_shutdown_receipt.sequence = 3;
        wrong_shutdown_receipt.receipt_commitment_digest = wrong_shutdown_receipt
            .computed_receipt_commitment_digest()
            .expect("rebind wrong shutdown receipt sequence");
        assert!(wrong_shutdown_receipt.validate_shape().is_err());
    }

    #[test]
    fn v13_dormant_session_crosses_attempt_capture_nonce_and_request_identity() {
        let baseline_command = final_verifier_command_request();

        let mut crossed_attempt_initialization = final_verifier_initialization_request();
        crossed_attempt_initialization
            .final_verification_attempt
            .provenance
            .coordinator_instance_id = "crossed-coordinator-v13".into();
        crossed_attempt_initialization
            .bind_request_commitment_digest()
            .expect("rebind individually valid crossed attempt initialization");
        let crossed_attempt_receipt =
            RunnerFinalVerifierInitializationReceiptV13::correlation_projection_for(
                &crossed_attempt_initialization,
                baseline_command.runner_nonce.clone(),
            )
            .expect("crossed attempt receipt");
        let mut validator = DormantFinalVerifierSessionValidatorV13::new();
        validator
            .accept_initialization_request(&crossed_attempt_initialization)
            .expect("accept crossed attempt initialization");
        validator
            .accept_initialization_receipt(&crossed_attempt_receipt)
            .expect("accept crossed attempt receipt");
        assert!(validator.accept_command_request(&baseline_command).is_err());

        let mut crossed_capture_initialization = final_verifier_initialization_request();
        crossed_capture_initialization.output_capture = test_command_output_capture_anchor(
            crossed_capture_initialization
                .output_capture
                .acquired()
                .source
                .clone(),
            crossed_capture_initialization
                .expected_private_state_digest
                .clone(),
            crossed_capture_initialization
                .output_capture
                .acquired()
                .max_aggregate_output_bytes,
            77,
        );
        crossed_capture_initialization
            .bind_request_commitment_digest()
            .expect("rebind individually valid crossed capture initialization");
        let crossed_capture_receipt =
            RunnerFinalVerifierInitializationReceiptV13::correlation_projection_for(
                &crossed_capture_initialization,
                baseline_command.runner_nonce.clone(),
            )
            .expect("crossed capture receipt");
        let mut validator = DormantFinalVerifierSessionValidatorV13::new();
        validator
            .accept_initialization_request(&crossed_capture_initialization)
            .expect("accept crossed capture initialization");
        validator
            .accept_initialization_receipt(&crossed_capture_receipt)
            .expect("accept crossed capture receipt");
        assert!(validator.accept_command_request(&baseline_command).is_err());

        let initialization = final_verifier_initialization_request();
        let nonce_crossed_receipt =
            RunnerFinalVerifierInitializationReceiptV13::correlation_projection_for(
                &initialization,
                digest('a'),
            )
            .expect("nonce-crossed receipt remains valid for initialization");
        let mut validator = DormantFinalVerifierSessionValidatorV13::new();
        validator
            .accept_initialization_request(&initialization)
            .expect("accept initialization");
        validator
            .accept_initialization_receipt(&nonce_crossed_receipt)
            .expect("accept nonce readback");
        assert!(validator.accept_command_request(&baseline_command).is_err());

        let initialization = final_verifier_initialization_request();
        let receipt = RunnerFinalVerifierInitializationReceiptV13::correlation_projection_for(
            &initialization,
            baseline_command.runner_nonce.clone(),
        )
        .expect("exact receipt");
        let mut reused_id_command = baseline_command;
        reused_id_command.request_id = initialization.request_id.clone();
        reused_id_command
            .bind_transport_commitment_digest()
            .expect("rebind individually valid reused request identity");
        let mut validator = DormantFinalVerifierSessionValidatorV13::new();
        validator
            .accept_initialization_request(&initialization)
            .expect("accept initialization");
        validator
            .accept_initialization_receipt(&receipt)
            .expect("accept receipt");
        assert!(
            validator
                .accept_command_request(&reused_id_command)
                .is_err()
        );
    }

    #[test]
    fn v13_raw_terminal_and_shutdown_reject_crossed_identifiers() {
        let (_, _, command, terminal, shutdown, _) = dormant_transcript();
        for mutation in 0..5 {
            let mut crossed = terminal.clone();
            match mutation {
                0 => crossed.session_id = "crossed-session-v13".into(),
                1 => crossed.request_id = "crossed-request-v13".into(),
                2 => crossed.effect_id = "crossed-effect-v13".into(),
                3 => crossed.capture_id = "crossed-capture-v13".into(),
                4 => crossed.attempt_id = "crossed-attempt-v13".into(),
                _ => unreachable!(),
            }
            crossed.response_commitment_digest = crossed
                .computed_response_commitment_digest()
                .expect("rebind crossed terminal shape");
            assert!(crossed.validate_correlation(&command).is_err());
        }

        for mutation in 0..3 {
            let mut crossed = shutdown.clone();
            match mutation {
                0 => crossed.session_id = "crossed-session-v13".into(),
                1 => crossed.runner_nonce = digest('a'),
                2 => crossed.terminal_response_commitment_digest = digest('b'),
                _ => unreachable!(),
            }
            crossed.request_commitment_digest = crossed
                .computed_request_commitment_digest()
                .expect("rebind crossed shutdown shape");
            let mut validator = DormantFinalVerifierSessionValidatorV13::new();
            let (initialization, initialization_receipt, command, terminal, _, _) =
                dormant_transcript();
            validator
                .accept_initialization_request(&initialization)
                .expect("accept initialization");
            validator
                .accept_initialization_receipt(&initialization_receipt)
                .expect("accept initialization receipt");
            validator
                .accept_command_request(&command)
                .expect("accept command");
            validator
                .accept_terminal_response(&terminal)
                .expect("accept terminal");
            assert!(validator.accept_shutdown_request(&crossed).is_err());
        }
    }

    #[test]
    fn v13_initialization_rejects_crossed_current_and_platform_bindings() {
        let baseline = final_verifier_initialization_request();
        for mutation in 0..9 {
            let mut crossed = baseline.clone();
            match mutation {
                0 => crossed.expected_sprint_spec_digest = digest('9'),
                1 => crossed.expected_task_graph_digest = digest('9'),
                2 => crossed.expected_task_graph_payload_digest = digest('9'),
                3 => crossed.expected_repair_slot_reserve_digest = digest('9'),
                4 => crossed.expected_grant_hash = digest('9'),
                5 => crossed.expected_input_snapshot = digest('9'),
                6 => crossed.expected_policy_hash = digest('9'),
                7 => crossed.expected_private_state_digest = digest('9'),
                8 => crossed.expected_binary_identity.link_count = 2,
                _ => unreachable!(),
            }
            assert!(
                crossed.bind_request_commitment_digest().is_err(),
                "initialization crossing {mutation} must fail"
            );
        }
    }

    #[test]
    fn v13_new_frames_reject_unknown_fields() {
        let (initialization, initialization_receipt, _, terminal, shutdown, receipt) =
            dormant_transcript();
        let payloads = [
            serde_json::to_vec(&initialization).expect("initialization payload"),
            serde_json::to_vec(&initialization_receipt).expect("initialization receipt payload"),
            serde_json::to_vec(&terminal).expect("terminal payload"),
            serde_json::to_vec(&shutdown).expect("shutdown payload"),
            serde_json::to_vec(&receipt).expect("shutdown receipt payload"),
        ];
        for (index, payload) in payloads.iter().enumerate() {
            let unknown = String::from_utf8(payload.clone())
                .expect("V13 payload is UTF-8")
                .replacen(
                    "\"protocol_version\":",
                    "\"unknown\":true,\"protocol_version\":",
                    1,
                );
            let result = match index {
                0 => decode_final_verifier_initialization_request_frame_v13(&framed_payload(
                    unknown.as_bytes(),
                ))
                .map(|_| ()),
                1 => decode_final_verifier_initialization_receipt_frame_v13(&framed_payload(
                    unknown.as_bytes(),
                ))
                .map(|_| ()),
                2 => decode_raw_terminal_response_frame_v13(&framed_payload(unknown.as_bytes()))
                    .map(|_| ()),
                3 => decode_shutdown_request_frame_v13(&framed_payload(unknown.as_bytes()))
                    .map(|_| ()),
                4 => decode_shutdown_receipt_frame_v13(&framed_payload(unknown.as_bytes()))
                    .map(|_| ()),
                _ => unreachable!(),
            };
            assert!(matches!(result, Err(WireProtocolError::InvalidJson(_))));
        }
    }

    #[test]
    fn v13_new_frames_reject_wrong_versions_and_legacy_bytes() {
        let (initialization, initialization_receipt, command, terminal, shutdown, receipt) =
            dormant_transcript();
        let mut wrong_initialization = initialization.clone();
        wrong_initialization.protocol_version = 12;
        let mut wrong_initialization_receipt = initialization_receipt.clone();
        wrong_initialization_receipt.protocol_version = 12;
        let mut wrong_terminal = terminal.clone();
        wrong_terminal.protocol_version = 12;
        let mut wrong_shutdown = shutdown.clone();
        wrong_shutdown.protocol_version = 12;
        let mut wrong_receipt = receipt.clone();
        wrong_receipt.protocol_version = 12;
        assert!(matches!(
            decode_final_verifier_initialization_request_frame_v13(&framed_payload(
                &serde_json::to_vec(&wrong_initialization).expect("wrong initialization version")
            )),
            Err(WireProtocolError::Version {
                expected: 13,
                actual: 12
            })
        ));
        assert!(matches!(
            decode_final_verifier_initialization_receipt_frame_v13(&framed_payload(
                &serde_json::to_vec(&wrong_initialization_receipt)
                    .expect("wrong initialization receipt version")
            )),
            Err(WireProtocolError::Version {
                expected: 13,
                actual: 12
            })
        ));
        assert!(matches!(
            decode_raw_terminal_response_frame_v13(&framed_payload(
                &serde_json::to_vec(&wrong_terminal).expect("wrong terminal version")
            )),
            Err(WireProtocolError::Version {
                expected: 13,
                actual: 12
            })
        ));
        assert!(matches!(
            decode_shutdown_request_frame_v13(&framed_payload(
                &serde_json::to_vec(&wrong_shutdown).expect("wrong shutdown version")
            )),
            Err(WireProtocolError::Version {
                expected: 13,
                actual: 12
            })
        ));
        assert!(matches!(
            decode_shutdown_receipt_frame_v13(&framed_payload(
                &serde_json::to_vec(&wrong_receipt).expect("wrong receipt version")
            )),
            Err(WireProtocolError::Version {
                expected: 13,
                actual: 12
            })
        ));

        let v12 = v12_substitution_for(&command);
        let v12_frame = encode_request_frame_v12(&v12).expect("encode unchanged V12 fixture");
        assert!(decode_final_verifier_initialization_request_frame_v13(&v12_frame).is_err());
        assert!(decode_raw_terminal_response_frame_v13(&v12_frame).is_err());
        assert!(decode_shutdown_request_frame_v13(&v12_frame).is_err());

        for new_frame in [
            encode_final_verifier_initialization_request_frame_v13(&initialization)
                .expect("encode new initialization"),
            encode_raw_terminal_response_frame_v13(&terminal).expect("encode new terminal"),
            encode_shutdown_request_frame_v13(&shutdown).expect("encode new shutdown"),
        ] {
            assert!(decode_request_frame(&new_frame).is_err());
            assert!(decode_request_frame_v12(&new_frame).is_err());
            assert!(decode_response_frame(&new_frame).is_err());
            assert!(decode_response_frame_v12(&new_frame).is_err());
        }
    }

    #[test]
    fn v13_full_initialization_frame_is_rejected_by_the_unchanged_service_router() {
        let initialization = final_verifier_initialization_request();
        let v13_frame = encode_final_verifier_initialization_request_frame_v13(&initialization)
            .expect("encode full canonical V13 initialization");
        assert!(matches!(
            test_decode_service_request_frame(&v13_frame),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("canonical v11 or v12")
        ));

        let v12 = v12_substitution_for(&worker_command_request());
        let v12_frame = encode_request_frame_v12(&v12).expect("encode unchanged V12 request");
        test_decode_service_request_frame(&v12_frame)
            .expect("unchanged service router still admits V12 framing");
        let mut v11 = v12.as_v11_envelope();
        v11.bind_transport_commitment_digest()
            .expect("bind unchanged V11 commitment domain");
        let v11_frame = encode_request_frame(&v11).expect("encode unchanged V11 request");
        test_decode_service_request_frame(&v11_frame)
            .expect("unchanged service router still admits V11 framing");
    }

    #[test]
    fn v13_dormant_session_schema_contains_no_credential_shaped_fields() {
        fn assert_no_credential_keys(value: &serde_json::Value) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, nested) in map {
                        assert!(
                            !matches!(
                                key.as_str(),
                                "environment"
                                    | "api_key"
                                    | "provider_key"
                                    | "access_token"
                                    | "bearer_token"
                                    | "credential"
                                    | "credentials"
                                    | "secret"
                            ),
                            "credential-shaped field {key} is forbidden"
                        );
                        assert_no_credential_keys(nested);
                    }
                }
                serde_json::Value::Array(values) => {
                    for nested in values {
                        assert_no_credential_keys(nested);
                    }
                }
                _ => {}
            }
        }

        let (initialization, initialization_receipt, command, terminal, shutdown, receipt) =
            dormant_transcript();
        for value in [
            serde_json::to_value(initialization).expect("initialization JSON"),
            serde_json::to_value(initialization_receipt).expect("initialization receipt JSON"),
            serde_json::to_value(command).expect("command JSON"),
            serde_json::to_value(terminal).expect("terminal JSON"),
            serde_json::to_value(shutdown).expect("shutdown JSON"),
            serde_json::to_value(receipt).expect("shutdown receipt JSON"),
        ] {
            assert_no_credential_keys(&value);
        }
    }
