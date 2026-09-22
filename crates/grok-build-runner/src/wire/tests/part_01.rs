    use grok_build_core::{
        AcceptanceCriterion, AcceptanceKind, CONTRACT_VERSION, CommandOutputArtifactSetReferenceV1,
        CommandOutputArtifactSourceV1, CommandOutputCaptureStoreHeadV1,
        CommandOutputStreamArtifactV1, CommandOutputStreamV1, EffectIntent, EffectKind,
        ProviderProfile, SprintBudget, WorkerLease,
    };

    use super::*;

    fn digest(byte: u8) -> Digest {
        Digest::sha256(&[byte])
    }

    fn command_request_digest(command: &WireCommandSpec) -> Digest {
        let canonical = serde_json::to_vec(&CommandSpec {
            program: command.program.clone(),
            arguments: command.arguments.clone(),
            working_directory: PathBuf::from(&command.working_directory),
        })
        .expect("encode canonical command fixture");
        Digest::sha256(&canonical)
    }

    fn sample_output_capture_anchor(
        sequence: u64,
        command: &WireCommandSpec,
    ) -> WireCommandOutputCaptureAnchorV1 {
        let effect_id = format!("effect-{sequence}");
        let source = CommandOutputArtifactSourceV1 {
            sprint_id: "sprint-1".into(),
            runner_launch_id: "launch-1".into(),
            runner_session_id: "session-1".into(),
            effect_id: effect_id.clone(),
            request_digest: command_request_digest(command),
        };
        test_command_output_capture_anchor(
            source,
            digest(3),
            command_output_capture_maximum(1_024).expect("fixture capture maximum"),
            sequence,
        )
    }

    fn worker_command_request(sequence: u64, command: WireCommandSpec) -> RunnerRequest {
        let output_capture = sample_output_capture_anchor(sequence, &command);
        RunnerRequest::WorkerRunCommand {
            command,
            output_capture,
        }
    }

    fn final_verifier_command_request(sequence: u64, command: WireCommandSpec) -> RunnerRequest {
        let output_capture = sample_output_capture_anchor(sequence, &command);
        RunnerRequest::FinalVerifierRunCommand {
            command,
            output_capture,
        }
    }

    fn sample_worker_lease() -> WorkerLease {
        WorkerLease::new(
            "sprint-1".into(),
            1,
            "task-1".into(),
            "worker-1".into(),
            vec![PathScope::Relative(PathBuf::from("src"))],
            1,
        )
        .expect("construct canonical wire worker lease")
    }

    fn sample_wire_grant() -> WireWorkspaceGrant {
        WireWorkspaceGrant {
            grant_id: "grant-1".into(),
            canonical_root: "/tmp/grok-build-wire-workspace".into(),
            permissions: WireWorkspacePermissions {
                read: true,
                write_regular_files: true,
                execute_commands: true,
                integrate_changes: true,
                apply_verified_changes: true,
            },
            network: WireWorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: digest(1),
        }
    }

    fn sample_sprint_spec() -> SprintSpec {
        SprintSpec {
            sprint_id: "sprint-1".into(),
            objective: "exercise the runner wire contract".into(),
            acceptance_criteria: vec![AcceptanceCriterion {
                criterion_id: "criterion-1".into(),
                description: "the exact sprint authority is retained".into(),
                kind: AcceptanceKind::HumanJudgment,
            }],
            provider: ProviderProfile {
                backend_id: "fake-provider".into(),
                model_id: "fake-model".into(),
                execution_origin: ExecutionOrigin::HostIsolated,
            },
            budget: SprintBudget {
                max_tasks: 1,
                max_attempts_per_task: 1,
                max_tool_calls: 8,
                max_duration_ms: 30_000,
            },
            max_workers: 1,
            workspace_grant: sample_wire_grant()
                .into_native()
                .expect("convert fixture grant"),
            base_snapshot: digest(13),
        }
    }

    fn sample_request() -> RunnerRequestEnvelope {
        let sprint_spec = sample_sprint_spec();
        RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: "session-1".into(),
            runner_nonce: None,
            sequence: 0,
            request_id: "request-1".into(),
            effect: None,
            request: RunnerRequest::InitializeSession {
                launch_id: "launch-1".into(),
                sprint_id: "sprint-1".into(),
                expected_sprint_spec_digest: sprint_spec_digest(&sprint_spec)
                    .expect("digest fixture sprint"),
                sprint_spec: Box::new(sprint_spec),
                logical_worker_id: Some("worker-1".into()),
                worker_lease: Some(sample_worker_lease()),
                role: RunnerRole::Worker,
                role_input_authority: RunnerRoleInputAuthority::IntegrationHead,
                workspace_grant: Box::new(sample_wire_grant()),
                execution_policy_request: Box::new(WireExecutionPolicyRequest {
                    policy_id: "policy-1".into(),
                    read_scopes: vec![WirePathScope::Workspace],
                    write_scopes: vec![WirePathScope::Relative { path: "src".into() }],
                    environment: Vec::new(),
                    network: WireExecutionNetwork::None,
                    mutation_mode: WireMutationMode::ShadowWorkspace,
                    resource_limits: WireResourceLimits {
                        wall_time_ms: 1_000,
                        max_output_bytes: 1_024,
                        max_processes: 1,
                        max_memory_bytes: None,
                    },
                    approval_id: None,
                }),
                expected_policy_hash: digest(2),
                expected_base_snapshot: digest(13),
                expected_private_state_digest: digest(3),
                expected_binary_digest: digest(4),
                expected_binary_identity: WireBinaryIdentity {
                    device_id: 1,
                    inode: 2,
                    byte_length: 3,
                    mode: 0o100_755,
                    owner_uid: 4,
                    link_count: 1,
                },
                private_state_root: "/tmp/grok-build-wire-state".into(),
                shadow_root: Some("/tmp/grok-build-wire-state/shadow-1".into()),
            },
        }
    }

    fn sample_post_completion_request() -> RunnerRequestEnvelope {
        let mut request = sample_request();
        let authority = PostCompletionRollbackApplicationArtifactAuthority {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            operation_id: "rollback-operation-1".into(),
            application_receipt_id: "application-receipt-1".into(),
            application_effect_id: "application-effect-1".into(),
            application_request_digest: digest(20),
            artifact: grok_build_core::TaskIntegrationArtifactReference {
                format_version: 1,
                artifact_digest: digest(21),
                change_set_id: "change-set-1".into(),
                base_snapshot: digest(13),
                result_snapshot: digest(14),
            },
        };
        let canonical = serde_json::to_vec(&authority).expect("encode role-input authority");
        let RunnerRequest::InitializeSession {
            logical_worker_id,
            worker_lease,
            role,
            role_input_authority,
            execution_policy_request,
            expected_base_snapshot,
            shadow_root,
            ..
        } = &mut request.request
        else {
            unreachable!()
        };
        *logical_worker_id = None;
        *worker_lease = None;
        *role = RunnerRole::Applier;
        *role_input_authority = RunnerRoleInputAuthority::PostCompletionAppliedResult {
            authority: Box::new(authority),
            authority_digest: Digest::sha256(&canonical),
        };
        execution_policy_request.write_scopes.clear();
        execution_policy_request.mutation_mode = WireMutationMode::ReadOnly;
        *expected_base_snapshot = digest(14);
        *shadow_root = None;
        request
    }

    fn effect_request(
        request_id: &str,
        sequence: u64,
        request: RunnerRequest,
    ) -> RunnerRequestEnvelope {
        let persisted_request_bytes = match &request {
            RunnerRequest::WorkerRunCommand { command, .. }
            | RunnerRequest::FinalVerifierRunCommand { command, .. } => {
                serde_json::to_vec(&CommandSpec {
                    program: command.program.clone(),
                    arguments: command.arguments.clone(),
                    working_directory: PathBuf::from(&command.working_directory),
                })
            }
            _ => request.to_core_task_integration_request().map_or_else(
                |_| serde_json::to_vec(&request),
                |core_request| serde_json::to_vec(&core_request),
            ),
        }
        .expect("serialize exact persisted request fixture");
        let mut envelope = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: "session-1".into(),
            runner_nonce: Some(digest(9)),
            sequence,
            request_id: request_id.into(),
            effect: Some(WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "launch-1".into(),
                effect_id: format!("effect-{sequence}"),
                idempotency_key: format!("idempotency-{sequence}"),
                sprint_id: "sprint-1".into(),
                task_id: Some("task-1".into()),
                worker_id: Some("worker-1".into()),
                worker_lease: Some(sample_worker_lease()),
                policy_hash: digest(2),
                input_snapshot: digest(7),
                request_digest: Digest::sha256(&persisted_request_bytes),
                transport_commitment_digest: digest(0),
            }),
            request,
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind fixture transport commitment");
        envelope
    }

    fn effect_request_v12(
        request_id: &str,
        sequence: u64,
        request: RunnerRequest,
    ) -> RunnerRequestEnvelopeV12 {
        let legacy = effect_request(request_id, sequence, request.clone());
        let mut envelope = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: legacy.session_id,
            runner_nonce: legacy.runner_nonce.expect("effect fixture has a nonce"),
            sequence: legacy.sequence,
            request_id: legacy.request_id,
            effect: legacy.effect.expect("effect fixture has context"),
            request: RunnerRequestV12::RunCommand {
                request,
                detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            },
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind full v12 transport commitment");
        envelope
    }

    #[test]
    fn v12_transport_commitment_binds_detector_policy_and_round_trips_canonically() {
        let command = WireCommandSpec {
            program: "printf".into(),
            arguments: vec!["clean".into()],
            working_directory: String::new(),
        };
        let request = effect_request_v12(
            "request-v12-policy-bound",
            1,
            worker_command_request(1, command),
        );
        let frame = encode_request_frame_v12(&request).expect("encode canonical v12 request");
        assert_eq!(
            decode_request_frame_v12(&frame).expect("decode canonical v12 request"),
            request
        );

        let old_digest = request.effect.transport_commitment_digest.clone();
        let mut substituted = request;
        let RunnerRequestV12::RunCommand {
            detector_policy, ..
        } = &mut substituted.request;
        detector_policy.policy_id.push_str("-substituted");
        assert_ne!(
            substituted
                .computed_transport_commitment_digest()
                .expect("compute commitment over substituted policy"),
            old_digest,
            "the v12 transport commitment must change when only policy changes"
        );
        assert!(encode_request_frame_v12(&substituted).is_err());
    }

    fn test_command_effect_authority(
        envelope: &RunnerRequestEnvelope,
        grant_hash: &Digest,
    ) -> Result<Option<CommandEffectAuthorityV1>, WireProtocolError> {
        CommandEffectAuthorityV1::from_session_validated(
            crate::service::test_session_validated_command_envelope(envelope, grant_hash),
        )
    }

    #[test]
    fn protocol_v9_initialization_requires_role_exact_worker_lease_identity() {
        let mut crossed_input_authority = sample_request();
        let RunnerRequest::InitializeSession {
            role_input_authority,
            ..
        } = &mut crossed_input_authority.request
        else {
            unreachable!()
        };
        *role_input_authority = RunnerRoleInputAuthority::PlanningBase;
        assert!(matches!(
            encode_request_frame(&crossed_input_authority),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("role input authority")
        ));

        let mut missing = sample_request();
        let RunnerRequest::InitializeSession { worker_lease, .. } = &mut missing.request else {
            unreachable!()
        };
        *worker_lease = None;
        assert!(matches!(
            encode_request_frame(&missing),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("worker initialization requires")
        ));

        let mut cross_worker = sample_request();
        let RunnerRequest::InitializeSession {
            logical_worker_id, ..
        } = &mut cross_worker.request
        else {
            unreachable!()
        };
        *logical_worker_id = Some("worker-2".into());
        assert!(matches!(
            encode_request_frame(&cross_worker),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("worker_lease.assignment")
        ));

        let mut cross_sprint = sample_request();
        let RunnerRequest::InitializeSession { sprint_id, .. } = &mut cross_sprint.request else {
            unreachable!()
        };
        *sprint_id = "sprint-2".into();
        assert!(matches!(
            encode_request_frame(&cross_sprint),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("sprint specification differs")
        ));

        let mut unexpected = sample_request();
        let RunnerRequest::InitializeSession {
            logical_worker_id,
            role,
            role_input_authority,
            shadow_root,
            ..
        } = &mut unexpected.request
        else {
            unreachable!()
        };
        *logical_worker_id = None;
        *role = RunnerRole::Applier;
        *role_input_authority = RunnerRoleInputAuthority::PlanningBase;
        *shadow_root = None;
        assert!(matches!(
            encode_request_frame(&unexpected),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("non-worker initialization forbids")
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the adversarial matrix keeps every independently valid SprintSpec substitution in one audit boundary"
    )]
    fn protocol_v9_initialization_binds_exact_sprint_authority_and_budget() {
        let spec = sample_sprint_spec();
        let canonical = serde_json::to_vec(&spec).expect("serialize canonical sprint");
        assert_ne!(
            sprint_spec_digest(&spec).expect("digest canonical sprint"),
            Digest::sha256(&canonical),
            "the sprint commitment must be domain separated"
        );

        let mut substituted_objective = sample_request();
        let RunnerRequest::InitializeSession { sprint_spec, .. } =
            &mut substituted_objective.request
        else {
            unreachable!()
        };
        sprint_spec.objective = "substituted objective".into();
        assert!(matches!(
            encode_request_frame(&substituted_objective),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("sprint specification differs")
        ));

        let mut substituted_digest = sample_request();
        let RunnerRequest::InitializeSession {
            expected_sprint_spec_digest,
            ..
        } = &mut substituted_digest.request
        else {
            unreachable!()
        };
        *expected_sprint_spec_digest = digest(99);
        assert!(matches!(
            encode_request_frame(&substituted_digest),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("sprint specification differs")
        ));

        let mut substituted_grant = sample_request();
        let RunnerRequest::InitializeSession {
            sprint_spec,
            expected_sprint_spec_digest,
            ..
        } = &mut substituted_grant.request
        else {
            unreachable!()
        };
        sprint_spec.workspace_grant.grant_id = "grant-substituted".into();
        *expected_sprint_spec_digest =
            sprint_spec_digest(sprint_spec).expect("digest crossed grant sprint");
        assert!(matches!(
            encode_request_frame(&substituted_grant),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("sprint specification differs")
        ));

        let mut substituted_base = sample_request();
        let RunnerRequest::InitializeSession {
            sprint_spec,
            expected_sprint_spec_digest,
            ..
        } = &mut substituted_base.request
        else {
            unreachable!()
        };
        sprint_spec.base_snapshot = digest(98);
        *expected_sprint_spec_digest =
            sprint_spec_digest(sprint_spec).expect("digest crossed base sprint");
        encode_request_frame(&substituted_base).expect(
            "worker role input is a distinct durable integration head, not a rewritten SprintSpec base",
        );

        let mut vendor_managed = sample_request();
        let RunnerRequest::InitializeSession {
            sprint_spec,
            expected_sprint_spec_digest,
            ..
        } = &mut vendor_managed.request
        else {
            unreachable!()
        };
        sprint_spec.provider.execution_origin = ExecutionOrigin::VendorManaged;
        *expected_sprint_spec_digest =
            sprint_spec_digest(sprint_spec).expect("digest vendor sprint");
        assert!(matches!(
            encode_request_frame(&vendor_managed),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("host-isolated")
        ));

        let mut over_budget = sample_request();
        let RunnerRequest::InitializeSession {
            sprint_spec,
            expected_sprint_spec_digest,
            ..
        } = &mut over_budget.request
        else {
            unreachable!()
        };
        sprint_spec.budget.max_duration_ms = 999;
        *expected_sprint_spec_digest =
            sprint_spec_digest(sprint_spec).expect("digest bounded sprint");
        assert!(matches!(
            encode_request_frame(&over_budget),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("wall time exceeds")
        ));

        let mut invalid_worker_ceiling = sample_request();
        let RunnerRequest::InitializeSession { sprint_spec, .. } =
            &mut invalid_worker_ceiling.request
        else {
            unreachable!()
        };
        sprint_spec.max_workers = 0;
        assert!(matches!(
            encode_request_frame(&invalid_worker_ceiling),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("max_workers")
        ));
    }

    #[test]
    fn protocol_v9_post_completion_role_input_binds_exact_artifact_result_and_digest() {
        let request = sample_post_completion_request();
        encode_request_frame(&request).expect("exact applied-result authority is admitted");

        let mut substituted_result = request.clone();
        let RunnerRequest::InitializeSession {
            expected_base_snapshot,
            ..
        } = &mut substituted_result.request
        else {
            unreachable!()
        };
        *expected_base_snapshot = digest(15);
        assert!(matches!(
            encode_request_frame(&substituted_result),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("post-completion role-input authority")
        ));

        let mut substituted_digest = request.clone();
        let RunnerRequest::InitializeSession {
            role_input_authority,
            ..
        } = &mut substituted_digest.request
        else {
            unreachable!()
        };
        let RunnerRoleInputAuthority::PostCompletionAppliedResult {
            authority_digest, ..
        } = role_input_authority
        else {
            unreachable!()
        };
        *authority_digest = digest(99);
        assert!(matches!(
            encode_request_frame(&substituted_digest),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("post-completion role-input authority")
        ));

        let mut substituted_artifact = request;
        let RunnerRequest::InitializeSession {
            role_input_authority,
            ..
        } = &mut substituted_artifact.request
        else {
            unreachable!()
        };
        let RunnerRoleInputAuthority::PostCompletionAppliedResult {
            authority,
            authority_digest,
        } = role_input_authority
        else {
            unreachable!()
        };
        authority.artifact.result_snapshot = digest(16);
        *authority_digest = Digest::sha256(
            &serde_json::to_vec(authority).expect("encode substituted role-input authority"),
        );
        assert!(matches!(
            encode_request_frame(&substituted_artifact),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("post-completion role-input authority")
        ));
    }

    #[test]
    fn protocol_v9_effect_shape_requires_role_exact_lease() {
        let mut missing = effect_request(
            "request-missing-lease",
            1,
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1024,
            },
        );
        missing.effect.as_mut().expect("worker effect").worker_lease = None;
        missing
            .bind_transport_commitment_digest()
            .expect("bind missing lease shape");
        assert!(matches!(
            encode_request_frame(&missing),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("worker effects require")
        ));

        let mut cross_task = effect_request(
            "request-cross-task",
            2,
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1024,
            },
        );
        cross_task.effect.as_mut().expect("worker effect").task_id = Some("task-2".into());
        cross_task
            .bind_transport_commitment_digest()
            .expect("bind crossed task");
        assert!(matches!(
            encode_request_frame(&cross_task),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("worker_lease.assignment")
        ));

        let mut unexpected = effect_request(
            "request-unexpected-lease",
            3,
            final_verifier_command_request(
                3,
                WireCommandSpec {
                    program: "/usr/bin/true".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
            ),
        );
        {
            let effect = unexpected.effect.as_mut().expect("final-verifier effect");
            effect.task_id = None;
            effect.worker_id = None;
            effect.worker_lease = None;
        }
        unexpected
            .bind_transport_commitment_digest()
            .expect("bind role-exact verifier effect");
        encode_request_frame(&unexpected).expect("non-worker effect without lease encodes");
        unexpected
            .effect
            .as_mut()
            .expect("final-verifier effect")
            .worker_lease = Some(sample_worker_lease());
        unexpected
            .bind_transport_commitment_digest()
            .expect("bind unexpected verifier lease");
        assert!(matches!(
            encode_request_frame(&unexpected),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("non-worker effects forbid")
        ));
    }

    #[test]
    fn protocol_v9_transport_commitment_binds_complete_worker_lease() {
        let mut substituted = effect_request(
            "request-lease-commitment",
            1,
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1024,
            },
        );
        substituted
            .effect
            .as_mut()
            .expect("worker effect")
            .worker_lease = Some(
            WorkerLease::new(
                "sprint-1".into(),
                2,
                "task-1".into(),
                "worker-1".into(),
                vec![PathScope::Relative(PathBuf::from("src"))],
                1,
            )
            .expect("construct different-epoch substitution"),
        );
        assert!(matches!(
            encode_request_frame(&substituted),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("transport commitment")
        ));
        substituted
            .bind_transport_commitment_digest()
            .expect("bind substituted lease exactly");
        encode_request_frame(&substituted)
            .expect("internally valid substituted lease is a service-level session mismatch");
    }

    #[test]
    fn command_effect_authority_retains_exact_validated_envelope_and_grant() {
        let request = effect_request(
            "request-command-authority",
            1,
            worker_command_request(
                1,
                WireCommandSpec {
                    program: "/usr/bin/cargo".into(),
                    arguments: vec!["test".into(), "--locked".into()],
                    working_directory: "fixture".into(),
                },
            ),
        );
        let grant_hash = digest(44);
        let authority = test_command_effect_authority(&request, &grant_hash)
            .expect("exact command authority validates")
            .expect("command produces authority");
        assert_eq!(
            authority.schema_version,
            COMMAND_EFFECT_AUTHORITY_SCHEMA_VERSION
        );
        assert_eq!(authority.contract_version, CONTRACT_VERSION);
        assert_eq!(authority.grant_hash, grant_hash);
        assert_eq!(authority.role(), RunnerRole::Worker);
        assert_eq!(authority.envelope, request);

        let canonical = serde_json::to_vec(&authority).expect("canonical authority");
        let decoded: CommandEffectAuthorityV1 =
            serde_json::from_slice(&canonical).expect("strict authority decode");
        decoded
            .validate_integrity()
            .expect("decoded authority revalidates");
        assert_eq!(decoded, authority);
    }

    #[test]
    fn command_effect_authority_rejects_crossed_core_digest_role_and_transport() {
        let mut crossed_digest = effect_request(
            "request-command-crossed-digest",
            2,
            final_verifier_command_request(
                2,
                WireCommandSpec {
                    program: "/usr/bin/true".into(),
                    arguments: Vec::new(),
                    working_directory: String::new(),
                },
            ),
        );
        {
            let effect = crossed_digest.effect.as_mut().expect("effect");
            effect.task_id = None;
            effect.worker_id = None;
            effect.worker_lease = None;
            effect.request_digest = digest(99);
        }
        crossed_digest
            .bind_transport_commitment_digest()
            .expect("rebind changed transport");
        assert!(test_command_effect_authority(&crossed_digest, &digest(44)).is_err());

        let mut crossed_role = effect_request(
            "request-command-crossed-role",
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
        let exact = test_command_effect_authority(&crossed_role, &digest(44))
            .expect("authority")
            .expect("command authority");
        let mut crossed_role_authority = exact.clone();
        crossed_role_authority.role = RunnerRole::FinalVerifier;
        assert!(crossed_role_authority.validate_integrity().is_err());

        crossed_role
            .effect
            .as_mut()
            .expect("effect")
            .transport_commitment_digest = digest(77);
        assert!(test_command_effect_authority(&crossed_role, &digest(44)).is_err());
    }

    #[test]
    fn non_command_request_does_not_fabricate_command_authority() {
        let request = effect_request(
            "request-not-command-authority",
            4,
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1024,
            },
        );
        assert_eq!(
            test_command_effect_authority(&request, &digest(44))
                .expect("ordinary request still validates"),
            None
        );
    }

    fn control_request(
        request_id: &str,
        sequence: u64,
        request: RunnerRequest,
    ) -> RunnerRequestEnvelope {
        RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: "session-1".into(),
            runner_nonce: Some(digest(9)),
            sequence,
            request_id: request_id.into(),
            effect: None,
            request,
        }
    }

    fn sample_bundle() -> StageBundleReference {
        StageBundleReference {
            format_version: 1,
            bundle_digest: digest(20),
            change_set_id: "changeset-1".into(),
            base_snapshot: digest(21),
            result_snapshot: digest(22),
        }
    }

    fn sample_change_set() -> ChangeSet {
        let bundle = sample_bundle();
        ChangeSet {
            change_set_id: bundle.change_set_id,
            base_snapshot: bundle.base_snapshot,
            result_snapshot: bundle.result_snapshot,
            operations: vec![FileOperation::Create {
                path: PathBuf::from("src/generated.rs"),
                result_hash: digest(23),
            }],
        }
    }

    fn sample_rollback_reference(artifact_count: usize) -> WireRollbackArtifactReference {
        assert!(artifact_count > 0);
        let mut artifacts = Vec::with_capacity(artifact_count);
        artifacts.push(WireRollbackArtifact {
            kind: WireRollbackArtifactKind::Plan,
            name: "plan".into(),
            length: 1,
            mode: 0o600,
            digest: digest(23),
            device: 1,
            inode: 2,
            owner_uid: 3,
            modified_seconds: 4,
            modified_nanoseconds: 5,
            changed_seconds: 6,
            changed_nanoseconds: 7,
        });
        for operation_index in 0..artifact_count.saturating_sub(1) {
            let operation_index = u32::try_from(operation_index).expect("fixture index fits u32");
            artifacts.push(WireRollbackArtifact {
                kind: WireRollbackArtifactKind::BaseBlob { operation_index },
                name: format!("base-{operation_index:06}"),
                length: u64::from(operation_index),
                mode: 0o600,
                digest: Digest::sha256(&operation_index.to_be_bytes()),
                device: 1,
                inode: u64::from(operation_index) + 10,
                owner_uid: 3,
                modified_seconds: 4,
                modified_nanoseconds: 5,
                changed_seconds: 6,
                changed_nanoseconds: 7,
            });
        }
        let mut reference = WireRollbackArtifactReference {
            transaction_id: "transaction-1".into(),
            change_set_id: "changeset-1".into(),
            base_snapshot: digest(21),
            touched_target_set_digest: digest(24),
            target_contract_digest:
                wire_rollback_target_contract_digest(&sample_rollback_targets()).unwrap(),
            transaction_device: 1,
            transaction_inode: 9,
            transaction_mode: 0o700,
            transaction_owner_uid: 3,
            artifacts_digest: digest(0),
            artifacts,
        };
        reference.artifacts_digest = Digest::sha256(&reference.canonical_bytes());
        reference
    }

    fn observed_from_expected(
        expected: &WireRollbackExpectedEndpoint,
    ) -> WireRollbackObservedEndpoint {
        match expected {
            WireRollbackExpectedEndpoint::Absent => WireRollbackObservedEndpoint::Absent,
            WireRollbackExpectedEndpoint::Regular { digest, mode } => {
                WireRollbackObservedEndpoint::Regular {
                    digest: digest.clone(),
                    length: 1,
                    mode: *mode,
                }
            }
        }
    }

    fn sample_rollback_targets() -> Vec<WireRollbackTargetContract> {
        vec![
            WireRollbackTargetContract {
                path: "src/generated.rs".into(),
                application: WireRollbackExpectedEndpoint::Regular {
                    digest: digest(23),
                    mode: 0o600,
                },
                restored_base: WireRollbackExpectedEndpoint::Absent,
            },
            WireRollbackTargetContract {
                path: "src/removed.rs".into(),
                application: WireRollbackExpectedEndpoint::Absent,
                restored_base: WireRollbackExpectedEndpoint::Regular {
                    digest: digest(24),
                    mode: 0o640,
                },
            },
        ]
    }

    fn sample_two_operation_change_set() -> ChangeSet {
        let bundle = sample_bundle();
        ChangeSet {
            change_set_id: bundle.change_set_id,
            base_snapshot: bundle.base_snapshot,
            result_snapshot: bundle.result_snapshot,
            operations: vec![
                FileOperation::Create {
                    path: PathBuf::from("src/generated.rs"),
                    result_hash: digest(23),
                },
                FileOperation::Delete {
                    path: PathBuf::from("src/removed.rs"),
                    base_hash: digest(24),
                },
            ],
        }
    }

    fn sample_explicit_rollback_evidence() -> WireExplicitRollbackEvidence {
        let target_contract = sample_rollback_targets();
        let pre_effect_observations = target_contract
            .iter()
            .map(|target| WireRollbackPathObservation {
                path: target.path.clone(),
                endpoint: observed_from_expected(&target.application),
            })
            .collect::<Vec<_>>();
        let post_restore_observations = target_contract
            .iter()
            .map(|target| WireRollbackPathObservation {
                path: target.path.clone(),
                endpoint: observed_from_expected(&target.restored_base),
            })
            .collect::<Vec<_>>();
        let touched_target_set_digest = wire_rollback_target_set_digest(&target_contract).unwrap();
        let mut rollback = sample_rollback_reference(1);
        rollback.artifacts.push(WireRollbackArtifact {
            kind: WireRollbackArtifactKind::BaseBlob { operation_index: 1 },
            name: "base-000001".into(),
            length: 1,
            mode: 0o600,
            digest: digest(24),
            device: 1,
            inode: 10,
            owner_uid: 3,
            modified_seconds: 4,
            modified_nanoseconds: 5,
            changed_seconds: 6,
            changed_nanoseconds: 7,
        });
        rollback.touched_target_set_digest = touched_target_set_digest.clone();
        rollback.artifacts_digest = Digest::sha256(&rollback.canonical_bytes());
        WireExplicitRollbackEvidence {
            bundle: sample_bundle(),
            transaction_id: rollback.transaction_id.clone(),
            change_set_id: rollback.change_set_id.clone(),
            rollback,
            expected_application_endpoints_digest: wire_expected_application_endpoints_digest(
                &target_contract,
            )
            .unwrap(),
            restored_base_endpoints_digest: wire_restored_base_endpoints_digest(&target_contract)
                .unwrap(),
            touched_target_set_digest,
            pre_effect_observations_digest: rollback_observations_digest(&pre_effect_observations)
                .unwrap(),
            pre_effect_observations,
            effect_started_at_unix_ms: 10,
            post_restore_observations_digest: rollback_observations_digest(
                &post_restore_observations,
            )
            .unwrap(),
            post_restore_observations,
            final_live_manifest_digest: digest(25),
            final_live_manifest_observed_at_unix_ms: 11,
            target_contract,
        }
    }

    fn sample_rollback_live_conflict() -> WireRollbackLiveConflict {
        let success = sample_explicit_rollback_evidence();
        let mut observations = success.pre_effect_observations.clone();
        observations[0].endpoint = WireRollbackObservedEndpoint::Absent;
        let conflicts = wire_rollback_conflicts(&success.target_contract, &observations).unwrap();
        WireRollbackLiveConflict {
            bundle: success.bundle,
            rollback: success.rollback,
            transaction_id: success.transaction_id,
            change_set_id: success.change_set_id,
            target_contract: success.target_contract,
            expected_application_endpoints_digest: success.expected_application_endpoints_digest,
            touched_target_set_digest: success.touched_target_set_digest,
            observed_endpoints_digest: rollback_observations_digest(&observations).unwrap(),
            observations,
            conflicts,
            live_manifest_digest: digest(26),
            manifest_observed_at_unix_ms: 10,
            observed_at_unix_ms: 11,
            rollback_mutation_started: false,
        }
    }

    fn response_for(
        request: &RunnerRequestEnvelope,
        response: RunnerResponse,
    ) -> RunnerResponseEnvelope {
        RunnerResponseEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: request.session_id.clone(),
            runner_nonce: request.runner_nonce.clone().expect("effect request nonce"),
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            effect: request.effect.clone(),
            response,
        }
    }

    fn complete_command_stream(bytes: &[u8]) -> WireCommandStreamEvidence {
        WireCommandStreamEvidence {
            retained_bytes: bytes.to_vec(),
            complete_digest: Digest::sha256(bytes),
            complete_length: u64::try_from(bytes.len()).expect("fixture stream length fits u64"),
            truncated: false,
        }
    }

    fn command_output_artifacts_for(
        request: &RunnerRequestEnvelope,
        stdout: &WireCommandStreamEvidence,
        stderr: &WireCommandStreamEvidence,
    ) -> CommandOutputArtifactSetReferenceV1 {
        let effect = request.effect.as_ref().expect("command effect context");
        CommandOutputArtifactSetReferenceV1::try_new(
            CommandOutputArtifactSourceV1 {
                sprint_id: effect.sprint_id.clone(),
                runner_launch_id: effect.launch_id.clone(),
                runner_session_id: request.session_id.clone(),
                effect_id: effect.effect_id.clone(),
                request_digest: effect.request_digest.clone(),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stdout,
                byte_length: stdout.complete_length,
                content_digest: stdout.complete_digest.clone(),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stderr,
                byte_length: stderr.complete_length,
                content_digest: stderr.complete_digest.clone(),
            },
        )
        .expect("canonical command-output artifact fixture")
    }

    fn command_terminal_for(request: &RunnerRequestEnvelope) -> WireCommandTerminalEvidence {
        let effect = request.effect.as_ref().expect("command effect context");
        let binding = CommandDomainCleanupBinding::try_new(
            request.session_id.clone(),
            effect.effect_id.clone(),
            effect.request_digest.clone(),
        )
        .expect("command cleanup binding");
        let (RunnerRequest::WorkerRunCommand {
            output_capture: output_capture_anchor,
            ..
        }
        | RunnerRequest::FinalVerifierRunCommand {
            output_capture: output_capture_anchor,
            ..
        }) = &request.request
        else {
            panic!("command terminal fixture requires a command request")
        };
        let acquired = output_capture_anchor.acquired();
        let proof = crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&binding);
        let stdout = complete_command_stream(b"complete stdout\n");
        let stderr = complete_command_stream(b"complete stderr\n");
        let output_artifacts = command_output_artifacts_for(request, &stdout, &stderr);
        let output_capture = WireCommandOutputCaptureTerminalV1::try_new(
            acquired.capture_id.clone(),
            acquired.acquired_anchor_digest.clone(),
            CommandOutputCaptureStoreHeadV1 {
                generation: acquired.store_head.generation + 3,
                record_digest: digest(40),
            },
            CommandOutputCaptureStoreHeadV1 {
                generation: acquired.store_head.generation + 4,
                record_digest: digest(41),
            },
            CommandOutputCaptureStoreHeadV1 {
                generation: acquired.store_head.generation + 5,
                record_digest: digest(42),
            },
            output_artifacts.clone(),
            digest(0),
        )
        .expect("capture terminal fixture");
        let mut terminal = WireCommandTerminalEvidence {
            output_capture,
            termination: CommandTerminationV1::Exited { code: 0 },
            output_digest: command_stream_output_digest(&stdout, &stderr),
            stdout,
            stderr,
            output_artifacts,
            launch_digest: digest(30),
            preflight_digest: digest(31),
            backend: WireCommandBackendIdentity {
                command_domain_backend: CommandDomainCleanupBackend::LinuxCgroupV2,
                backend_id: "linux-cgroup-v2-fixture".into(),
                implementation_digest: digest(32),
            },
            cleanup_proof: WireCommandCleanupProof::try_from(&proof)
                .expect("validated cleanup proof adapts to wire"),
            duration_ms: 7,
        };
        terminal
            .bind_terminal_record_digest()
            .expect("bind canonical terminal record fixture");
        terminal
    }

    fn rebind_command_terminal(terminal: &mut WireCommandTerminalEvidence) {
        terminal.output_capture.expected_output_artifacts = terminal.output_artifacts.clone();
        terminal
            .bind_terminal_record_digest()
            .expect("rebind canonical terminal fixture");
    }

    fn framed_payload(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("test payload fits u32")
                .to_be_bytes(),
        );
        frame.extend_from_slice(payload);
        frame
    }

    fn framed_command_terminal_json(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(
            COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN.len()
                + std::mem::size_of::<u64>()
                + payload.len(),
        );
        frame.extend_from_slice(COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN);
        frame.extend_from_slice(
            &u64::try_from(payload.len())
                .expect("terminal fixture payload fits u64")
                .to_be_bytes(),
        );
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn request_round_trip_is_exactly_canonical() {
        let request = sample_request();
        let frame = encode_request_frame(&request).expect("encode canonical request");
        assert_eq!(
            decode_request_frame(&frame).expect("decode request"),
            request
        );
    }

    #[test]
    fn whitespace_and_field_reordering_are_noncanonical() {
        let request = sample_request();
        let canonical = serde_json::to_vec(&request).expect("serialize fixture");
        let mut whitespace = canonical.clone();
        whitespace.insert(1, b' ');
        assert!(matches!(
            decode_request_frame(&framed_payload(&whitespace)),
            Err(WireProtocolError::NonCanonical)
        ));

        let value: serde_json::Value = serde_json::from_slice(&canonical).expect("parse fixture");
        let reordered = serde_json::to_vec(&value).expect("serialize map-ordered fixture");
        assert_ne!(reordered, canonical);
        assert!(matches!(
            decode_request_frame(&framed_payload(&reordered)),
            Err(WireProtocolError::NonCanonical)
        ));
    }

    #[test]
    fn duplicate_and_unknown_fields_are_rejected() {
        let canonical =
            String::from_utf8(serde_json::to_vec(&sample_request()).expect("serialize fixture"))
                .expect("fixture is UTF-8");
        let duplicate = canonical.replacen(
            "\"request_id\":\"request-1\",",
            "\"request_id\":\"request-1\",\"request_id\":\"request-2\",",
            1,
        );
        assert!(matches!(
            decode_request_frame(&framed_payload(duplicate.as_bytes())),
            Err(WireProtocolError::InvalidJson(_))
        ));

        let unknown = canonical.replacen("\"request\":", "\"unexpected\":true,\"request\":", 1);
        assert!(matches!(
            decode_request_frame(&framed_payload(unknown.as_bytes())),
            Err(WireProtocolError::InvalidJson(_))
        ));

        let mut nested_unknown = canonical.clone();
        let workspace_grant_start = nested_unknown
            .rfind("\"workspace_grant\":{")
            .expect("explicit wire workspace grant")
            + "\"workspace_grant\":{".len();
        nested_unknown.insert_str(workspace_grant_start, "\"credential\":\"forbidden\",");
        assert!(matches!(
            decode_request_frame(&framed_payload(nested_unknown.as_bytes())),
            Err(WireProtocolError::InvalidJson(_))
        ));

        let sprint_unknown = canonical.replacen(
            "\"objective\":\"exercise the runner wire contract\",",
            "\"objective\":\"exercise the runner wire contract\",\"credential\":\"forbidden\",",
            1,
        );
        assert!(matches!(
            decode_request_frame(&framed_payload(sprint_unknown.as_bytes())),
            Err(WireProtocolError::NonCanonical)
        ));
    }

    #[test]
    fn zero_oversized_partial_invalid_utf8_and_trailing_frames_are_rejected() {
        assert!(matches!(
            decode_request_frame(&0_u32.to_be_bytes()),
            Err(WireProtocolError::InvalidLength(0))
        ));
        let oversized = u32::try_from(MAX_WIRE_FRAME_BYTES + 1)
            .expect("frame bound fits u32")
            .to_be_bytes();
        assert!(matches!(
            decode_request_frame(&oversized),
            Err(WireProtocolError::InvalidLength(_))
        ));
        assert!(matches!(
            decode_request_frame(&[0, 0, 0]),
            Err(WireProtocolError::TruncatedPrefix)
        ));
        assert!(matches!(
            decode_request_frame(&[0, 0, 0, 4, b'{']),
            Err(WireProtocolError::TruncatedPayload {
                expected: 4,
                actual: 1
            })
        ));
        assert!(matches!(
            decode_request_frame(&framed_payload(&[0xff])),
            Err(WireProtocolError::InvalidJson(_))
        ));
        let mut frame = encode_request_frame(&sample_request()).expect("encode fixture");
        frame.push(0);
        assert!(matches!(
            decode_request_frame(&frame),
            Err(WireProtocolError::TrailingFrameBytes)
        ));
    }

    #[test]
    fn invalid_version_and_shell_program_are_rejected() {
        let mut request = sample_request();
        request.protocol_version = 10;
        let payload = serde_json::to_vec(&request).expect("serialize invalid version");
        assert!(matches!(
            decode_request_frame(&framed_payload(&payload)),
            Err(WireProtocolError::Version {
                expected: 11,
                actual: 10
            })
        ));

        let command = effect_request(
            "request-2",
            1,
            worker_command_request(
                1,
                WireCommandSpec {
                    program: "/bin/sh".into(),
                    arguments: vec!["-c".into(), "id".into()],
                    working_directory: String::new(),
                },
            ),
        );
        assert!(matches!(
            encode_request_frame(&command),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[test]
    fn response_correlation_is_exact() {
        let request = effect_request(
            "request-2",
            1,
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1024,
            },
        );
        let response = response_for(
            &request,
            RunnerResponse::Failed {
                code: "fixture_failure".into(),
                class: WireFailureClass::BeforeEffect,
                reconciliation: None,
                message: "fixture".into(),
            },
        );
        response
            .validate_correlation(&request)
            .expect("correlated response");
        let mut crossed = response;
        crossed.session_id = "session-2".into();
        assert!(matches!(
            crossed.validate_correlation(&request),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[test]
    fn reconciliation_references_cannot_cross_correlated_request_authority() {
        let bundle = sample_bundle();
        let request = effect_request(
            "request-apply",
            1,
            RunnerRequest::ApplierApplyBundle {
                bundle: bundle.clone(),
            },
        );
        let exact = response_for(
            &request,
            RunnerResponse::failed_requiring_reconciliation(
                "fixture",
                WireReconciliationReference::Application {
                    bundle: bundle.clone(),
                },
                "fixture",
            ),
        );
        exact
            .validate_correlation(&request)
            .expect("exact application reference correlates");

        let mut crossed_bundle = bundle;
        crossed_bundle.bundle_digest = digest(99);
        let crossed = response_for(
            &request,
            RunnerResponse::failed_requiring_reconciliation(
                "fixture",
                WireReconciliationReference::Application {
                    bundle: crossed_bundle,
                },
                "fixture",
            ),
        );
        assert!(crossed.validate_correlation(&request).is_err());

        let file_request = effect_request(
            "request-file",
            2,
            RunnerRequest::WorkerDeleteFile {
                path: "src/lib.rs".into(),
                expected_digest: digest(1),
            },
        );
        let crossed_file = response_for(
            &file_request,
            RunnerResponse::failed_requiring_reconciliation(
                "fixture",
                WireReconciliationReference::File {
                    path: "src/other.rs".into(),
                },
                "fixture",
            ),
        );
        assert!(crossed_file.validate_correlation(&file_request).is_err());
    }

    #[test]
    fn stage_preparation_and_durable_effect_preimage_are_exact() {
        let change_set = sample_change_set();
        let bundle = sample_bundle();
        let prepare = control_request(
            "request-stage-prepare",
            1,
            RunnerRequest::WorkerPrepareStage {
                change_set_id: change_set.change_set_id.clone(),
                created_at_unix_ms: 1,
            },
        );
        let prepared = response_for(
            &prepare,
            RunnerResponse::StagePrepared {
                change_set: Box::new(change_set.clone()),
                expected_bundle: bundle.clone(),
            },
        );
        prepared
            .validate_correlation(&prepare)
            .expect("exact stage preparation correlates");
        assert!(
            response_for(
                &prepare,
                RunnerResponse::StageBundleReconciled {
                    bundle: bundle.clone(),
                },
            )
            .validate_correlation(&prepare)
            .is_err()
        );

        let stage = effect_request(
            "request-stage-effect",
            2,
            RunnerRequest::WorkerStageChanges {
                change_set: Box::new(change_set.clone()),
                expected_bundle: bundle.clone(),
            },
        );
        let core_request = stage
            .request
            .to_core_task_integration_request()
            .expect("construct durable core integration preimage");
        assert_eq!(core_request.change_set, change_set);
        assert_eq!(core_request.artifact.artifact_digest, bundle.bundle_digest);
        assert_eq!(
            RunnerRequest::try_from(&core_request)
                .expect("reconstruct exact stage effect after coordinator restart"),
            stage.request
        );
        assert_eq!(
            stage
                .effect
                .as_ref()
                .expect("stage effect context")
                .request_digest,
            Digest::sha256(
                &serde_json::to_vec(&core_request).expect("encode core integration preimage")
            )
        );
        assert_ne!(
            stage
                .effect
                .as_ref()
                .expect("stage effect context")
                .request_digest,
            Digest::sha256(&serde_json::to_vec(&stage.request).expect("encode wire stage request"))
        );
        encode_request_frame(&stage).expect("exact bounded stage effect encodes");
        let persisted = response_for(
            &stage,
            RunnerResponse::StageBundlePersisted {
                bundle: bundle.clone(),
            },
        );
        persisted
            .validate_correlation(&stage)
            .expect("exact persisted bundle correlates");
    }

    #[test]
    fn stage_response_correlation_and_request_validation_are_strict() {
        let change_set = sample_change_set();
        let bundle = sample_bundle();
        let stage = effect_request(
            "request-stage-effect",
            1,
            RunnerRequest::WorkerStageChanges {
                change_set: Box::new(change_set.clone()),
                expected_bundle: bundle.clone(),
            },
        );
        let mut crossed_bundle = bundle.clone();
        crossed_bundle.bundle_digest = digest(99);
        let crossed = response_for(
            &stage,
            RunnerResponse::StageBundlePersisted {
                bundle: crossed_bundle.clone(),
            },
        );
        assert!(crossed.validate_correlation(&stage).is_err());

        let reconcile = control_request(
            "request-stage-reconcile",
            3,
            RunnerRequest::WorkerReconcileStage {
                expected_bundle: bundle.clone(),
            },
        );
        response_for(
            &reconcile,
            RunnerResponse::StageBundleReconciled {
                bundle: bundle.clone(),
            },
        )
        .validate_correlation(&reconcile)
        .expect("exact read-only stage reconciliation correlates");
        assert!(
            response_for(
                &reconcile,
                RunnerResponse::StageBundleReconciled {
                    bundle: crossed_bundle.clone(),
                },
            )
            .validate_correlation(&reconcile)
            .is_err()
        );

        crossed_bundle.result_snapshot = digest(98);
        let mismatched_request = effect_request(
            "request-stage-mismatch",
            4,
            RunnerRequest::WorkerStageChanges {
                change_set: Box::new(change_set),
                expected_bundle: crossed_bundle,
            },
        );
        assert!(matches!(
            encode_request_frame(&mismatched_request),
            Err(WireProtocolError::InvalidContract(_))
        ));

        let mut protected_change_set = sample_change_set();
        protected_change_set.operations[0] = FileOperation::Create {
            path: PathBuf::from(".GIT/config"),
            result_hash: digest(23),
        };
        let protected = effect_request(
            "request-stage-protected",
            5,
            RunnerRequest::WorkerStageChanges {
                change_set: Box::new(protected_change_set),
                expected_bundle: bundle,
            },
        );
        assert!(matches!(
            encode_request_frame(&protected),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[test]
    fn stage_preparation_refuses_a_change_set_that_cannot_fit_one_response_frame() {
        let bundle = sample_bundle();
        let suffix = "x".repeat(2_400);
        let change_set = ChangeSet {
            change_set_id: bundle.change_set_id.clone(),
            base_snapshot: bundle.base_snapshot.clone(),
            result_snapshot: bundle.result_snapshot.clone(),
            operations: (0..MAX_CHANGE_SET_OPERATIONS)
                .map(|index| FileOperation::Create {
                    path: PathBuf::from(format!("src/{index:04}-{suffix}")),
                    result_hash: digest(23),
                })
                .collect(),
        };
        assert!(matches!(
            RunnerResponse::stage_prepared(change_set, bundle),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("canonical request exceeds")
                    || message.contains("bounded runner response frame")
        ));
    }

    #[test]
    fn oversized_inline_file_and_command_retention_are_rejected() {
        let request = effect_request(
            "request-2",
            1,
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1024,
            },
        );
        let read = response_for(
            &request,
            RunnerResponse::FileRead {
                path: "src/lib.rs".into(),
                digest: digest(1),
                bytes: vec![0; MAX_INLINE_FILE_BYTES + 1],
            },
        );
        assert!(matches!(
            encode_response_frame(&read),
            Err(WireProtocolError::InvalidContract(_))
        ));

        let command_request = effect_request(
            "request-command-output-bound",
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
        let mut evidence = command_terminal_for(&command_request);
        evidence.stderr = complete_command_stream(b"");
        let at_bound = vec![1; MAX_INLINE_COMMAND_RETAINED_BYTES];
        evidence.stdout = complete_command_stream(&at_bound);
        evidence.output_artifacts =
            command_output_artifacts_for(&command_request, &evidence.stdout, &evidence.stderr);
        evidence.output_digest = command_stream_output_digest(&evidence.stdout, &evidence.stderr);
        rebind_command_terminal(&mut evidence);
        let maximum_inline = response_for(
            &command_request,
            RunnerResponse::CommandCompleted {
                evidence: evidence.clone(),
            },
        );
        let frame = encode_response_frame(&maximum_inline)
            .expect("maximum retained output and cleanup proof fit one frame");
        assert!(frame.len() <= MAX_WIRE_FRAME_BYTES + 4);

        let over_bound = vec![1; MAX_INLINE_COMMAND_RETAINED_BYTES + 1];
        evidence.stdout = complete_command_stream(&over_bound);
        evidence.output_artifacts =
            command_output_artifacts_for(&command_request, &evidence.stdout, &evidence.stderr);
        evidence.output_digest = command_stream_output_digest(&evidence.stdout, &evidence.stderr);
        let command = response_for(
            &command_request,
            RunnerResponse::CommandCompleted { evidence },
        );
        assert!(matches!(
            encode_response_frame(&command),
            Err(WireProtocolError::InvalidContract(_))
        ));

        let mut unreachable_artifact = command_terminal_for(&command_request);
        unreachable_artifact.stdout = WireCommandStreamEvidence {
            retained_bytes: Vec::new(),
            complete_digest: digest(88),
            complete_length: MAX_COMMAND_OUTPUT_ARTIFACT_BYTES + 1,
            truncated: true,
        };
        unreachable_artifact.stderr = complete_command_stream(b"");
        unreachable_artifact.output_artifacts = command_output_artifacts_for(
            &command_request,
            &unreachable_artifact.stdout,
            &unreachable_artifact.stderr,
        );
        unreachable_artifact.output_digest = command_stream_output_digest(
            &unreachable_artifact.stdout,
            &unreachable_artifact.stderr,
        );
        let command = response_for(
            &command_request,
            RunnerResponse::CommandCompleted {
                evidence: unreachable_artifact,
            },
        );
        assert!(matches!(
            encode_response_frame(&command),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[test]
    fn effect_commitment_binds_nonce_sequence_context_and_request() {
        let mut request = effect_request(
            "request-2",
            1,
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1024,
            },
        );
        encode_request_frame(&request).expect("bound effect encodes");

        let mut crossed_contract = request.clone();
        crossed_contract
            .effect
            .as_mut()
            .expect("fixture effect")
            .contract_version = CONTRACT_VERSION + 1;
        crossed_contract
            .bind_transport_commitment_digest()
            .expect("transport can commit the crossed version for validation");
        assert!(matches!(
            encode_request_frame(&crossed_contract),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("effect.contract_version")
        ));

        request.sequence = 2;
        assert!(matches!(
            encode_request_frame(&request),
            Err(WireProtocolError::InvalidContract(_))
        ));
        request.sequence = 1;
        request.runner_nonce = Some(digest(8));
        assert!(matches!(
            encode_request_frame(&request),
            Err(WireProtocolError::InvalidContract(_))
        ));
        request.runner_nonce = Some(digest(9));
        request
            .effect
            .as_mut()
            .expect("fixture effect")
            .input_snapshot = digest(6);
        assert!(matches!(
            encode_request_frame(&request),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[test]
    fn core_request_digest_is_preserved_separately_from_transport_commitment() {
        let request_dto = RunnerRequest::WorkerReadFile {
            path: "src/lib.rs".into(),
            max_bytes: 1024,
        };
        let persisted_request_bytes =
            serde_json::to_vec(&request_dto).expect("canonical persisted request bytes");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-core-1".into(),
            idempotency_key: "idempotency-core-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(
                WorkerLease::new(
                    "sprint-1".into(),
                    1,
                    "task-1".into(),
                    "worker-1".into(),
                    vec![PathScope::Relative(PathBuf::from("src"))],
                    1,
                )
                .expect("worker lease"),
            ),
            causation_event_id: None,
            correlation_id: "correlation-1".into(),
            kind: EffectKind::ReadRelativeFile,
            request_digest: Digest::sha256(&persisted_request_bytes),
            policy_hash: digest(2),
            input_snapshot: digest(7),
            created_at_unix_ms: 1,
        };
        intent.validate().expect("valid core effect intent");

        let mut request = effect_request("request-core-1", 1, request_dto);
        let effect = request.effect.as_mut().expect("wire effect context");
        effect.effect_id.clone_from(&intent.effect_id);
        effect.idempotency_key.clone_from(&intent.idempotency_key);
        effect.sprint_id.clone_from(&intent.sprint_id);
        effect.task_id.clone_from(&intent.task_id);
        effect.worker_id.clone_from(&intent.worker_id);
        effect.worker_lease.clone_from(&intent.worker_lease);
        effect.policy_hash.clone_from(&intent.policy_hash);
        effect.input_snapshot.clone_from(&intent.input_snapshot);
        effect.request_digest.clone_from(&intent.request_digest);
        request
            .bind_transport_commitment_digest()
            .expect("bind transport commitment");

        let decoded = decode_request_frame(
            &encode_request_frame(&request).expect("encode core-bound request"),
        )
        .expect("decode core-bound request");
        assert_eq!(
            decoded
                .effect
                .as_ref()
                .expect("decoded effect")
                .request_digest,
            intent.request_digest
        );
        assert_ne!(
            decoded
                .effect
                .as_ref()
                .expect("decoded effect")
                .transport_commitment_digest,
            intent.request_digest
        );

        let response = response_for(
            &decoded,
            RunnerResponse::failed_before_effect("fixture", "fixture"),
        );
        response
            .validate_correlation(&decoded)
            .expect("effect digest echo correlates");
        assert_eq!(
            response.effect.expect("response effect").request_digest,
            intent.request_digest
        );
    }

    #[test]
    fn controls_forbid_effects_while_ordinary_requests_require_them() {
        let mut request = effect_request(
            "request-2",
            1,
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1,
            },
        );
        request.effect = None;
        assert!(matches!(
            encode_request_frame(&request),
            Err(WireProtocolError::InvalidContract(_))
        ));

        let mut request = effect_request("request-2", 1, RunnerRequest::WorkerCancel);
        assert!(matches!(
            encode_request_frame(&request),
            Err(WireProtocolError::InvalidContract(_))
        ));

        request = control_request("request-2", 1, RunnerRequest::WorkerCancel);
        encode_request_frame(&request).expect("context-free control encodes");
        let response = response_for(
            &request,
            RunnerResponse::failed_before_effect("fixture", "fixture"),
        );
        response
            .validate_correlation(&request)
            .expect("context-free control response correlates exactly");

        request.runner_nonce = None;
        assert!(matches!(
            encode_request_frame(&request),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[test]
    fn bounded_failure_messages_truncate_only_at_utf8_boundaries() {
        let mut adversarial = "a".repeat(MAX_ERROR_MESSAGE_BYTES - 1);
        adversarial.push('é');
        assert_eq!(adversarial.len(), MAX_ERROR_MESSAGE_BYTES + 1);
        assert!(!adversarial.is_char_boundary(MAX_ERROR_MESSAGE_BYTES));

        let initialization = RunnerResponse::initialization_rejected(&adversarial);
        let RunnerResponse::InitializationRejected { message, .. } = initialization else {
            panic!("initialization rejection expected")
        };
        assert_eq!(message.len(), MAX_ERROR_MESSAGE_BYTES - 1);

        for failure in [
            RunnerResponse::failed_before_effect("fixture", &adversarial),
            RunnerResponse::failed_after_known_effect("fixture", &adversarial),
            RunnerResponse::failed_requiring_reconciliation(
                "fixture",
                WireReconciliationReference::ApplicationRecovery,
                &adversarial,
            ),
        ] {
            let RunnerResponse::Failed { message, .. } = failure else {
                panic!("failure response expected")
            };
            assert_eq!(message.len(), MAX_ERROR_MESSAGE_BYTES - 1);
            assert!(message.is_char_boundary(message.len()));
        }
    }

    #[test]
    fn current_stage_authentication_requires_effects_only_for_publication() {
        assert_eq!(RUNNER_WIRE_PROTOCOL_VERSION, 11);
        let change_set = sample_change_set();
        let bundle = sample_bundle();

        let stage_without_effect = control_request(
            "request-stage-without-effect",
            1,
            RunnerRequest::WorkerStageChanges {
                change_set: Box::new(change_set),
                expected_bundle: bundle.clone(),
            },
        );
        assert!(matches!(
            encode_request_frame(&stage_without_effect),
            Err(WireProtocolError::InvalidContract(_))
        ));

        for control in [
            RunnerRequest::WorkerPrepareStage {
                change_set_id: bundle.change_set_id.clone(),
                created_at_unix_ms: 1,
            },
            RunnerRequest::WorkerReconcileStage {
                expected_bundle: bundle.clone(),
            },
            RunnerRequest::ApplierReconcileStageBundle {
                expected_bundle: bundle,
            },
        ] {
            let control_with_effect = effect_request("request-control-with-effect", 2, control);
            assert!(matches!(
                encode_request_frame(&control_with_effect),
                Err(WireProtocolError::InvalidContract(_))
            ));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed request enum classification is exhaustively audited in one table"
    )]
    fn session_control_classification_is_closed_and_exhaustive() {
        let bundle = sample_bundle();
        let rollback = sample_rollback_reference(1);
        let command = WireCommandSpec {
            program: "/usr/bin/true".into(),
            arguments: Vec::new(),
            working_directory: String::new(),
        };
        let requests = vec![
            (sample_request().request, false),
            (
                RunnerRequest::WorkerCaptureLive {
                    created_at_unix_ms: 1,
                },
                true,
            ),
            (
                RunnerRequest::WorkerCreateShadow {
                    base_snapshot: digest(1),
                },
                true,
            ),
            (
                RunnerRequest::WorkerReadFile {
                    path: "a".into(),
                    max_bytes: 1,
                },
                false,
            ),
            (
                RunnerRequest::WorkerSearchLiteral {
                    path: "a".into(),
                    needle: vec![1],
                    max_bytes: 1,
                    max_matches: 1,
                },
                false,
            ),
            (
                RunnerRequest::WorkerCreateFile {
                    path: "a".into(),
                    contents: vec![1],
                },
                false,
            ),
            (
                RunnerRequest::WorkerReplaceFile {
                    path: "a".into(),
                    expected_digest: digest(2),
                    contents: vec![1],
                },
                false,
            ),
            (
                RunnerRequest::WorkerDeleteFile {
                    path: "a".into(),
                    expected_digest: digest(2),
                },
                false,
            ),
            (
                RunnerRequest::WorkerReconcileFile {
                    path: "a".into(),
                    expected: WireFileExpectation::Absent,
                    max_bytes: 1,
                },
                true,
            ),
            (
                RunnerRequest::WorkerPrepareStage {
                    change_set_id: "changeset-1".into(),
                    created_at_unix_ms: 1,
                },
                true,
            ),
            (
                RunnerRequest::WorkerStageChanges {
                    change_set: Box::new(sample_change_set()),
                    expected_bundle: bundle.clone(),
                },
                false,
            ),
            (
                RunnerRequest::WorkerReconcileStage {
                    expected_bundle: bundle.clone(),
                },
                true,
            ),
            (worker_command_request(1, command.clone()), false),
            (RunnerRequest::WorkerCancel, true),
            (
                RunnerRequest::FinalVerifierCapture {
                    created_at_unix_ms: 1,
                },
                true,
            ),
            (final_verifier_command_request(1, command.clone()), false),
            (RunnerRequest::ApplierRecoverPending, true),
            (
                RunnerRequest::ApplierReconcileStageBundle {
                    expected_bundle: bundle.clone(),
                },
                true,
            ),
            (
                RunnerRequest::ApplierApplyBundle {
                    bundle: bundle.clone(),
                },
                false,
            ),
            (
                RunnerRequest::ApplierReconcile {
                    bundle: bundle.clone(),
                },
                true,
            ),
            (
                RunnerRequest::ApplierRollback {
                    bundle: bundle.clone(),
                    rollback,
                },
                false,
            ),
            (
                RunnerRequest::ApplierCaptureLive {
                    created_at_unix_ms: 1,
                },
                true,
            ),
            (RunnerRequest::Shutdown, true),
        ];
        for (request, expected) in requests {
            assert_eq!(request.is_session_control(), expected, "{request:?}");
        }
    }

    #[test]
    fn dot_git_is_rejected_case_insensitively() {
        let request = effect_request(
            "request-2",
            1,
            RunnerRequest::WorkerReadFile {
                path: ".GIT/config".into(),
                max_bytes: 1024,
            },
        );
        assert!(matches!(
            encode_request_frame(&request),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_grant_conversion_rejects_non_utf8_authority_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let grant = WorkspaceGrant {
            grant_id: "grant-non-utf8".into(),
            canonical_root: PathBuf::from(OsString::from_vec(
                b"/tmp/grok-build-non-utf8-\xff".to_vec(),
            )),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: digest(1),
        };
        assert!(WireWorkspaceGrant::try_from(&grant).is_err());
    }

    #[test]
    fn command_terminal_round_trip_uses_stream_framed_complete_commitments() {
        let request = effect_request(
            "request-2",
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
        let stdout = complete_command_stream(b"abc");
        let stderr = complete_command_stream(b"xy");
        let evidence_bytes = command_stream_output_evidence_bytes(&stdout, &stderr);
        assert_eq!(
            Digest::sha256(&evidence_bytes),
            command_stream_output_digest(&stdout, &stderr)
        );
        assert_eq!(
            command_stream_output_digest(&stdout, &stderr).as_str(),
            "d27b6e8bc85bc1d224b89c4181f69334243bc6a9a89373986c2c3fb376f3f999"
        );
        let mut terminal = command_terminal_for(&request);
        terminal.stdout = stdout;
        terminal.stderr = stderr;
        terminal.output_artifacts =
            command_output_artifacts_for(&request, &terminal.stdout, &terminal.stderr);
        terminal.output_digest = command_stream_output_digest(&terminal.stdout, &terminal.stderr);
        rebind_command_terminal(&mut terminal);
        let valid = response_for(
            &request,
            RunnerResponse::CommandCompleted {
                evidence: terminal.clone(),
            },
        );
        let frame = encode_response_frame(&valid).expect("stream-separated terminal evidence");
        let decoded = decode_response_frame(&frame).expect("decode command terminal");
        decoded
            .validate_correlation(&request)
            .expect("command terminal correlates to exact request");
        assert_eq!(decoded, valid);

        let aggregate = command_terminal_evidence_bytes(&terminal)
            .expect("canonical aggregate terminal preimage");
        assert_eq!(
            Digest::sha256(&aggregate),
            command_terminal_digest(&terminal).expect("aggregate terminal digest")
        );

        let mut forged = valid.clone();
        let RunnerResponse::CommandCompleted { evidence } = &mut forged.response else {
            unreachable!()
        };
        evidence.output_digest = digest(1);
        assert!(matches!(
            encode_response_frame(&forged),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[test]
    fn command_terminal_validates_truncated_streams_without_claiming_complete_bytes() {
        let request = effect_request(
            "request-truncated-command",
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
        let mut terminal = command_terminal_for(&request);
        terminal.stdout = WireCommandStreamEvidence {
            retained_bytes: b"a".to_vec(),
            complete_digest: Digest::sha256(b"abc"),
            complete_length: 3,
            truncated: true,
        };
        terminal.output_artifacts =
            command_output_artifacts_for(&request, &terminal.stdout, &terminal.stderr);
        terminal.output_digest = command_stream_output_digest(&terminal.stdout, &terminal.stderr);
        rebind_command_terminal(&mut terminal);
        let valid = response_for(
            &request,
            RunnerResponse::CommandCompleted {
                evidence: terminal.clone(),
            },
        );
        encode_response_frame(&valid).expect("truncated prefix with complete commitment is valid");

        let retained_terminal_digest =
            command_terminal_digest(&terminal).expect("digest truncated terminal");
        let mut substituted_prefix = terminal.clone();
        substituted_prefix.stdout.retained_bytes = b"b".to_vec();
        validate_command_terminal_shape_without_record_digest(&substituted_prefix)
            .expect("complete commitment alone cannot authenticate its claimed prefix");
        assert!(validate_command_terminal_shape(&substituted_prefix).is_err());
        rebind_command_terminal(&mut substituted_prefix);
        assert_ne!(
            command_terminal_digest(&substituted_prefix)
                .expect("digest substituted retained prefix"),
            retained_terminal_digest
        );

        let mut crossed_flag = terminal.clone();
        crossed_flag.stdout.truncated = false;
        crossed_flag.output_digest =
            command_stream_output_digest(&crossed_flag.stdout, &crossed_flag.stderr);
        assert!(validate_command_terminal_shape(&crossed_flag).is_err());

        let mut crossed_digest = terminal.clone();
        crossed_digest.stdout.complete_length = 1;
        crossed_digest.stdout.truncated = false;
        crossed_digest.output_digest =
            command_stream_output_digest(&crossed_digest.stdout, &crossed_digest.stderr);
        assert!(validate_command_terminal_shape(&crossed_digest).is_err());

        let mut synthetic_limit = command_terminal_for(&request);
        synthetic_limit.termination = CommandTerminationV1::OutputLimitExceeded;
        assert!(validate_command_terminal_shape(&synthetic_limit).is_err());

        terminal.termination = CommandTerminationV1::OutputLimitExceeded;
        rebind_command_terminal(&mut terminal);
        validate_command_terminal_shape(&terminal)
            .expect("output-limit terminal with omitted observed output is valid");

        for termination in [
            CommandTerminationV1::Exited { code: 0 },
            CommandTerminationV1::Signaled { signal: 9 },
            CommandTerminationV1::TimedOut,
            CommandTerminationV1::Canceled,
        ] {
            let mut ordinary = command_terminal_for(&request);
            ordinary.termination = termination;
            rebind_command_terminal(&mut ordinary);
            validate_command_terminal_shape(&ordinary)
                .expect("typed non-output terminal validates");
        }
        let mut invalid_exit = command_terminal_for(&request);
        invalid_exit.termination = CommandTerminationV1::Exited { code: -1 };
        assert!(validate_command_terminal_shape(&invalid_exit).is_err());
        invalid_exit.termination = CommandTerminationV1::Signaled { signal: 0 };
        assert!(validate_command_terminal_shape(&invalid_exit).is_err());
    }

    #[test]
    fn command_output_artifacts_are_mandatory_and_exactly_bound() {
        let request = effect_request(
            "request-output-artifacts",
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

        let mut missing: serde_json::Value =
            serde_json::to_value(&valid).expect("serialize command response fixture");
        missing["response"]["evidence"]
            .as_object_mut()
            .expect("terminal evidence object")
            .remove("output_artifacts");
        assert!(serde_json::from_value::<RunnerResponseEnvelope>(missing).is_err());

        let RunnerResponse::CommandCompleted {
            evidence: base_evidence,
        } = &valid.response
        else {
            unreachable!()
        };
        let source = &base_evidence.output_artifacts.source;
        let crossed_sources = [
            CommandOutputArtifactSourceV1 {
                sprint_id: "sprint-crossed".into(),
                ..source.clone()
            },
            CommandOutputArtifactSourceV1 {
                runner_launch_id: "launch-crossed".into(),
                ..source.clone()
            },
            CommandOutputArtifactSourceV1 {
                runner_session_id: "session-crossed".into(),
                ..source.clone()
            },
            CommandOutputArtifactSourceV1 {
                effect_id: "effect-crossed".into(),
                ..source.clone()
            },
            CommandOutputArtifactSourceV1 {
                request_digest: digest(99),
                ..source.clone()
            },
        ];
        for crossed_source in crossed_sources {
            let mut crossed = valid.clone();
            let RunnerResponse::CommandCompleted { evidence } = &mut crossed.response else {
                unreachable!()
            };
            evidence.output_artifacts = CommandOutputArtifactSetReferenceV1::try_new(
                crossed_source,
                evidence.output_artifacts.stdout.clone(),
                evidence.output_artifacts.stderr.clone(),
            )
            .expect("redigest the independently valid crossed source");
            assert!(encode_response_frame(&crossed).is_err());
        }

        let mut crossed_roles = valid.clone();
        let RunnerResponse::CommandCompleted { evidence } = &mut crossed_roles.response else {
            unreachable!()
        };
        std::mem::swap(
            &mut evidence.output_artifacts.stdout,
            &mut evidence.output_artifacts.stderr,
        );
        assert!(encode_response_frame(&crossed_roles).is_err());

        let mut crossed_streams = valid;
        let RunnerResponse::CommandCompleted { evidence } = &mut crossed_streams.response else {
            unreachable!()
        };
        let mut crossed_stdout = evidence.output_artifacts.stdout.clone();
        crossed_stdout.byte_length = crossed_stdout.byte_length.saturating_add(1);
        evidence.output_artifacts = CommandOutputArtifactSetReferenceV1::try_new(
            evidence.output_artifacts.source.clone(),
            crossed_stdout,
            evidence.output_artifacts.stderr.clone(),
        )
        .expect("redigest independently valid crossed stream commitments");
        assert!(encode_response_frame(&crossed_streams).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the v11 adversarial anchor matrix stays together as one auditable contract proof"
    )]
    fn wire_v11_command_capture_anchor_is_mandatory_path_free_and_exactly_bound() {
        let command = WireCommandSpec {
            program: "/usr/bin/true".into(),
            arguments: Vec::new(),
            working_directory: String::new(),
        };
        let request = effect_request(
            "request-capture-anchor",
            1,
            worker_command_request(1, command.clone()),
        );
        encode_request_frame(&request).expect("exact acquired anchor encodes");

        let RunnerRequest::WorkerRunCommand {
            output_capture: capture,
            ..
        } = &request.request
        else {
            unreachable!()
        };
        capture
            .validate_session_binding(
                &digest(3),
                command_output_capture_maximum(1_024).expect("fixture capture maximum"),
            )
            .expect("exact root and limit bind");
        assert!(
            capture
                .validate_session_binding(
                    &digest(99),
                    capture.acquired().max_aggregate_output_bytes
                )
                .is_err()
        );
        assert!(
            capture
                .validate_session_binding(
                    &digest(3),
                    capture.acquired().max_aggregate_output_bytes - 1,
                )
                .is_err()
        );

        let capture_json = serde_json::to_string(capture).expect("encode capture anchor");
        assert!(!capture_json.contains('/'));
        assert!(!capture_json.contains("private_state_root"));
        assert!(!capture_json.contains("\"path\""));

        let mut missing: serde_json::Value =
            serde_json::to_value(&request).expect("encode command request");
        missing["request"]
            .as_object_mut()
            .expect("request object")
            .remove("output_capture");
        assert!(serde_json::from_value::<RunnerRequestEnvelope>(missing).is_err());

        for (field, replacement) in [
            ("layout_version", serde_json::json!(2)),
            ("capture_id", serde_json::json!("A".repeat(64))),
            ("dispatch_claim_id", serde_json::json!(digest(88).as_str())),
            ("acquired_anchor_digest", serde_json::json!(digest(89))),
        ] {
            let mut crossed: serde_json::Value =
                serde_json::to_value(&request).expect("encode command request");
            crossed["request"]["output_capture"][field] = replacement;
            let crossed: RunnerRequestEnvelope =
                serde_json::from_value(crossed).expect("decode structurally valid crossed anchor");
            assert!(encode_request_frame(&crossed).is_err(), "{field}");
        }

        let base_source = capture.acquired().source.clone();
        let crossed_sources = [
            CommandOutputArtifactSourceV1 {
                sprint_id: "sprint-crossed".into(),
                ..base_source.clone()
            },
            CommandOutputArtifactSourceV1 {
                runner_launch_id: "launch-crossed".into(),
                ..base_source.clone()
            },
            CommandOutputArtifactSourceV1 {
                runner_session_id: "session-crossed".into(),
                ..base_source.clone()
            },
            CommandOutputArtifactSourceV1 {
                effect_id: "effect-crossed".into(),
                ..base_source.clone()
            },
            CommandOutputArtifactSourceV1 {
                request_digest: digest(90),
                ..base_source
            },
        ];
        for (index, source) in crossed_sources.into_iter().enumerate() {
            let mut crossed = request.clone();
            let RunnerRequest::WorkerRunCommand { output_capture, .. } = &mut crossed.request
            else {
                unreachable!()
            };
            *output_capture = test_command_output_capture_anchor(
                source,
                digest(3),
                command_output_capture_maximum(1_024).expect("fixture capture maximum"),
                20 + u64::try_from(index).expect("index fits u64"),
            );
            crossed
                .bind_transport_commitment_digest()
                .expect("bind crossed capture transport");
            assert!(encode_request_frame(&crossed).is_err());
        }

        let mut crossed_identity: serde_json::Value =
            serde_json::to_value(&request).expect("encode command request");
        crossed_identity["request"]["output_capture"]["stderr"]["inode"] =
            crossed_identity["request"]["output_capture"]["stdout"]["inode"].clone();
        let crossed_identity: RunnerRequestEnvelope = serde_json::from_value(crossed_identity)
            .expect("decode structurally valid crossed identity");
        assert!(encode_request_frame(&crossed_identity).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the v11 terminal substitution matrix stays together as one auditable contract proof"
    )]
    fn wire_v11_command_terminal_binds_monotonic_capture_journal_and_record() {
        let command = WireCommandSpec {
            program: "/usr/bin/true".into(),
            arguments: Vec::new(),
            working_directory: String::new(),
        };
        let request = effect_request(
            "request-capture-terminal",
            1,
            worker_command_request(1, command.clone()),
        );
        let terminal = command_terminal_for(&request);
        let valid = response_for(
            &request,
            RunnerResponse::CommandCompleted {
                evidence: terminal.clone(),
            },
        );
        valid
            .validate_correlation(&request)
            .expect("terminal binds exact acquired capture");

        let mut non_monotonic = terminal.clone();
        non_monotonic.output_capture.published_store_head.generation =
            non_monotonic.output_capture.finished_store_head.generation;
        assert!(non_monotonic.bind_terminal_record_digest().is_err());

        let mut reused_head = terminal.clone();
        reused_head
            .output_capture
            .published_store_head
            .record_digest = reused_head
            .output_capture
            .finished_store_head
            .record_digest
            .clone();
        assert!(reused_head.bind_terminal_record_digest().is_err());

        let mut crossed_record = valid.clone();
        let RunnerResponse::CommandCompleted { evidence } = &mut crossed_record.response else {
            unreachable!()
        };
        evidence.output_capture.terminal_record_digest = digest(91);
        assert!(encode_response_frame(&crossed_record).is_err());

        for mutate in [
            |capture: &mut WireCommandOutputCaptureTerminalV1| {
                capture.capture_id = digest(92).as_str().to_owned();
            },
            |capture: &mut WireCommandOutputCaptureTerminalV1| {
                capture.acquired_anchor_digest = digest(93);
            },
        ] {
            let mut crossed = terminal.clone();
            mutate(&mut crossed.output_capture);
            crossed
                .bind_terminal_record_digest()
                .expect("crossed terminal remains self-consistent");
            let crossed = response_for(
                &request,
                RunnerResponse::CommandCompleted { evidence: crossed },
            );
            assert!(crossed.validate_correlation(&request).is_err());
        }

        let acquired_generation = match &request.request {
            RunnerRequest::WorkerRunCommand { output_capture, .. } => {
                output_capture.acquired().store_head.generation
            }
            _ => unreachable!(),
        };
        let mut stale_finished = terminal.clone();
        stale_finished.output_capture.finished_store_head.generation = acquired_generation;
        stale_finished
            .bind_terminal_record_digest()
            .expect("terminal is internally ordered but stale against acquisition");
        let stale_finished = response_for(
            &request,
            RunnerResponse::CommandCompleted {
                evidence: stale_finished,
            },
        );
        assert!(stale_finished.validate_correlation(&request).is_err());

        let mut low_limit_request = request.clone();
        let effect = low_limit_request.effect.as_ref().expect("command effect");
        let RunnerRequest::WorkerRunCommand { output_capture, .. } = &mut low_limit_request.request
        else {
            unreachable!()
        };
        *output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: effect.sprint_id.clone(),
                runner_launch_id: effect.launch_id.clone(),
                runner_session_id: low_limit_request.session_id.clone(),
                effect_id: effect.effect_id.clone(),
                request_digest: effect.request_digest.clone(),
            },
            digest(3),
            1,
            40,
        );
        low_limit_request
            .bind_transport_commitment_digest()
            .expect("bind low-limit capture");
        let low_limit_terminal = command_terminal_for(&low_limit_request);
        let low_limit_response = response_for(
            &low_limit_request,
            RunnerResponse::CommandCompleted {
                evidence: low_limit_terminal,
            },
        );
        assert!(
            low_limit_response
                .validate_correlation(&low_limit_request)
                .is_err()
        );
    }

    #[test]
    fn terminal_record_restart_decoder_is_strict_canonical_and_digest_bound() {
        let request = effect_request(
            "request-terminal-restart-decode",
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
        let terminal = command_terminal_for(&request);
        let bytes = command_terminal_record_bytes(&terminal).expect("canonical terminal bytes");
        let terminal_head = terminal.output_capture.terminal_prepared_store_head.clone();
        let decoded = decode_command_terminal_record_bytes(&bytes, &terminal_head)
            .expect("strict restart decode");
        assert_eq!(decoded, terminal);
        assert_eq!(
            decoded.output_capture.terminal_record_digest,
            Digest::sha256(&bytes)
        );
        assert_eq!(
            decoded.output_capture.terminal_prepared_store_head,
            terminal_head
        );

        assert!(matches!(
            decode_command_terminal_record_bytes(&bytes[..bytes.len() - 1], &terminal_head),
            Err(WireProtocolError::TruncatedPayload { .. })
        ));
        assert!(matches!(
            decode_command_terminal_record_bytes(
                &bytes[..COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN.len()],
                &terminal_head
            ),
            Err(WireProtocolError::TruncatedPrefix)
        ));

        let payload_start =
            COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN.len() + std::mem::size_of::<u64>();
        let payload = &bytes[payload_start..];
        let mut extra_field = payload[..payload.len() - 1].to_vec();
        extra_field.extend_from_slice(b",\"unexpected\":true}");
        assert!(matches!(
            decode_command_terminal_record_bytes(
                &framed_command_terminal_json(&extra_field),
                &terminal_head
            ),
            Err(WireProtocolError::InvalidJson(_))
        ));

        let mut noncanonical = payload.to_vec();
        noncanonical.insert(1, b' ');
        assert!(matches!(
            decode_command_terminal_record_bytes(
                &framed_command_terminal_json(&noncanonical),
                &terminal_head
            ),
            Err(WireProtocolError::NonCanonical)
        ));

        let mut substituted: DecodedCommandTerminalRecord =
            serde_json::from_slice(payload).expect("decode owned fixture");
        substituted
            .output_capture
            .expected_output_artifacts
            .stdout
            .content_digest = digest(90);
        let substituted = serde_json::to_vec(&substituted).expect("encode canonical substitution");
        assert!(matches!(
            decode_command_terminal_record_bytes(
                &framed_command_terminal_json(&substituted),
                &terminal_head
            ),
            Err(WireProtocolError::InvalidContract(_))
        ));

        let mut digest_substitution: DecodedCommandTerminalRecord =
            serde_json::from_slice(payload).expect("decode digest fixture");
        digest_substitution.output_digest = digest(91);
        let digest_substitution =
            serde_json::to_vec(&digest_substitution).expect("encode digest substitution");
        assert!(matches!(
            decode_command_terminal_record_bytes(
                &framed_command_terminal_json(&digest_substitution),
                &terminal_head
            ),
            Err(WireProtocolError::InvalidContract(_))
        ));

        let mut stale_head = terminal_head;
        stale_head.generation = terminal.output_capture.published_store_head.generation;
        assert!(matches!(
            decode_command_terminal_record_bytes(&bytes, &stale_head),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }
