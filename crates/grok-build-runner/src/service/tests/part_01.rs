    use std::io::{Read as _, Write as _};
    use std::net::Shutdown;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use grok_build_core::{
        CONTRACT_VERSION, CommandOutputArtifactSourceV1, CommandOutputCaptureIntentV1, CommandSpec,
        PathScope, WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };

    use crate::command::contained_boundary::{
        BackendIdentity, test_contained_execution_evidence,
        test_contained_sensitive_output_rejection_evidence,
    };
    use crate::wire::{
        WireCommandOutputCaptureAnchorV1, WireCommandSpec, WireFailureClass,
        command_output_capture_maximum, decode_response_frame, encode_request_frame,
        test_command_output_capture_anchor,
    };
    use crate::{CommandDomainCleanupBinding, CommandTermination};

    use super::*;

    static NEXT_STAGE_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct StageTestDirectory(PathBuf);

    impl StageTestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_STAGE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-service-stage-{label}-{}-{sequence}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }

    impl Drop for StageTestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn private_directory(path: &Path) {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn unchanged_shadow_fixture() -> (
        StageTestDirectory,
        IssuedWorkspaceGrant,
        CapabilityShadowWorkspace,
        CapabilityStageBundleStore,
    ) {
        let top = StageTestDirectory::new("verified-noop");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("input.txt"), b"unchanged\n").unwrap();
        let private = top.0.join("private");
        private_directory(&private);
        let live = fs::canonicalize(live).unwrap();
        let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "service-stage-test-grant".into(),
            workspace_root: live,
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .unwrap();
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let shadow_store = CapabilityShadowStore::open(&private).unwrap();
        let bundle_store = CapabilityStageBundleStore::open(&private).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let shadow = workspace
            .create_shadow(&grant, &base, &shadow_store, "worker-shadow")
            .unwrap();
        (top, grant, shadow, bundle_store)
    }

    fn digest(byte: u8) -> Digest {
        Digest::sha256(&[byte])
    }

    fn runner_core_dump_profile_fixture()
    -> crate::sensitive_output::SensitiveOutputCoreDumpSuppressionV1 {
        #[cfg(target_os = "linux")]
        let core = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::linux();
        #[cfg(not(target_os = "linux"))]
        let core = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::macos();
        let runner = crate::sensitive_output::SensitiveOutputCoreDumpSuppressionV1 {
            schema_version: core.schema_version,
            core_limit_current: core.core_limit_current,
            core_limit_maximum: core.core_limit_maximum,
            linux_dumpable_disabled: core.linux_dumpable_disabled,
            profile_digest: core.profile_digest.clone(),
        };
        runner
            .validate()
            .expect("runner fixture validates the exact zero-dump profile");
        assert_eq!(
            serde_json::to_vec(&runner).expect("encode runner zero-dump profile"),
            serde_json::to_vec(&core).expect("encode core zero-dump profile")
        );
        assert_eq!(runner.profile_digest, core.profile_digest);
        runner
    }

    struct OneCommandJobFactory {
        job: Option<CommandJob>,
    }

    struct JobExitGuard(Arc<AtomicBool>);

    impl Drop for JobExitGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct PollingSocketWriter(UnixStream);

    impl Write for PollingSocketWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            loop {
                match self.0.write(bytes) {
                    Ok(written) => return Ok(written),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        let mut descriptor = [PollFd::new(&self.0, PollFlags::OUT)];
                        poll(&mut descriptor, None).map_err(io::Error::from)?;
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl OneCommandJobFactory {
        fn new(job: CommandJob) -> Self {
            Self { job: Some(job) }
        }
    }

    impl CommandJobFactory for OneCommandJobFactory {
        fn create(
            &mut self,
            _envelope: &RunnerRequestEnvelopeV12,
            _authority: &CommandEffectAuthorityV2,
        ) -> Option<CommandJob> {
            self.job.take()
        }
    }

    fn coordinator_worker_lease() -> WorkerLease {
        WorkerLease::new(
            "coordinator-sprint".into(),
            1,
            "coordinator-task".into(),
            "coordinator-worker".into(),
            vec![PathScope::Workspace],
            1,
        )
        .expect("coordinator worker lease")
    }

    fn coordinator_service() -> RunnerService {
        let mut service = RunnerService::new(digest(90));
        service.session = Some(InitializedSession::Test(Box::new(TestInitializedSession {
            role: RunnerRole::Worker,
            session_id: "coordinator-session".into(),
            launch_id: "coordinator-launch".into(),
            sprint_id: "coordinator-sprint".into(),
            logical_worker_id: Some("coordinator-worker".into()),
            worker_lease: Some(coordinator_worker_lease()),
            policy_hash: digest(91),
            grant_hash: digest(92),
            input_snapshot: digest(93),
        })));
        service.seen_request_ids.insert("initialize-0".into());
        service.expected_sequence = 1;
        service.command_capture_private_state_digest = Some(digest(97));
        service.command_capture_max_aggregate_output_bytes =
            Some(command_output_capture_maximum(1_024).expect("coordinator capture maximum"));
        service
    }

    fn coordinator_command(sequence: u64) -> RunnerRequestEnvelopeV12 {
        let command = WireCommandSpec {
            program: "/usr/bin/true".into(),
            arguments: Vec::new(),
            working_directory: String::new(),
        };
        let persisted = serde_json::to_vec(&CommandSpec {
            program: command.program.clone(),
            arguments: command.arguments.clone(),
            working_directory: PathBuf::new(),
        })
        .expect("canonical command fixture");
        let effect_id = format!("command-effect-{sequence}");
        let request_digest = Digest::sha256(&persisted);
        let output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: "coordinator-sprint".into(),
                runner_launch_id: "coordinator-launch".into(),
                runner_session_id: "coordinator-session".into(),
                effect_id: effect_id.clone(),
                request_digest: request_digest.clone(),
            },
            digest(97),
            command_output_capture_maximum(1_024).expect("coordinator capture maximum"),
            sequence,
        );
        let mut envelope = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: "coordinator-session".into(),
            runner_nonce: digest(90),
            sequence,
            request_id: format!("command-{sequence}"),
            effect: WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "coordinator-launch".into(),
                effect_id,
                idempotency_key: format!("command-idempotency-{sequence}"),
                sprint_id: "coordinator-sprint".into(),
                task_id: Some("coordinator-task".into()),
                worker_id: Some("coordinator-worker".into()),
                worker_lease: Some(coordinator_worker_lease()),
                policy_hash: digest(91),
                input_snapshot: digest(93),
                request_digest,
                transport_commitment_digest: digest(0),
            },
            request: crate::wire::RunnerRequestV12::RunCommand {
                request: RunnerRequest::WorkerRunCommand {
                    command,
                    output_capture,
                },
                detector_policy:
                    grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            },
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind command transport commitment");
        envelope
    }

    fn coordinator_control(sequence: u64, request: RunnerRequest) -> RunnerRequestEnvelope {
        RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: "coordinator-session".into(),
            runner_nonce: Some(digest(90)),
            sequence,
            request_id: format!("control-{sequence}"),
            effect: None,
            request,
        }
    }

    fn prepared_after_known_response(request: &RunnerRequestEnvelopeV12) -> RunnerResponseV12 {
        RunnerResponseV12::command_failed(
            request.detector_policy().clone(),
            WireFailureClass::AfterKnownEffect,
            WireCommandFailureCodeV12::InternalFailure,
            None,
        )
        .expect("construct typed v12 after-known-effect fixture")
    }

    fn spawn_coordinator<F>(
        mut service: RunnerService,
        mut command_jobs: F,
    ) -> (
        UnixStream,
        thread::JoinHandle<Result<(), RunnerServiceError>>,
    )
    where
        F: CommandJobFactory + Send + 'static,
    {
        let (client, mut reader) = UnixStream::pair().expect("coordinator socket pair");
        let writer = reader.try_clone().expect("coordinator response socket");
        let server = thread::spawn(move || {
            set_nonblocking(&reader)?;
            let mut writer = PollingSocketWriter(writer);
            service.serve_nonblocking(&mut reader, &mut writer, &mut command_jobs)
        });
        (client, server)
    }

    trait CoordinatorRequestFrame {
        fn encode_test_frame(&self) -> Vec<u8>;
    }

    impl CoordinatorRequestFrame for RunnerRequestEnvelope {
        fn encode_test_frame(&self) -> Vec<u8> {
            encode_request_frame(self).expect("encode v11 coordinator request")
        }
    }

    impl CoordinatorRequestFrame for RunnerRequestEnvelopeV12 {
        fn encode_test_frame(&self) -> Vec<u8> {
            crate::wire::encode_request_frame_v12(self)
                .expect("encode v12 coordinator command request")
        }
    }

    fn write_request<T: CoordinatorRequestFrame>(stream: &mut UnixStream, request: &T) {
        let frame = request.encode_test_frame();
        stream.write_all(&frame).expect("write coordinator request");
    }

    fn read_response_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut prefix = [0_u8; 4];
        stream
            .read_exact(&mut prefix)
            .expect("read coordinator response prefix");
        let payload_length =
            usize::try_from(u32::from_be_bytes(prefix)).expect("response payload length");
        let mut frame = vec![0_u8; 4 + payload_length];
        frame[..4].copy_from_slice(&prefix);
        stream
            .read_exact(&mut frame[4..])
            .expect("read coordinator response payload");
        frame
    }

    fn read_response(stream: &mut UnixStream) -> RunnerResponseEnvelope {
        decode_response_frame(&read_response_frame(stream))
            .expect("decode v11 coordinator response")
    }

    fn read_response_v12(stream: &mut UnixStream) -> RunnerResponseEnvelopeV12 {
        crate::wire::decode_response_frame_v12(&read_response_frame(stream))
            .expect("decode v12 coordinator command response")
    }

    fn assert_no_response(stream: &mut UnixStream) {
        stream
            .set_nonblocking(true)
            .expect("set nonblocking response probe");
        let mut byte = [0_u8; 1];
        let result = stream.read(&mut byte);
        stream
            .set_nonblocking(false)
            .expect("restore blocking response socket");
        match result {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            result => panic!("unexpected response byte: {result:?}"),
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the integration proof constructs and checks every Acquired-to-TerminalPrepared custody transition explicitly"
    )]
    fn contained_terminal_is_journaled_before_service_emits_command_completed() {
        let private = StageTestDirectory::new("contained-terminal");
        let store = CapabilityCommandOutputStore::open(&private.0).expect("open capture store");
        let private_state_digest = inspect_private_state_digest(&private.0)
            .expect("inspect exact test private-state identity");
        let mut request = coordinator_command(1);
        let fixture_acquired = match request.request.command_request() {
            RunnerRequest::WorkerRunCommand { output_capture, .. } => {
                output_capture.acquired().clone()
            }
            _ => panic!("coordinator command must carry capture authority"),
        };
        let capture_id = Digest::sha256(b"service-contained-terminal-capture/v1")
            .as_str()
            .to_owned();
        let intent = CommandOutputCaptureIntentV1::try_new(
            capture_id,
            fixture_acquired.source,
            private_state_digest.clone(),
            fixture_acquired.max_aggregate_output_bytes,
            1,
        )
        .expect("construct exact terminal test capture intent");
        let detector_policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let reservation = store
            .reserve_anchored_capture_v2(
                &intent,
                &fixture_acquired.dispatch_claim_id,
                2,
                &detector_policy,
            )
            .expect("reserve exact terminal test capture");
        let acquired = reservation
            .into_acquired_anchor_for_handoff()
            .expect("close reservation descriptors before runner handoff");
        let anchor = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
            .expect("construct exact wire capture anchor");
        let crate::wire::RunnerRequestV12::RunCommand {
            request: command_request,
            ..
        } = &mut request.request;
        let RunnerRequest::WorkerRunCommand { output_capture, .. } = command_request else {
            panic!("coordinator command changed request class")
        };
        *output_capture = anchor;
        request
            .bind_transport_commitment_digest()
            .expect("rebind request to real acquired capture");

        let capture = store
            .reopen_anchored_capture_v2(&acquired, &detector_policy)
            .expect("runner attaches exact output writers");
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        let launch_intended_store_head = publisher
            .record_launch_intended_v2(
                "runner-contained-capture-launch/v1",
                br#"{"service_terminal_test":true}"#.to_vec(),
                &runner_core_dump_profile_fixture(),
            )
            .expect("append LaunchIntended before fixture launch");
        let stdout_bytes = b"service stdout\n".to_vec();
        let stderr_bytes = b"service stderr\n".to_vec();
        stdout.append(&stdout_bytes).expect("append fixture stdout");
        stderr.append(&stderr_bytes).expect("append fixture stderr");
        publisher
            .record_sensitive_output_scanned_clean_v2()
            .expect("append exact clean scan boundary");
        let stdout = stdout.finish().expect("finish fixture stdout");
        let stderr = stderr.finish().expect("finish fixture stderr");
        let validated_artifact = publisher
            .publish(stdout, stderr)
            .expect("publish exact fixture output");
        let output_artifacts = validated_artifact.reference().clone();
        let finished_store_head = validated_artifact
            .capture_finished_store_head()
            .expect("published fixture retains Finished head")
            .clone();
        let published_store_head = validated_artifact
            .capture_published_store_head()
            .expect("published fixture retains Published head")
            .clone();
        drop(validated_artifact);

        let effect = &request.effect;
        let cleanup_binding = CommandDomainCleanupBinding::try_new(
            request.session_id.clone(),
            effect.effect_id.clone(),
            effect.request_digest.clone(),
        )
        .expect("construct exact command cleanup binding");
        let cleanup_proof =
            crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&cleanup_binding);
        let evidence = test_contained_execution_evidence(
            CommandTermination::Exited(0),
            stdout_bytes,
            stderr_bytes,
            output_artifacts,
            acquired.capture_id.clone(),
            acquired.acquired_anchor_digest.clone(),
            launch_intended_store_head,
            finished_store_head,
            published_store_head,
            digest(94),
            digest(95),
            cleanup_proof,
        );
        let mut service = coordinator_service();
        service.command_capture_private_state_digest = Some(private_state_digest);
        service.command_capture_store = Some(store.clone());
        let job: CommandJob = Box::new(move |_cancellation| {
            CommandJobOutcome::Terminal(Box::new(CommandTerminalOutcome::Contained(evidence)))
        });
        let (mut client, server) = spawn_coordinator(service, OneCommandJobFactory::new(job));
        write_request(&mut client, &request);
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );
        let response_envelope = read_response_v12(&mut client);
        response_envelope
            .validate_correlation(&request)
            .expect("clean v12 service response correlates to the exact command");
        let response = response_envelope.response;
        let RunnerResponseV12::CommandCompleted {
            evidence: terminal,
            scan_receipt,
            ..
        } = response
        else {
            panic!("service must emit only the durably prepared terminal")
        };
        terminal
            .validate_for_output_capture(match request.request.command_request() {
                RunnerRequest::WorkerRunCommand { output_capture, .. } => output_capture,
                _ => unreachable!(),
            })
            .expect("emitted terminal binds the exact acquired request capture");
        let recovery = store
            .reopen_capture(&acquired.capture_id)
            .expect("reopen exact TerminalPrepared capture");
        assert_eq!(
            recovery.state(),
            crate::command_output_store::CommandOutputCaptureJournalStateV1::TerminalPrepared
        );
        assert_eq!(
            recovery.terminal_prepared_store_head(),
            Some(&terminal.output_capture.terminal_prepared_store_head)
        );
        let terminal_record = command_terminal_record_bytes(&terminal)
            .expect("reconstruct canonical emitted terminal record");
        assert_eq!(
            recovery
                .terminal()
                .expect("TerminalPrepared payload")
                .canonical_bytes,
            terminal_record
        );
        assert_eq!(
            store
                .reopen_sensitive_output_clean_v2(&acquired.capture_id)
                .expect("reopen v2 clean receipt"),
            Some(scan_receipt)
        );
        assert!(matches!(
            read_response(&mut client).response,
            RunnerResponse::ShutdownPrepared { .. }
        ));
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    #[allow(
        clippy::items_after_statements,
        clippy::too_many_lines,
        reason = "the integration proof keeps its recursive raw-JSON privacy assertion beside the parsed response it audits"
    )]
    fn sensitive_output_rejection_round_trips_without_rejected_output_fields_or_bytes() {
        const SENTINEL: &[u8] = b"gb-secret-canary-service-rejection";

        let private = StageTestDirectory::new("sensitive-output-rejection");
        let store = CapabilityCommandOutputStore::open(&private.0).expect("open capture store");
        let private_state_digest = inspect_private_state_digest(&private.0)
            .expect("inspect exact test private-state identity");
        let mut request = coordinator_command(1);
        let fixture_acquired = match request.request.command_request() {
            RunnerRequest::WorkerRunCommand { output_capture, .. } => {
                output_capture.acquired().clone()
            }
            _ => panic!("coordinator command must carry capture authority"),
        };
        let capture_id = Digest::sha256(b"service-sensitive-output-rejection-capture/v1")
            .as_str()
            .to_owned();
        let intent = CommandOutputCaptureIntentV1::try_new(
            capture_id,
            fixture_acquired.source,
            private_state_digest.clone(),
            fixture_acquired.max_aggregate_output_bytes,
            1,
        )
        .expect("construct exact rejection test capture intent");
        let detector_policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let reservation = store
            .reserve_anchored_capture_v2(
                &intent,
                &fixture_acquired.dispatch_claim_id,
                2,
                &detector_policy,
            )
            .expect("reserve exact rejection test capture");
        let acquired = reservation
            .into_acquired_anchor_for_handoff()
            .expect("close reservation descriptors before runner handoff");
        let anchor = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
            .expect("construct exact wire capture anchor");
        let crate::wire::RunnerRequestV12::RunCommand {
            request: command_request,
            ..
        } = &mut request.request;
        let RunnerRequest::WorkerRunCommand { output_capture, .. } = command_request else {
            panic!("coordinator command changed request class")
        };
        *output_capture = anchor;
        request
            .bind_transport_commitment_digest()
            .expect("rebind request to real acquired capture");

        let capture = store
            .reopen_anchored_capture_v2(&acquired, &detector_policy)
            .expect("runner attaches exact rejection writers");
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        stdout
            .append(SENTINEL)
            .expect("stage rejected sentinel stdout");
        stderr
            .append(SENTINEL)
            .expect("stage rejected sentinel stderr");
        let launch_intended_store_head = publisher
            .record_launch_intended_v2(
                "runner-sensitive-output-rejection/v1",
                br#"{"service_rejection_test":true}"#.to_vec(),
                &runner_core_dump_profile_fixture(),
            )
            .expect("append LaunchIntended before fixture launch");
        publisher
            .record_sensitive_output_detected_v2(&launch_intended_store_head, &detector_policy)
            .expect("durably record sensitive-output detection");

        let effect = &request.effect;
        let cleanup_binding = CommandDomainCleanupBinding::try_new(
            request.session_id.clone(),
            effect.effect_id.clone(),
            effect.request_digest.clone(),
        )
        .expect("construct exact rejection cleanup binding");
        let cleanup_proof =
            crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&cleanup_binding);
        let neutralization = publisher
            .neutralize_sensitive_output_staging_v2(&mut stdout, &mut stderr)
            .expect("neutralize every rejected staging object");
        let abandonment = publisher
            .abandon_sensitive_output_v2(
                stdout.into_custody(),
                stderr.into_custody(),
                grok_build_core::CommandTerminationV1::Canceled,
                cleanup_proof.os_evidence_digest().as_str(),
                &detector_policy,
                &neutralization,
            )
            .expect("durably abandon rejected output");
        let cleaned_store_head = abandonment
            .recovery
            .cleaned_store_head()
            .cloned()
            .expect("rejection retains exact Cleaned store head");
        assert!(abandonment.recovery.expected_reference().is_none());
        let evidence = test_contained_sensitive_output_rejection_evidence(
            CommandTermination::Cancelled,
            detector_policy,
            acquired.capture_id.clone(),
            acquired.acquired_anchor_digest.clone(),
            launch_intended_store_head,
            cleaned_store_head,
            abandonment.journal_receipt,
            BackendIdentity::new(
                crate::cleanup_proof::CommandDomainCleanupBackend::LinuxCgroupV2,
                "service-rejection-test-backend",
                Digest::sha256(b"service-rejection-test-backend/v1"),
            ),
            cleanup_proof,
        );

        let mut service = coordinator_service();
        service.command_capture_private_state_digest = Some(private_state_digest);
        service.command_capture_store = Some(store);
        let job: CommandJob = Box::new(move |_cancellation| {
            CommandJobOutcome::Terminal(Box::new(CommandTerminalOutcome::SensitiveOutputRejected(
                evidence,
            )))
        });
        let (mut client, server) = spawn_coordinator(service, OneCommandJobFactory::new(job));
        write_request(&mut client, &request);
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );

        let raw_frame = read_response_frame(&mut client);
        let raw_payload = &raw_frame[4..];
        assert!(
            !raw_payload
                .windows(SENTINEL.len())
                .any(|bytes| bytes == SENTINEL),
            "rejected sentinel bytes crossed the service response boundary"
        );
        let json: serde_json::Value =
            serde_json::from_slice(raw_payload).expect("parse exact v12 rejection frame payload");
        fn assert_no_forbidden_rejection_keys(value: &serde_json::Value) {
            match value {
                serde_json::Value::Object(fields) => {
                    for (key, value) in fields {
                        assert!(
                            !matches!(
                                key.as_str(),
                                "output"
                                    | "artifact"
                                    | "duration"
                                    | "duration_ms"
                                    | "length"
                                    | "offset"
                                    | "message"
                                    | "fingerprint"
                            ),
                            "v12 rejection frame retained forbidden key {key:?}"
                        );
                        assert_no_forbidden_rejection_keys(value);
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        assert_no_forbidden_rejection_keys(value);
                    }
                }
                _ => {}
            }
        }
        assert_no_forbidden_rejection_keys(&json);

        let response_envelope = crate::wire::decode_response_frame_v12(&raw_frame)
            .expect("decode exact v12 rejection response");
        response_envelope
            .validate_correlation(&request)
            .expect("rejection response correlates to the exact v12 command");
        let RunnerResponseV12::CommandOutputAbandoned { rejection } = response_envelope.response
        else {
            panic!("service must emit only the typed sensitive-output abandonment")
        };
        assert_eq!(rejection.capture_id, acquired.capture_id);
        assert_eq!(
            rejection.reason,
            grok_build_core::CommandOutputAbandonmentReasonV2::SensitiveOutputRejected
        );
        assert!(matches!(
            read_response(&mut client).response,
            RunnerResponse::ShutdownPrepared { .. }
        ));
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    fn crossed_command_capture_root_and_limit_are_rejected_before_effect_admission() {
        let expected_maximum =
            command_output_capture_maximum(1_024).expect("coordinator capture maximum");
        for (private_state_digest, maximum) in [
            (digest(98), expected_maximum),
            (digest(97), expected_maximum - 1),
        ] {
            let mut request = coordinator_command(1);
            let source = match request.request.command_request() {
                RunnerRequest::WorkerRunCommand { output_capture, .. } => {
                    output_capture.acquired().source.clone()
                }
                _ => unreachable!(),
            };
            let crate::wire::RunnerRequestV12::RunCommand {
                request: command_request,
                ..
            } = &mut request.request;
            let RunnerRequest::WorkerRunCommand { output_capture, .. } = command_request else {
                unreachable!()
            };
            *output_capture =
                test_command_output_capture_anchor(source, private_state_digest, maximum, maximum);
            request
                .bind_transport_commitment_digest()
                .expect("bind crossed capture transport commitment");

            let mut service = coordinator_service();
            assert!(matches!(
                service.validate_v12_envelope_order(&request),
                Err(RunnerServiceError::EffectContextMismatch)
            ));
            assert_eq!(service.command_effects_admitted, 0);
            assert!(!service.seen_request_ids.contains(&request.request_id));
            assert!(service.seen_effect_ids.is_empty());
        }
    }

    #[test]
    fn service_rejects_v11_run_command_before_factory_or_effect_admission() {
        let mut legacy_command = coordinator_command(1).as_v11_envelope();
        legacy_command
            .bind_transport_commitment_digest()
            .expect("bind exact historical v11 command commitment");
        let never_run: CommandJob = Box::new(|_| panic!("v11 command reached the job factory"));
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(never_run));
        write_request(&mut client, &legacy_command);
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );

        let rejected = read_response(&mut client);
        assert!(matches!(
            rejected.response,
            RunnerResponse::Failed {
                ref code,
                class: WireFailureClass::BeforeEffect,
                reconciliation: None,
                ..
            } if code == "command_requires_runner_protocol_v12"
        ));
        let RunnerResponse::ShutdownPrepared { acknowledgement } =
            read_response(&mut client).response
        else {
            panic!("shutdown acknowledgement expected")
        };
        assert_eq!(acknowledgement.command_effects_admitted, 0);
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    fn mixed_router_selects_only_the_exact_leading_canonical_version_prefix() {
        assert_eq!(RUNNER_WIRE_PROTOCOL_VERSION, 11);
        assert_eq!(RUNNER_WIRE_PROTOCOL_VERSION_V12, 12);
        let control = coordinator_control(1, RunnerRequest::Shutdown);
        let control_frame = encode_request_frame(&control).expect("encode canonical v11 control");
        assert_eq!(
            decode_service_request_frame(&control_frame).expect("route exact v11 prefix"),
            ServiceRequestEnvelope::V11(control)
        );

        let command = coordinator_command(1);
        let command_frame =
            crate::wire::encode_request_frame_v12(&command).expect("encode canonical v12 command");
        assert_eq!(
            decode_service_request_frame(&command_frame).expect("route exact v12 prefix"),
            ServiceRequestEnvelope::V12(command)
        );

        let mut padded_payload = b" ".to_vec();
        padded_payload.extend_from_slice(&control_frame[4..]);
        let mut padded = u32::try_from(padded_payload.len())
            .expect("bounded padded payload")
            .to_be_bytes()
            .to_vec();
        padded.extend_from_slice(&padded_payload);
        assert!(matches!(
            decode_service_request_frame(&padded),
            Err(WireProtocolError::InvalidContract(message))
                if message.contains("exact leading canonical")
        ));

        let unknown_payload = br#"{"protocol_version":13,"session_id":"x"}"#;
        let mut unknown = u32::try_from(unknown_payload.len())
            .expect("bounded unknown payload")
            .to_be_bytes()
            .to_vec();
        unknown.extend_from_slice(unknown_payload);
        assert!(matches!(
            decode_service_request_frame(&unknown),
            Err(WireProtocolError::InvalidContract(_))
        ));
    }

    #[test]
    fn historical_v11_shutdown_codec_remains_byte_exact() {
        let request = coordinator_control(1, RunnerRequest::Shutdown);
        let payload = format!(
            "{{\"protocol_version\":11,\"session_id\":\"coordinator-session\",\"runner_nonce\":\"{}\",\"sequence\":1,\"request_id\":\"control-1\",\"effect\":null,\"request\":{{\"kind\":\"shutdown\"}}}}",
            digest(90).as_str()
        );
        let mut expected = u32::try_from(payload.len())
            .expect("bounded historical payload")
            .to_be_bytes()
            .to_vec();
        expected.extend_from_slice(payload.as_bytes());
        let encoded = encode_request_frame(&request).expect("encode frozen v11 request");
        assert_eq!(encoded, expected);
        assert_eq!(
            decode_request_frame(&expected).expect("decode frozen v11 fixture"),
            request
        );
    }

    #[test]
    fn service_descriptor_authenticates_mixed_v11_v12_sensitive_output_law() {
        let descriptor = str::from_utf8(PROTOCOL_DESCRIPTOR).expect("ASCII protocol descriptor");
        for required in [
            "routing=exact-leading-protocol-version-prefix",
            "v11=initialization,controls,non-command,historical-codec-exact",
            "v11-run-command=failed-before-effect",
            "v12=run-command-only",
            "v12-command-effect-authority=full-envelope-policy-and-transport-commitment",
            "v12-detector-policy=gb.sensitive-output-detector.v1",
            "v12-clean-scan-receipt=runner-v2",
            "v12-core-dump-profile=zero-limit-pre-launch",
            "v12-sensitive-staging=neutralized-before-abandonment",
            "v12-rejection=no-output-fields",
        ] {
            assert!(
                descriptor.contains(required),
                "descriptor omitted {required}"
            );
        }
        assert_eq!(
            runner_protocol_digest(),
            Digest::sha256(PROTOCOL_DESCRIPTOR)
        );
        assert_ne!(
            runner_protocol_digest(),
            Digest::sha256(b"grok-build.runner-wire.v11\0")
        );
    }

    #[test]
    fn v12_reconciliation_response_round_trips_with_exact_capture_identity() {
        let request = coordinator_command(1);
        let acquired = match request.request.command_request() {
            RunnerRequest::WorkerRunCommand { output_capture, .. } => output_capture.acquired(),
            _ => unreachable!(),
        };
        let reference = WireReconciliationReference::CommandOutputCapture {
            capture_id: acquired.capture_id.clone(),
            acquired_anchor_digest: acquired.acquired_anchor_digest.clone(),
            last_known_store_head: acquired.store_head.clone(),
            expected_output_artifacts: None,
        };
        let expected_reference = reference.clone();
        let job: CommandJob =
            Box::new(move |_| CommandJobOutcome::ReconciliationRequired { reference });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        write_request(&mut client, &request);
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );

        let response = read_response_v12(&mut client);
        response
            .validate_correlation(&request)
            .expect("reconciliation response keeps exact v12 correlation");
        assert!(matches!(
            response.response,
            RunnerResponseV12::CommandFailed {
                class: WireFailureClass::ReconciliationRequired,
                code: WireCommandFailureCodeV12::ReconciliationRequired,
                reconciliation: Some(reference),
                ..
            } if reference == expected_reference
        ));
        assert!(matches!(
            read_response(&mut client).response,
            RunnerResponse::ShutdownPrepared { .. }
        ));
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    fn incremental_decoder_preserves_partial_prefix_and_payload() {
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), DisabledCommandJobFactory);
        let request = coordinator_control(1, RunnerRequest::Shutdown);
        let frame = encode_request_frame(&request).expect("shutdown frame");

        client.write_all(&frame[..2]).expect("partial prefix");
        assert_no_response(&mut client);
        client
            .write_all(&frame[2..frame.len() - 1])
            .expect("prefix and partial payload");
        assert_no_response(&mut client);
        client
            .write_all(&frame[frame.len() - 1..])
            .expect("final payload byte");

        let response = read_response(&mut client);
        assert_eq!(response.sequence, 1);
        let RunnerResponse::ShutdownPrepared { acknowledgement } = response.response else {
            panic!("shutdown acknowledgement expected")
        };
        assert_eq!(acknowledgement.accepted_request_count, 2);
        assert_eq!(acknowledgement.command_effects_admitted, 0);
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    fn idle_eof_is_fatal_without_a_detached_reader() {
        let (client, server) = spawn_coordinator(coordinator_service(), DisabledCommandJobFactory);
        drop(client);
        assert!(matches!(
            server.join().expect("coordinator join"),
            Err(RunnerServiceError::UnexpectedEndOfStream)
        ));
    }

    #[test]
    fn live_cancel_and_shutdown_emit_command_before_control_ack() {
        for control in [RunnerRequest::WorkerCancel, RunnerRequest::Shutdown] {
            let command_request = coordinator_command(1);
            let terminal_request = command_request.clone();
            let exited = Arc::new(AtomicBool::new(false));
            let worker_exited = Arc::clone(&exited);
            let job: CommandJob = Box::new(move |cancellation| {
                let _guard = JobExitGuard(worker_exited);
                for _ in 0..1_000 {
                    if cancellation.is_cancelled() {
                        return CommandJobOutcome::Terminal(Box::new(
                            CommandTerminalOutcome::PreparedV12(prepared_after_known_response(
                                &terminal_request,
                            )),
                        ));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                CommandJobOutcome::UnprovenAfterLaunch
            });
            let (mut client, server) =
                spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
            write_request(&mut client, &command_request);
            let control_request = coordinator_control(2, control.clone());
            write_request(&mut client, &control_request);

            let command_response = read_response_v12(&mut client);
            let control_response = read_response(&mut client);
            assert_eq!(command_response.sequence, 1);
            assert_eq!(command_response.request_id, "command-1");
            assert!(matches!(
                command_response.response,
                RunnerResponseV12::CommandFailed {
                    class: WireFailureClass::AfterKnownEffect,
                    ..
                }
            ));
            assert_eq!(control_response.sequence, 2);
            let acknowledgement = match control_response.response {
                RunnerResponse::CancellationPrepared { acknowledgement }
                    if matches!(control, RunnerRequest::WorkerCancel) =>
                {
                    acknowledgement
                }
                RunnerResponse::ShutdownPrepared { acknowledgement }
                    if matches!(control, RunnerRequest::Shutdown) =>
                {
                    acknowledgement
                }
                _ => panic!("role-exact control acknowledgement expected"),
            };
            assert_eq!(acknowledgement.accepted_request_count, 3);
            assert_eq!(acknowledgement.command_effects_admitted, 1);
            assert!(server.join().expect("coordinator join").is_ok());
            assert!(exited.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn write_eof_after_control_waits_for_delayed_cleanup_without_repolling_hup() {
        let command_request = coordinator_command(1);
        let terminal_request = command_request.clone();
        let job: CommandJob = Box::new(move |cancellation| {
            while !cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            thread::sleep(Duration::from_millis(30));
            CommandJobOutcome::Terminal(Box::new(CommandTerminalOutcome::PreparedV12(
                prepared_after_known_response(&terminal_request),
            )))
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        write_request(&mut client, &command_request);
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );
        client
            .shutdown(Shutdown::Write)
            .expect("half-close request stream");

        assert!(matches!(
            read_response_v12(&mut client).response,
            RunnerResponseV12::CommandFailed {
                class: WireFailureClass::AfterKnownEffect,
                ..
            }
        ));
        assert!(matches!(
            read_response(&mut client).response,
            RunnerResponse::ShutdownPrepared { .. }
        ));
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    fn completion_before_cancel_race_truthfully_preserves_exit() {
        let command_request = coordinator_command(1);
        let terminal_request = command_request.clone();
        let job: CommandJob = Box::new(move |_cancellation| {
            CommandJobOutcome::Terminal(Box::new(CommandTerminalOutcome::PreparedV12(
                prepared_after_known_response(&terminal_request),
            )))
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        let mut requests =
            crate::wire::encode_request_frame_v12(&command_request).expect("v12 command frame");
        requests.extend_from_slice(
            &encode_request_frame(&coordinator_control(2, RunnerRequest::WorkerCancel))
                .expect("cancel frame"),
        );
        client.write_all(&requests).expect("coalesced race frames");

        let command_response = read_response_v12(&mut client);
        let control_response = read_response(&mut client);
        assert!(matches!(
            command_response.response,
            RunnerResponseV12::CommandFailed {
                class: WireFailureClass::AfterKnownEffect,
                ..
            }
        ));
        assert!(matches!(
            control_response.response,
            RunnerResponse::CancellationPrepared { .. }
        ));
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    fn second_command_is_fatal_and_worker_is_joined_without_a_queue() {
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = Arc::clone(&exited);
        let job: CommandJob = Box::new(move |cancellation| {
            let _guard = JobExitGuard(worker_exited);
            while !cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            CommandJobOutcome::RefusedBeforeLaunch {
                code: WireCommandFailureCodeV12::InternalFailure,
            }
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        write_request(&mut client, &coordinator_command(1));
        write_request(&mut client, &coordinator_command(2));

        assert!(matches!(
            server.join().expect("coordinator join"),
            Err(RunnerServiceError::CommandJobAlreadyActive)
        ));
        assert!(exited.load(Ordering::SeqCst));
        assert_no_response(&mut client);
    }

    #[test]
    fn simultaneous_terminal_and_queued_command_is_fatal_without_a_response() {
        let command_request = coordinator_command(1);
        let terminal_request = command_request.clone();
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = Arc::clone(&exited);
        let job: CommandJob = Box::new(move |_cancellation| {
            let _guard = JobExitGuard(worker_exited);
            CommandJobOutcome::Terminal(Box::new(CommandTerminalOutcome::PreparedV12(
                prepared_after_known_response(&terminal_request),
            )))
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        let mut requests = crate::wire::encode_request_frame_v12(&command_request)
            .expect("first v12 command frame");
        requests.extend_from_slice(
            &crate::wire::encode_request_frame_v12(&coordinator_command(2))
                .expect("queued v12 command frame"),
        );
        client
            .write_all(&requests)
            .expect("simultaneous terminal race frames");

        assert!(matches!(
            server.join().expect("coordinator join"),
            Err(RunnerServiceError::CommandJobAlreadyActive)
        ));
        assert!(exited.load(Ordering::SeqCst));
        assert_no_response(&mut client);
    }

    #[test]
    fn fragmented_queued_command_holds_terminal_then_fails_without_a_response() {
        let command_request = coordinator_command(1);
        let terminal_request = command_request.clone();
        let job: CommandJob = Box::new(move |_cancellation| {
            CommandJobOutcome::Terminal(Box::new(CommandTerminalOutcome::PreparedV12(
                prepared_after_known_response(&terminal_request),
            )))
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        let first = crate::wire::encode_request_frame_v12(&command_request)
            .expect("first v12 command frame");
        let second = crate::wire::encode_request_frame_v12(&coordinator_command(2))
            .expect("second v12 command frame");
        let mut initial = first;
        initial.extend_from_slice(&second[..2]);
        client
            .write_all(&initial)
            .expect("command followed by partial command prefix");
        thread::sleep(Duration::from_millis(20));
        assert_no_response(&mut client);
        client
            .write_all(&second[2..])
            .expect("finish forbidden queued command");

        assert!(matches!(
            server.join().expect("coordinator join"),
            Err(RunnerServiceError::CommandJobAlreadyActive)
        ));
        assert_no_response(&mut client);
    }

    #[test]
    fn fragmented_valid_control_holds_terminal_until_classified() {
        let command_request = coordinator_command(1);
        let terminal_request = command_request.clone();
        let job: CommandJob = Box::new(move |_cancellation| {
            CommandJobOutcome::Terminal(Box::new(CommandTerminalOutcome::PreparedV12(
                prepared_after_known_response(&terminal_request),
            )))
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        let command =
            crate::wire::encode_request_frame_v12(&command_request).expect("v12 command frame");
        let control = encode_request_frame(&coordinator_control(2, RunnerRequest::Shutdown))
            .expect("shutdown frame");
        let mut initial = command;
        initial.extend_from_slice(&control[..2]);
        client
            .write_all(&initial)
            .expect("command followed by partial control prefix");
        thread::sleep(Duration::from_millis(20));
        assert_no_response(&mut client);
        client
            .write_all(&control[2..])
            .expect("finish valid control frame");

        let command_response = read_response_v12(&mut client);
        let control_response = read_response(&mut client);
        assert!(matches!(
            command_response.response,
            RunnerResponseV12::CommandFailed {
                class: WireFailureClass::AfterKnownEffect,
                ..
            }
        ));
        assert!(matches!(
            control_response.response,
            RunnerResponse::ShutdownPrepared { .. }
        ));
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    fn frame_behind_pending_control_is_fatal_before_any_response() {
        let command_request = coordinator_command(1);
        let terminal_request = command_request.clone();
        let job: CommandJob = Box::new(move |cancellation| {
            while !cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            CommandJobOutcome::Terminal(Box::new(CommandTerminalOutcome::PreparedV12(
                prepared_after_known_response(&terminal_request),
            )))
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        let mut requests =
            crate::wire::encode_request_frame_v12(&command_request).expect("v12 command frame");
        requests.extend_from_slice(
            &encode_request_frame(&coordinator_control(2, RunnerRequest::Shutdown))
                .expect("shutdown frame"),
        );
        requests.extend_from_slice(
            &crate::wire::encode_request_frame_v12(&coordinator_command(3))
                .expect("trailing v12 command frame"),
        );
        client
            .write_all(&requests)
            .expect("command, control, and forbidden trailing frame");

        assert!(matches!(
            server.join().expect("coordinator join"),
            Err(RunnerServiceError::CommandJobAlreadyActive)
        ));
        assert_no_response(&mut client);
    }

    #[test]
    fn partial_frame_behind_pending_control_is_also_fatal() {
        let job: CommandJob = Box::new(move |cancellation| {
            while !cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            CommandJobOutcome::RefusedBeforeLaunch {
                code: WireCommandFailureCodeV12::InternalFailure,
            }
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        let command = crate::wire::encode_request_frame_v12(&coordinator_command(1))
            .expect("v12 command frame");
        let shutdown = encode_request_frame(&coordinator_control(2, RunnerRequest::Shutdown))
            .expect("shutdown frame");
        let trailing = crate::wire::encode_request_frame_v12(&coordinator_command(3))
            .expect("trailing v12 frame");
        let mut requests = command;
        requests.extend_from_slice(&shutdown);
        requests.extend_from_slice(&trailing[..2]);
        client
            .write_all(&requests)
            .expect("control followed by partial frame");

        assert!(matches!(
            server.join().expect("coordinator join"),
            Err(RunnerServiceError::CommandJobAlreadyActive)
        ));
        assert_no_response(&mut client);
    }

    #[test]
    fn wrong_sequence_control_cancels_and_joins_before_failing() {
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = Arc::clone(&exited);
        let job: CommandJob = Box::new(move |cancellation| {
            let _guard = JobExitGuard(worker_exited);
            while !cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            CommandJobOutcome::UnprovenAfterLaunch
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        write_request(&mut client, &coordinator_command(1));
        write_request(
            &mut client,
            &coordinator_control(3, RunnerRequest::Shutdown),
        );

        assert!(matches!(
            server.join().expect("coordinator join"),
            Err(RunnerServiceError::SequenceMismatch)
        ));
        assert!(exited.load(Ordering::SeqCst));
        assert_no_response(&mut client);
    }

    #[test]
    fn refused_before_launch_is_the_only_nonterminal_job_failure_response() {
        let job: CommandJob =
            Box::new(
                move |_cancellation| CommandJobOutcome::RefusedBeforeLaunch {
                    code: WireCommandFailureCodeV12::ContainmentUnavailable,
                },
            );
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        write_request(&mut client, &coordinator_command(1));
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );

        let refusal = read_response_v12(&mut client);
        let shutdown = read_response(&mut client);
        assert!(matches!(
            refusal.response,
            RunnerResponseV12::CommandFailed {
                class: WireFailureClass::BeforeEffect,
                code: WireCommandFailureCodeV12::ContainmentUnavailable,
                ..
            }
        ));
        let RunnerResponse::ShutdownPrepared { acknowledgement } = shutdown.response else {
            panic!("shutdown acknowledgement expected")
        };
        assert_eq!(acknowledgement.command_effects_admitted, 1);
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    fn v12_before_effect_failure_is_typed_and_message_free() {
        let job: CommandJob =
            Box::new(
                move |_cancellation| CommandJobOutcome::RefusedBeforeLaunch {
                    code: WireCommandFailureCodeV12::InvalidAuthority,
                },
            );
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        write_request(&mut client, &coordinator_command(1));
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );

        let refusal = read_response_v12(&mut client);
        let RunnerResponseV12::CommandFailed { class, code, .. } = refusal.response else {
            panic!("typed refusal expected")
        };
        assert_eq!(class, WireFailureClass::BeforeEffect);
        assert_eq!(code, WireCommandFailureCodeV12::InvalidAuthority);
        let encoded =
            crate::wire::encode_response_frame_v12(&refusal).expect("re-encode exact v12 refusal");
        assert!(!String::from_utf8_lossy(&encoded[4..]).contains("message"));
        assert!(matches!(
            read_response(&mut client).response,
            RunnerResponse::ShutdownPrepared { .. }
        ));
        assert!(server.join().expect("coordinator join").is_ok());
    }

    #[test]
    fn unproven_after_launch_emits_no_command_response_or_control_ack() {
        let job: CommandJob = Box::new(move |cancellation| {
            while !cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            CommandJobOutcome::UnprovenAfterLaunch
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        write_request(&mut client, &coordinator_command(1));
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );

        assert!(matches!(
            server.join().expect("coordinator join"),
            Err(RunnerServiceError::CommandJobUnprovenAfterLaunch)
        ));
        assert_no_response(&mut client);
    }

    #[test]
    fn panicked_job_is_caught_joined_and_emits_nothing() {
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = Arc::clone(&exited);
        let job: CommandJob = Box::new(move |cancellation| {
            let _guard = JobExitGuard(worker_exited);
            while !cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(1));
            }
            panic!("injected coordinator job panic")
        });
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), OneCommandJobFactory::new(job));
        write_request(&mut client, &coordinator_command(1));
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );

        assert!(matches!(
            server.join().expect("coordinator join"),
            Err(RunnerServiceError::CommandJobPanicked)
        ));
        assert!(exited.load(Ordering::SeqCst));
        assert_no_response(&mut client);
    }

    #[test]
    fn unavailable_command_path_does_not_increment_admission_count() {
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), DisabledCommandJobFactory);
        write_request(&mut client, &coordinator_command(1));
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );

        let failed = read_response_v12(&mut client);
        let shutdown = read_response(&mut client);
        assert!(matches!(
            failed.response,
            RunnerResponseV12::CommandFailed {
                class: WireFailureClass::BeforeEffect,
                code: WireCommandFailureCodeV12::ContainmentUnavailable,
                ..
            }
        ));
        let RunnerResponse::ShutdownPrepared { acknowledgement } = shutdown.response else {
            panic!("shutdown acknowledgement expected")
        };
        assert_eq!(acknowledgement.accepted_request_count, 3);
        assert_eq!(acknowledgement.command_effects_admitted, 0);
        assert!(server.join().expect("coordinator join").is_ok());
    }

    fn bundle() -> StageBundleReference {
        StageBundleReference {
            format_version: 1,
            bundle_digest: digest(1),
            change_set_id: "changeset-1".into(),
            base_snapshot: digest(2),
            result_snapshot: digest(3),
        }
    }

    #[test]
    fn verified_noop_prepare_is_stage_prepared_without_publication() {
        let (_top, grant, mut shadow, bundle_store) = unchanged_shadow_fixture();
        let staged = shadow
            .stage_changes_or_verified_noop(&grant, "prepare-noop", 2)
            .unwrap();
        let expected_bundle = CapabilityStageBundleStore::preview(&staged).unwrap();

        let response =
            RunnerResponse::stage_prepared(staged.change_set().clone(), expected_bundle.clone())
                .unwrap();
        assert!(matches!(
            response,
            RunnerResponse::StagePrepared {
                change_set,
                expected_bundle: response_bundle,
            } if change_set.as_ref() == staged.change_set()
                && response_bundle == expected_bundle
        ));
        assert!(bundle_store.reconcile(&expected_bundle).is_err());
    }

    #[test]
    fn claimed_verified_noop_stage_persists_the_exact_preview() {
        let (_top, grant, mut shadow, bundle_store) = unchanged_shadow_fixture();
        let staged = shadow
            .stage_changes_or_verified_noop(&grant, "persist-noop", 2)
            .unwrap();
        let expected_bundle = CapabilityStageBundleStore::preview(&staged).unwrap();
        assert!(bundle_store.reconcile(&expected_bundle).is_err());

        let persisted = bundle_store.persist(&staged).unwrap();

        assert_eq!(persisted, expected_bundle);
        assert_eq!(
            bundle_store.reconcile(&expected_bundle).unwrap(),
            expected_bundle
        );
        assert_eq!(bundle_store.load(&expected_bundle).unwrap(), staged);
    }

    fn assert_reconciliation(response: RunnerResponse) -> WireReconciliationReference {
        let RunnerResponse::Failed {
            class: WireFailureClass::ReconciliationRequired,
            reconciliation: Some(reference),
            ..
        } = response
        else {
            panic!("expected reconciliation-required failure")
        };
        reference
    }

    fn assert_live_capture_cut_is_after_known_effect(cut: &'static str) {
        let response = live_state_capture_failure(CapabilityWorkspaceError::Root(cut.into()));
        assert!(matches!(
            response,
            RunnerResponse::Failed {
                code,
                class: WireFailureClass::AfterKnownEffect,
                reconciliation: None,
                message,
            } if code == "live_workspace_capture_incomplete" && message.contains(cut)
        ));
    }

    #[test]
    fn live_capture_authority_preflight_precedes_start_sample_and_effect_boundary() {
        let response = workspace_failure(CapabilityWorkspaceError::Authority(
            "pre-scan grant mismatch".into(),
        ));
        assert!(matches!(
            response,
            RunnerResponse::Failed {
                code,
                class: WireFailureClass::BeforeEffect,
                reconciliation: None,
                message,
            } if code == "workspace_operation_rejected"
                && message.contains("pre-scan grant mismatch")
        ));
    }

    #[test]
    fn live_capture_first_descriptor_scan_failure_is_after_known_effect() {
        assert_live_capture_cut_is_after_known_effect("first descriptor scan failed");
    }

    #[test]
    fn live_capture_stability_interval_failure_is_after_known_effect() {
        assert_live_capture_cut_is_after_known_effect("workspace changed between scans");
    }

    #[test]
    fn live_capture_second_descriptor_scan_failure_is_after_known_effect() {
        assert_live_capture_cut_is_after_known_effect("second descriptor scan failed");
    }

    #[test]
    fn live_capture_manifest_encoding_failure_is_after_known_effect() {
        assert_live_capture_cut_is_after_known_effect("manifest encoding failed");
    }

    #[test]
    fn crash_and_ambiguous_application_errors_never_claim_before_effect() {
        let bundle = bundle();
        let injected = assert_reconciliation(apply_failure(
            CapabilityApplyError::InjectedCrash {
                affected_operations: 1,
            },
            Some(&bundle),
        ));
        assert_eq!(
            injected,
            WireReconciliationReference::Application {
                bundle: bundle.clone(),
            }
        );

        let ambiguous = assert_reconciliation(apply_failure(
            CapabilityApplyError::ReconciliationRequired {
                change_set_id: bundle.change_set_id.clone(),
                path: Some(PathBuf::from("src/lib.rs")),
                operation: "fixture mutation",
                reason: "fixture proof failed".into(),
            },
            Some(&bundle),
        ));
        assert_eq!(
            ambiguous,
            WireReconciliationReference::Application {
                bundle: bundle.clone(),
            }
        );

        let phase_sync_ambiguity = apply_failure(
            CapabilityApplyError::ReconciliationRequired {
                change_set_id: bundle.change_set_id.clone(),
                path: None,
                operation: "durably transition evidence-bearing rollback to rolling_back",
                reason: "directory sync failed after atomic phase rename".into(),
            },
            Some(&bundle),
        );
        let RunnerResponse::Failed {
            class,
            reconciliation,
            message,
            ..
        } = phase_sync_ambiguity
        else {
            panic!("phase-sync ambiguity must be a typed failure")
        };
        assert_eq!(class, WireFailureClass::ReconciliationRequired);
        assert_eq!(
            reconciliation,
            Some(WireReconciliationReference::Application {
                bundle: bundle.clone(),
            })
        );
        assert!(message.contains("rolling_back"));

        for error in [
            CapabilityApplyError::InjectedPreparationCrash {
                checkpoint: "fixture",
                completed_blobs: 1,
            },
            CapabilityApplyError::PreparationCleanupRequired {
                preparation_id: "preparation-1".into(),
                reason: "fixture cleanup failed".into(),
            },
        ] {
            assert_eq!(
                assert_reconciliation(apply_failure(error, Some(&bundle))),
                WireReconciliationReference::ApplicationRecovery
            );
        }

        assert_eq!(
            assert_reconciliation(post_effect_evidence_failure(
                &bundle,
                "fixture evidence failure",
            )),
            WireReconciliationReference::Application { bundle }
        );
    }

    /// Builds the exact refusal the live service emits for one physically
    /// reserved capture, so the attached evidence is produced by the production
    /// path rather than a fixture.
    fn refusal_for_reserved_capture(
        private: &StageTestDirectory,
    ) -> (
        RunnerResponseV12,
        grok_build_core::CommandOutputCaptureAcquiredV1,
        String,
    ) {
        let store = CapabilityCommandOutputStore::open(&private.0).expect("open capture store");
        let private_state_digest =
            inspect_private_state_digest(&private.0).expect("inspect private-state identity");
        let mut request = coordinator_command(1);
        let fixture_acquired = match request.request.command_request() {
            RunnerRequest::WorkerRunCommand { output_capture, .. } => {
                output_capture.acquired().clone()
            }
            _ => panic!("coordinator command must carry capture authority"),
        };
        let intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(b"service-containment-refusal-capture/v1")
                .as_str()
                .to_owned(),
            fixture_acquired.source,
            private_state_digest.clone(),
            fixture_acquired.max_aggregate_output_bytes,
            1,
        )
        .expect("construct refusal test capture intent");
        let detector_policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(
                &intent,
                &fixture_acquired.dispatch_claim_id,
                2,
                &detector_policy,
            )
            .expect("reserve exact refusal test capture")
            .into_acquired_anchor_for_handoff()
            .expect("close reservation descriptors before runner handoff");
        let anchor = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
            .expect("construct exact wire capture anchor");
        let crate::wire::RunnerRequestV12::RunCommand {
            request: command_request,
            ..
        } = &mut request.request;
        let RunnerRequest::WorkerRunCommand { output_capture, .. } = command_request else {
            panic!("coordinator command changed request class")
        };
        *output_capture = anchor;
        request
            .bind_transport_commitment_digest()
            .expect("rebind request to the real acquired capture");

        let mut service = coordinator_service();
        service.command_capture_private_state_digest = Some(private_state_digest);
        service.command_capture_store = Some(store);
        let effect_id = request.effect.effect_id.clone();
        let (mut client, server) = spawn_coordinator(service, DisabledCommandJobFactory);
        write_request(&mut client, &request);
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );
        let refused = read_response_v12(&mut client);
        let _shutdown = read_response(&mut client);
        server.join().expect("coordinator join").expect("clean run");
        (refused.response, acquired, effect_id)
    }

    /// The production containment refusal now carries what it can prove: the
    /// exact untouched capture head it read back, and canonical no-domain proof
    /// bytes minted from kernel reads. The failure class and code are
    /// unchanged, so nothing about the refusal's meaning moves -- only what
    /// backs it.
    ///
    /// The assertion is a biconditional rather than an unconditional presence
    /// check, because this test binary also exercises process launch and a
    /// process that has created a child cannot answer the absence question at
    /// all. Both halves are asserted: evidence is attached exactly when the
    /// live read is available, and when it is attached it validates completely.
    /// `tests/command_domain_absence_live.rs` proves the positive half
    /// unconditionally in a binary that forks nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn containment_refusal_carries_evidence_backed_no_domain_proof() {
        let private = StageTestDirectory::new("containment-refusal-evidence");
        let (response, acquired, effect_id) = refusal_for_reserved_capture(&private);
        let RunnerResponseV12::CommandFailed {
            class,
            code,
            reconciliation,
            containment_refusal,
            ..
        } = response
        else {
            panic!("typed containment refusal expected")
        };
        assert_eq!(class, WireFailureClass::BeforeEffect);
        assert_eq!(code, WireCommandFailureCodeV12::ContainmentUnavailable);
        assert_eq!(reconciliation, None);
        let live_read_available = crate::command_domain_absence::observe_linux_command_domain_absence(
            "coordinator-session",
            &effect_id,
            acquired.source.request_digest.as_str(),
        )
        .is_ok();
        assert_eq!(
            containment_refusal.is_some(),
            live_read_available,
            "the refusal must carry evidence exactly when this process can still read it"
        );
        let Some(refusal) = containment_refusal else {
            return;
        };
        assert_eq!(refusal.capture_id, acquired.capture_id);
        assert_eq!(refusal.untouched_store_head, acquired.store_head);
        assert_eq!(
            refusal.command_domain_backend,
            crate::cleanup_proof::CommandDomainCleanupBackend::LinuxCgroupV2
        );

        let binding = crate::cleanup_proof::CommandDomainCleanupBinding::try_new(
            "coordinator-session",
            effect_id,
            acquired.source.request_digest.clone(),
        )
        .expect("exact refusal binding");
        let proof = refusal
            .readback(&binding)
            .expect("the desktop must be able to reopen the attached proof");
        assert_eq!(
            proof.disposition(),
            grok_build_core::CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
        );
        assert_eq!(proof.surviving_processes(), 0);
        assert_eq!(proof.binding(), &binding);

        // A proof bound to one effect cannot be presented for another.
        let crossed = crate::cleanup_proof::CommandDomainCleanupBinding::try_new(
            "coordinator-session",
            "some-other-effect",
            acquired.source.request_digest,
        )
        .expect("crossed refusal binding");
        assert!(refusal.readback(&crossed).is_err());
    }

    /// The evidence is optional and fail-closed. A host with no cgroup-v2
    /// hierarchy to read produces no observation, and the refusal keeps exactly
    /// its historical evidence-free shape rather than a weaker record.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn containment_refusal_without_a_readable_domain_namespace_carries_no_evidence() {
        let private = StageTestDirectory::new("containment-refusal-evidence");
        let (response, _acquired, _effect_id) = refusal_for_reserved_capture(&private);
        assert!(matches!(
            response,
            RunnerResponseV12::CommandFailed {
                class: WireFailureClass::BeforeEffect,
                code: WireCommandFailureCodeV12::ContainmentUnavailable,
                reconciliation: None,
                containment_refusal: None,
                ..
            }
        ));
    }

    /// A capture with a launch record may contain output. Refusal must not
    /// misreport it as an untouched reservation or bypass output classification.
    #[test]
    fn a_launch_bearing_capture_makes_the_refusal_attach_nothing() {
        let private = StageTestDirectory::new("containment-refusal-launched");
        let store = CapabilityCommandOutputStore::open(&private.0).expect("open capture store");
        let private_state_digest =
            inspect_private_state_digest(&private.0).expect("inspect private-state identity");
        let mut request = coordinator_command(1);
        let fixture_acquired = match request.request.command_request() {
            RunnerRequest::WorkerRunCommand { output_capture, .. } => {
                output_capture.acquired().clone()
            }
            _ => panic!("coordinator command must carry capture authority"),
        };
        let intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(b"service-containment-refusal-launched/v1")
                .as_str()
                .to_owned(),
            fixture_acquired.source,
            private_state_digest.clone(),
            fixture_acquired.max_aggregate_output_bytes,
            1,
        )
        .expect("construct launched refusal capture intent");
        let detector_policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(
                &intent,
                &fixture_acquired.dispatch_claim_id,
                2,
                &detector_policy,
            )
            .expect("reserve launched refusal capture")
            .into_acquired_anchor_for_handoff()
            .expect("close reservation descriptors before handoff");
        let anchor = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
            .expect("construct exact wire capture anchor");
        let crate::wire::RunnerRequestV12::RunCommand {
            request: command_request,
            ..
        } = &mut request.request;
        let RunnerRequest::WorkerRunCommand { output_capture, .. } = command_request else {
            panic!("coordinator command changed request class")
        };
        *output_capture = anchor;
        request
            .bind_transport_commitment_digest()
            .expect("rebind request to the launched capture");

        // Exactly one input differs from the evidence-bearing case: this
        // capture became launch-bearing and accumulated output bytes.
        let capture = store
            .reopen_anchored_capture_v2(&acquired, &detector_policy)
            .expect("attach exact output writers");
        let (mut stdout, stderr, mut publisher) = capture.split();
        publisher
            .record_launch_intended_v2(
                "runner-contained-capture-launch/v1",
                br#"{"service_refusal_launch_test":true}"#.to_vec(),
                &runner_core_dump_profile_fixture(),
            )
            .expect("append LaunchIntended");
        stdout
            .append(b"output that a refusal must never describe\n")
            .expect("append fixture stdout");
        drop(stdout);
        drop(stderr);
        drop(publisher);

        let mut service = coordinator_service();
        service.command_capture_private_state_digest = Some(private_state_digest);
        service.command_capture_store = Some(store);
        let (mut client, server) = spawn_coordinator(service, DisabledCommandJobFactory);
        write_request(&mut client, &request);
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );
        let refused = read_response_v12(&mut client);
        let _shutdown = read_response(&mut client);
        server.join().expect("coordinator join").expect("clean run");
        assert!(matches!(
            refused.response,
            RunnerResponseV12::CommandFailed {
                class: WireFailureClass::BeforeEffect,
                code: WireCommandFailureCodeV12::ContainmentUnavailable,
                containment_refusal: None,
                ..
            }
        ));
    }

    /// Attach refusal evidence only for the exact reservation read back as
    /// `Acquired` with no launch record. A capture that may contain output cannot
    /// be described as untouched.
    #[test]
    fn a_refusal_attaches_no_evidence_for_a_capture_it_cannot_read_back_untouched() {
        let (mut client, server) =
            spawn_coordinator(coordinator_service(), DisabledCommandJobFactory);
        write_request(&mut client, &coordinator_command(1));
        write_request(
            &mut client,
            &coordinator_control(2, RunnerRequest::Shutdown),
        );
        let refused = read_response_v12(&mut client);
        let _shutdown = read_response(&mut client);
        server.join().expect("coordinator join").expect("clean run");
        assert!(matches!(
            refused.response,
            RunnerResponseV12::CommandFailed {
                containment_refusal: None,
                ..
            }
        ));
    }
