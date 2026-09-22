    use super::contained_boundary::{
        BackendCanaryStatus, BackendControl, BackendIdentity, BackendPreflightReport,
        BackendTermination, ContainedCommandBackend, ContainedDescendantDomain,
        ContainedExecutionOutcome, DomainObservation, DomainTerminationRequest,
        DurablyAnchoredCapture, PreparedContainedCommand, ValidatedBackendPermit,
    };
    use super::*;
    use crate::wire::{
        RUNNER_WIRE_PROTOCOL_VERSION, RunnerRequestEnvelope, WireCommandOutputCaptureAnchorV1,
        WireCommandSpec, WireEffectContext, command_output_capture_maximum,
        test_command_output_capture_anchor,
    };
    use grok_build_core::{
        CONTRACT_VERSION, CommandOutputCaptureIntentV1, CommandOutputCaptureReconciliationClaimV1,
        EnvironmentVariable, ExecutionPolicyCompiler, ExecutionPolicyRequest, WorkerLease,
        WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_PRIVATE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-command-{label}-{}-{sequence}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(&path).expect("create test directory");
            Self(fs::canonicalize(path).expect("canonical test directory"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn authority(
        workspace: &Path,
        network: ExecutionNetwork,
        max_output_bytes: u64,
    ) -> (IssuedWorkspaceGrant, CompiledExecutionPolicy) {
        authority_with_limits(
            workspace,
            network,
            ResourceLimits {
                wall_time_ms: 2_000,
                max_output_bytes,
                max_processes: 1,
                max_memory_bytes: None,
            },
        )
    }

    fn authority_with_limits(
        workspace: &Path,
        network: ExecutionNetwork,
        resource_limits: ResourceLimits,
    ) -> (IssuedWorkspaceGrant, CompiledExecutionPolicy) {
        let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "grant-command-test".into(),
            workspace_root: workspace.to_path_buf(),
            permissions: WorkspacePermissions::trusted(),
            network: if network == ExecutionNetwork::None {
                WorkspaceNetworkPolicy::Denied
            } else {
                WorkspaceNetworkPolicy::Allowed
            },
            policy_version: 1,
        })
        .expect("issue grant");
        let policy = ExecutionPolicyCompiler::compile(
            &grant,
            ExecutionPolicyRequest {
                policy_id: "policy-command-test".into(),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                environment: vec![EnvironmentVariable {
                    name: "PATH".into(),
                    value: "/usr/bin:/bin".into(),
                }],
                network,
                mutation_mode: MutationMode::ShadowWorkspace,
                resource_limits,
                approval_id: None,
            },
        )
        .expect("compile policy");
        (grant, policy)
    }

    #[derive(Clone, Default)]
    struct FakeBackendState {
        launch_count: Arc<AtomicU64>,
        poll_count: Arc<AtomicU64>,
        cleanup_proof_consumptions: Arc<AtomicU64>,
        cleanup_proof_consumed_at_poll: Arc<AtomicU64>,
        terminations: Arc<Mutex<Vec<DomainTerminationRequest>>>,
    }

    struct FakeContainedBackend {
        identity: BackendIdentity,
        controls: BTreeSet<BackendControl>,
        descriptors: Vec<i32>,
        canary_status: BackendCanaryStatus,
        reported_identity: Option<BackendIdentity>,
        cleanup_proof: Option<ValidatedCommandDomainCleanupProof>,
        observations: VecDeque<DomainObservation>,
        state: FakeBackendState,
        cancel_on_launch: Option<CancellationToken>,
        preflight_error: Option<&'static str>,
        launch_error: Option<&'static str>,
        poll_error: Option<&'static str>,
        poll_error_after_observations: u64,
        terminate_error: Option<&'static str>,
        launch_hook: Option<Box<dyn FnOnce() + Send>>,
    }

    impl FakeContainedBackend {
        fn ready_for(
            command: &PreparedContainedCommand,
            observations: impl IntoIterator<Item = DomainObservation>,
        ) -> (Self, FakeBackendState) {
            let state = FakeBackendState::default();
            let cleanup_binding = test_command_cleanup_binding(command);
            let backend = Self {
                identity: BackendIdentity::new(
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    "fake-contained-v1",
                    hash_bytes(b"fake backend"),
                ),
                controls: contained_boundary::required_controls(ResourceLimits {
                    wall_time_ms: 1,
                    max_output_bytes: 1,
                    max_processes: 1,
                    max_memory_bytes: None,
                }),
                descriptors: vec![0, 1, 2],
                canary_status: BackendCanaryStatus::Passed(hash_bytes(b"active canaries passed")),
                reported_identity: None,
                cleanup_proof: Some(
                    crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(
                        &cleanup_binding,
                    ),
                ),
                observations: observations.into_iter().collect(),
                state: state.clone(),
                cancel_on_launch: None,
                preflight_error: None,
                launch_error: None,
                poll_error: None,
                poll_error_after_observations: 0,
                terminate_error: None,
                launch_hook: None,
            };
            (backend, state)
        }
    }

    struct FakeContainedDomain {
        observations: VecDeque<DomainObservation>,
        state: FakeBackendState,
        last_leader: Option<BackendTermination>,
        cleanup_proof: Option<ValidatedCommandDomainCleanupProof>,
        poll_error: Option<&'static str>,
        poll_error_after_observations: u64,
        terminate_error: Option<&'static str>,
    }

    impl ContainedDescendantDomain for FakeContainedDomain {
        fn poll(
            &mut self,
            maximum_chunk_bytes: usize,
        ) -> Result<DomainObservation, SupervisorError> {
            assert_eq!(maximum_chunk_bytes, CONTAINED_BACKEND_POLL_CHUNK_LIMIT);
            if self.poll_error.is_some()
                && self.state.poll_count.load(Ordering::Acquire)
                    >= self.poll_error_after_observations
            {
                let message = self.poll_error.take().expect("poll error remains present");
                self.state.poll_count.fetch_add(1, Ordering::AcqRel);
                return Err(SupervisorError::Capability(message.into()));
            }
            if let Some(observation) = self.observations.pop_front() {
                self.state.poll_count.fetch_add(1, Ordering::AcqRel);
                if observation.leader.is_some() {
                    self.last_leader = observation.leader;
                }
                return Ok(observation);
            }
            self.state.poll_count.fetch_add(1, Ordering::AcqRel);
            Ok(DomainObservation {
                stdout: Vec::new(),
                stderr: Vec::new(),
                leader: self.last_leader,
                stdout_closed: self.last_leader.is_some(),
                stderr_closed: self.last_leader.is_some(),
                domain_empty: self.last_leader.is_some(),
            })
        }

        fn terminate_all(
            &mut self,
            reason: DomainTerminationRequest,
        ) -> Result<(), SupervisorError> {
            self.state
                .terminations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(reason);
            if let Some(message) = self.terminate_error.take() {
                return Err(SupervisorError::Capability(message.into()));
            }
            if self.last_leader.is_none()
                && !self
                    .observations
                    .iter()
                    .any(|observation| observation.leader.is_some())
            {
                self.observations.push_back(DomainObservation {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    leader: Some(BackendTermination::Signaled(9)),
                    stdout_closed: true,
                    stderr_closed: true,
                    domain_empty: true,
                });
            }
            Ok(())
        }

        fn into_cleanup_proof(
            mut self,
        ) -> Result<ValidatedCommandDomainCleanupProof, SupervisorError> {
            self.state
                .cleanup_proof_consumptions
                .fetch_add(1, Ordering::AcqRel);
            self.state.cleanup_proof_consumed_at_poll.store(
                self.state.poll_count.load(Ordering::Acquire),
                Ordering::Release,
            );
            self.cleanup_proof.take().ok_or_else(|| {
                SupervisorError::Capability(
                    "contained domain reached empty state without a validated cleanup proof".into(),
                )
            })
        }
    }

    impl ContainedCommandBackend for FakeContainedBackend {
        type Domain = FakeContainedDomain;

        fn identity(&self) -> Result<BackendIdentity, SupervisorError> {
            Ok(self.identity.clone())
        }

        fn active_preflight(
            &mut self,
            command: &PreparedContainedCommand,
        ) -> Result<BackendPreflightReport, SupervisorError> {
            if let Some(message) = self.preflight_error {
                return Err(SupervisorError::Canary(message.into()));
            }
            Ok(BackendPreflightReport::new(
                command.launch_digest().clone(),
                self.reported_identity
                    .clone()
                    .unwrap_or_else(|| self.identity.clone()),
                self.controls.clone(),
                self.descriptors.clone(),
                self.canary_status.clone(),
            ))
        }

        fn launch(
            &mut self,
            command: PreparedContainedCommand,
            permit: ValidatedBackendPermit,
            output_capture: &DurablyAnchoredCapture,
        ) -> Result<Self::Domain, SupervisorError> {
            assert_eq!(permit.launch_digest(), command.launch_digest());
            assert_eq!(permit.backend(), &self.identity);
            assert_eq!(permit.closed_descriptors(), &[0, 1, 2]);
            assert_ne!(permit.preflight_digest(), command.launch_digest());
            assert!(!output_capture.capture_id().is_empty());
            assert_ne!(
                output_capture.acquired_anchor_digest(),
                &output_capture.launch_intended_store_head().record_digest
            );
            self.state.launch_count.fetch_add(1, Ordering::AcqRel);
            if let Some(hook) = self.launch_hook.take() {
                hook();
            }
            if let Some(message) = self.launch_error {
                return Err(SupervisorError::Capability(message.into()));
            }
            if let Some(cancellation) = &self.cancel_on_launch {
                cancellation.cancel();
            }
            Ok(FakeContainedDomain {
                observations: std::mem::take(&mut self.observations),
                state: self.state.clone(),
                last_leader: None,
                cleanup_proof: self.cleanup_proof.take(),
                poll_error: self.poll_error.take(),
                poll_error_after_observations: self.poll_error_after_observations,
                terminate_error: self.terminate_error.take(),
            })
        }
    }

    fn prepared_output_capture_id(prepared: &PreparedContainedCommand) -> String {
        match &prepared.command_effect_authority().envelope().request {
            RunnerRequest::WorkerRunCommand { output_capture, .. }
            | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
                output_capture.acquired().capture_id.clone()
            }
            _ => panic!("prepared command requires exact output capture"),
        }
    }

    fn prepared_output_capture_authority(
        prepared: &PreparedContainedCommand,
    ) -> (CommandOutputCaptureIntentV1, CommandOutputCaptureAcquiredV1) {
        let acquired = match &prepared.command_effect_authority().envelope().request {
            RunnerRequest::WorkerRunCommand { output_capture, .. }
            | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
                output_capture.acquired().clone()
            }
            _ => panic!("prepared command requires exact output capture"),
        };
        let intent = CommandOutputCaptureIntentV1::try_new(
            acquired.capture_id.clone(),
            acquired.source.clone(),
            acquired.private_state_digest.clone(),
            acquired.max_aggregate_output_bytes,
            1,
        )
        .expect("rebuild exact test capture intent");
        assert_eq!(intent.intent_digest, acquired.intent_digest);
        (intent, acquired)
    }

    #[derive(Serialize)]
    struct CanonicalLiveErrorRecoveryClaim<'a> {
        contract_version: u32,
        claim_id: &'a str,
        capture_id: &'a str,
        owner_id: &'a str,
        claim_epoch: u64,
        previous_claim_id: Option<&'a str>,
        fencing_token: &'a Digest,
        acquired_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    }

    fn framed_test_digest(domain: &[u8], value: &[u8]) -> Digest {
        let mut bytes = Vec::with_capacity(domain.len() + 8 + value.len());
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(
            &u64::try_from(value.len())
                .expect("test value length fits u64")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(value);
        Digest::sha256(&bytes)
    }

    fn live_error_recovery_claim(capture_id: &str) -> CommandOutputCaptureReconciliationClaimV1 {
        let owner_id = "command-live-error-recovery";
        let claim_epoch = 1_u64;
        let claim_id =
            Digest::sha256(format!("claim-{owner_id}-{capture_id}").as_bytes()).to_string();
        let mut token_bytes = Vec::new();
        for value in [
            capture_id.as_bytes(),
            claim_id.as_bytes(),
            owner_id.as_bytes(),
        ] {
            token_bytes.extend_from_slice(
                &u64::try_from(value.len())
                    .expect("test claim field length fits u64")
                    .to_be_bytes(),
            );
            token_bytes.extend_from_slice(value);
        }
        token_bytes.extend_from_slice(&claim_epoch.to_be_bytes());
        let fencing_token = framed_test_digest(
            b"grok-build/command-output-capture-reconciliation-fencing-token/v1\0",
            &token_bytes,
        );
        let acquired_at_unix_ms = 10;
        let expires_at_unix_ms = 1_010;
        let canonical = serde_json::to_vec(&CanonicalLiveErrorRecoveryClaim {
            contract_version: CONTRACT_VERSION,
            claim_id: &claim_id,
            capture_id,
            owner_id,
            claim_epoch,
            previous_claim_id: None,
            fencing_token: &fencing_token,
            acquired_at_unix_ms,
            expires_at_unix_ms,
        })
        .expect("encode canonical live-error recovery claim");
        let claim_digest = framed_test_digest(
            b"grok-build/command-output-capture-reconciliation-claim/v1\0",
            &canonical,
        );
        let claim = CommandOutputCaptureReconciliationClaimV1 {
            contract_version: CONTRACT_VERSION,
            claim_id,
            capture_id: capture_id.to_owned(),
            owner_id: owner_id.into(),
            claim_epoch,
            previous_claim_id: None,
            fencing_token,
            acquired_at_unix_ms,
            expires_at_unix_ms,
            claim_digest,
        };
        claim
            .validate()
            .expect("validate live-error recovery claim");
        claim
    }

    fn quarantine_generation_four_after_live_error(
        private_state_root: &Path,
        intent: &CommandOutputCaptureIntentV1,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
    ) {
        let store = CapabilityCommandOutputStore::open(private_state_root)
            .expect("reopen store for generation-four quarantine");
        let before = store
            .reopen_sensitive_output_journal_v2(&intent.capture_id)
            .expect("reopen generation-four v2 launch state");
        assert_eq!(before.head().generation, 4);
        let claim = live_error_recovery_claim(&intent.capture_id);
        let quarantine = store
            .quarantine_unclassified_sensitive_output_after_launch_v2(
                intent,
                &claim,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                native_cleanup_proof,
            )
            .expect("zero-first quarantine exact unclassified live error");
        quarantine
            .validate()
            .expect("validate typed generation-four quarantine");
        assert_eq!(quarantine.v2_launch_intended(), &before);
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&intent.capture_id)
                .expect("reread unchanged generation-four v2 state"),
            before
        );
        assert_eq!(
            quarantine.v1_cleaned().state(),
            crate::command_output_store::CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert!(quarantine.v1_cleaned().expected_reference().is_none());
        assert!(
            !private_state_root
                .join(format!(".command-output-capture-{}", intent.capture_id))
                .exists(),
            "zero-first quarantine must remove exact staging custody"
        );
    }

    #[allow(
        clippy::items_after_statements,
        reason = "the recursive JSON inspector stays beside the raw-byte quarantine audit it serves"
    )]
    fn assert_quarantine_retains_no_prefix_derived_metadata(
        private_state_root: &Path,
        released_prefix: &[u8],
    ) {
        fn inspect(
            path: &Path,
            released_prefix: &[u8],
            released_prefix_digest: &[u8],
            observed_zero_lengths: &mut usize,
        ) {
            for entry in fs::read_dir(path).expect("enumerate quarantined private state") {
                let entry = entry.expect("read quarantined private-state entry");
                let file_type = entry.file_type().expect("inspect quarantined entry type");
                if file_type.is_dir() {
                    inspect(
                        &entry.path(),
                        released_prefix,
                        released_prefix_digest,
                        observed_zero_lengths,
                    );
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                let bytes = fs::read(entry.path()).expect("read quarantined retained evidence");
                assert!(
                    !bytes
                        .windows(released_prefix.len())
                        .any(|window| window == released_prefix),
                    "scanner-released prefix bytes survived zero-first quarantine"
                );
                assert!(
                    !bytes
                        .windows(released_prefix_digest.len())
                        .any(|window| window == released_prefix_digest),
                    "scanner-released prefix digest survived zero-first quarantine"
                );
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                    continue;
                };
                fn inspect_json(
                    value: &serde_json::Value,
                    output_object: bool,
                    observed_zero_lengths: &mut usize,
                ) {
                    match value {
                        serde_json::Value::Object(fields) => {
                            for (field, value) in fields {
                                assert!(
                                    ![
                                        "output_digest",
                                        "fingerprint",
                                        "offset",
                                        "matched_length",
                                        "matched_rule",
                                        "summary",
                                    ]
                                    .contains(&field.as_str()),
                                    "quarantine retained prohibited output-derived field {field}"
                                );
                                if output_object && field == "byte_length" {
                                    *observed_zero_lengths += 1;
                                    assert_eq!(
                                        value.as_u64(),
                                        Some(0),
                                        "quarantine may persist only constant-zero output-object lengths"
                                    );
                                }
                                inspect_json(
                                    value,
                                    output_object || matches!(field.as_str(), "stdout" | "stderr"),
                                    observed_zero_lengths,
                                );
                            }
                        }
                        serde_json::Value::Array(values) => {
                            for value in values {
                                inspect_json(value, output_object, observed_zero_lengths);
                            }
                        }
                        _ => {}
                    }
                }
                inspect_json(&value, false, observed_zero_lengths);
            }
        }

        assert!(!released_prefix.is_empty());
        let released_prefix_digest = Digest::sha256(released_prefix).to_string();
        let mut observed_zero_lengths = 0;
        inspect(
            private_state_root,
            released_prefix,
            released_prefix_digest.as_bytes(),
            &mut observed_zero_lengths,
        );
        assert!(
            observed_zero_lengths >= 2,
            "zero-first quarantine must retain exact zero object identities"
        );
    }

    fn assert_post_match_failure_preserved_private_precleanup(
        private_state_root: &Path,
        capture_id: &str,
        expected_v2_generation: u64,
    ) {
        assert_post_match_failure_preserved_private_precleanup_with(
            private_state_root,
            capture_id,
            expected_v2_generation,
            |stdout, stderr| {
                assert_eq!(
                    stdout,
                    Vec::<u8>::new(),
                    "matched bytes must never reach stdout staging"
                );
                assert_eq!(
                    stderr,
                    Vec::<u8>::new(),
                    "matched bytes must never reach stderr staging"
                );
            },
        );
    }

    fn assert_post_match_failure_preserved_private_precleanup_with(
        private_state_root: &Path,
        capture_id: &str,
        expected_v2_generation: u64,
        inspect_staging: impl FnOnce(Vec<u8>, Vec<u8>),
    ) {
        let store = CapabilityCommandOutputStore::open(private_state_root).expect("reopen store");
        let v1 = store
            .reopen_capture(capture_id)
            .expect("reopen exact post-match v1 state");
        assert_eq!(
            v1.state(),
            crate::command_output_store::CommandOutputCaptureJournalStateV1::LaunchIntended,
            "post-match failure must not append legacy CleanupIntended or Cleaned"
        );
        assert!(v1.cleanup_intended_store_head().is_none());
        assert!(v1.cleaned_store_head().is_none());
        let v2 = store
            .reopen_sensitive_output_journal_v2(capture_id)
            .expect("reopen exact post-match v2 prefix");
        assert_eq!(v2.head().generation, expected_v2_generation);
        match expected_v2_generation {
            4 => assert!(matches!(
                v2.stage(),
                crate::command_output_store::SensitiveOutputJournalStageV2::LaunchIntended { .. }
            )),
            5 => assert!(matches!(
                v2.stage(),
                crate::command_output_store::SensitiveOutputJournalStageV2::SensitiveOutputDetected {}
            )),
            _ => panic!("post-match fixture expected only generation four or five"),
        }
        let working = private_state_root.join(format!(".command-output-capture-{capture_id}"));
        inspect_staging(
            fs::read(working.join("stdout.raw")).expect("read screened stdout staging"),
            fs::read(working.join("stderr.raw")).expect("read screened stderr staging"),
        );
    }

    fn contained_fixture(
        label: &str,
        limits: ResourceLimits,
    ) -> (
        TestDirectory,
        TestDirectory,
        SupervisorPaths,
        IssuedWorkspaceGrant,
        CompiledExecutionPolicy,
        CommandSpec,
    ) {
        let workspace = TestDirectory::new(&format!("{label}-workspace"));
        let private = TestDirectory::new(&format!("{label}-private"));
        let shadow = private.0.join("shadow");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&shadow).expect("create private shadow");
        fs::create_dir(shadow.join("src")).expect("create contained cwd");
        let (grant, policy) = authority_with_limits(&workspace.0, ExecutionNetwork::None, limits);
        let paths = SupervisorPaths::shadow(&private.0, &shadow);
        let command = CommandSpec {
            program: "/usr/bin/true".into(),
            arguments: vec!["literal space".into(), "$HOME".into(), "'quoted'".into()],
            working_directory: PathBuf::from("src"),
        };
        (workspace, private, paths, grant, policy, command)
    }

    fn try_worker_command_effect_authority(
        command: &CommandSpec,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        input_snapshot: &Digest,
        session_id: &str,
        effect_id: &str,
        request_id: &str,
    ) -> Result<Option<CommandEffectAuthorityV1>, crate::wire::WireProtocolError> {
        let core_command_bytes = serde_json::to_vec(command).expect("encode core command");
        let worker_lease = WorkerLease::new(
            "sprint-command-test".into(),
            1,
            "task-command-test".into(),
            "worker-command-test".into(),
            vec![PathScope::Relative(PathBuf::from("src"))],
            1,
        )
        .expect("construct command worker lease");
        let wire_command = WireCommandSpec {
            program: command.program.clone(),
            arguments: command.arguments.clone(),
            working_directory: command
                .working_directory
                .to_str()
                .expect("command cwd is UTF-8")
                .into(),
        };
        let request_digest = Digest::sha256(&core_command_bytes);
        let output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: "sprint-command-test".into(),
                runner_launch_id: "launch-command-test".into(),
                runner_session_id: session_id.into(),
                effect_id: effect_id.into(),
                request_digest: request_digest.clone(),
            },
            hash_bytes(b"command-test-private-state"),
            command_output_capture_maximum(policy.contract().resource_limits.max_output_bytes)
                .expect("command test capture maximum"),
            1,
        );
        let mut envelope = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: session_id.into(),
            runner_nonce: Some(hash_bytes(b"command runner nonce")),
            sequence: 1,
            request_id: request_id.into(),
            effect: Some(WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "launch-command-test".into(),
                effect_id: effect_id.into(),
                idempotency_key: "idempotency-command-test".into(),
                sprint_id: "sprint-command-test".into(),
                task_id: Some("task-command-test".into()),
                worker_id: Some("worker-command-test".into()),
                worker_lease: Some(worker_lease),
                policy_hash: policy.contract().policy_hash.clone(),
                input_snapshot: input_snapshot.clone(),
                request_digest,
                transport_commitment_digest: hash_bytes(b"unbound transport commitment"),
            }),
            request: RunnerRequest::WorkerRunCommand {
                command: wire_command,
                output_capture,
            },
        };
        envelope.bind_transport_commitment_digest()?;
        CommandEffectAuthorityV1::from_session_validated(
            crate::service::test_session_validated_command_envelope(
                &envelope,
                &grant.contract().grant_hash,
            ),
        )
    }

    fn worker_command_effect_authority(
        command: &CommandSpec,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        input_snapshot: &Digest,
        session_id: &str,
        effect_id: &str,
        request_id: &str,
    ) -> CommandEffectAuthorityV1 {
        try_worker_command_effect_authority(
            command,
            grant,
            policy,
            input_snapshot,
            session_id,
            effect_id,
            request_id,
        )
        .expect("validate command-effect authority")
        .expect("worker command produces effect authority")
    }

    fn read_only_command_policy(grant: &IssuedWorkspaceGrant) -> CompiledExecutionPolicy {
        ExecutionPolicyCompiler::compile(
            grant,
            ExecutionPolicyRequest {
                policy_id: "policy-command-test-read-only".into(),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: Vec::new(),
                environment: vec![EnvironmentVariable {
                    name: "PATH".into(),
                    value: "/usr/bin:/bin".into(),
                }],
                network: ExecutionNetwork::None,
                mutation_mode: MutationMode::ReadOnly,
                resource_limits: ResourceLimits {
                    wall_time_ms: 1_000,
                    max_output_bytes: 1024,
                    max_processes: 1,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile read-only command policy")
    }

    fn final_verifier_command_effect_authority(
        command: &CommandSpec,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        input_snapshot: &Digest,
    ) -> CommandEffectAuthorityV1 {
        let core_command_bytes = serde_json::to_vec(command).expect("encode core command");
        let wire_command = WireCommandSpec {
            program: command.program.clone(),
            arguments: command.arguments.clone(),
            working_directory: command
                .working_directory
                .to_str()
                .expect("command cwd is UTF-8")
                .into(),
        };
        let request_digest = Digest::sha256(&core_command_bytes);
        let output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: "sprint-command-test".into(),
                runner_launch_id: "launch-final-verifier-blocked".into(),
                runner_session_id: "session-final-verifier-blocked".into(),
                effect_id: "effect-final-verifier-blocked".into(),
                request_digest: request_digest.clone(),
            },
            hash_bytes(b"final-verifier-test-private-state"),
            command_output_capture_maximum(policy.contract().resource_limits.max_output_bytes)
                .expect("final-verifier test capture maximum"),
            2,
        );
        let mut envelope = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: "session-final-verifier-blocked".into(),
            runner_nonce: Some(hash_bytes(b"final verifier runner nonce")),
            sequence: 1,
            request_id: "request-final-verifier-blocked".into(),
            effect: Some(WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "launch-final-verifier-blocked".into(),
                effect_id: "effect-final-verifier-blocked".into(),
                idempotency_key: "idempotency-final-verifier-blocked".into(),
                sprint_id: "sprint-command-test".into(),
                task_id: None,
                worker_id: None,
                worker_lease: None,
                policy_hash: policy.contract().policy_hash.clone(),
                input_snapshot: input_snapshot.clone(),
                request_digest,
                transport_commitment_digest: hash_bytes(b"unbound transport commitment"),
            }),
            request: RunnerRequest::FinalVerifierRunCommand {
                command: wire_command,
                output_capture,
            },
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind final-verifier command transport");
        CommandEffectAuthorityV1::from_session_validated(
            crate::service::test_session_validated_command_envelope(
                &envelope,
                &grant.contract().grant_hash,
            ),
        )
        .expect("validate final-verifier authority")
        .expect("final-verifier command produces authority")
    }

    pub(crate) fn prepare_contained(
        grant: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        paths: &SupervisorPaths,
        command: &CommandSpec,
    ) -> Result<PreparedContainedCommand, SupervisorError> {
        let execution_root_manifest = test_execution_root_manifest(paths, &grant)
            .map_err(|error| SupervisorError::InvalidCommand(error.to_string()))?;
        let authority = worker_command_effect_authority(
            command,
            &grant,
            &policy,
            &execution_root_manifest.snapshot().snapshot_id,
            "session-command-test",
            "effect-command-test",
            "request-command-test",
        );
        let authority = anchor_test_output_capture(&authority, paths.private_state_root(), &grant)
            .expect("durably reserve exact test command-output capture");
        let root_authority = test_execution_root_authority(&authority, paths)?;
        contained_boundary::prepare(
            authority,
            grant,
            policy,
            root_authority,
            paths,
            &execution_root_manifest,
        )
    }

    fn anchor_test_output_capture(
        authority: &CommandEffectAuthorityV1,
        private_state_root: &Path,
        grant: &IssuedWorkspaceGrant,
    ) -> Result<CommandEffectAuthorityV1, String> {
        let mut envelope = authority.envelope().clone();
        let acquired_fixture = match &envelope.request {
            RunnerRequest::WorkerRunCommand { output_capture, .. }
            | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
                output_capture.acquired().clone()
            }
            _ => return Err("test command authority has no acquired capture".into()),
        };
        let capture_id = Digest::sha256(
            format!(
                "{}:{}:{}",
                envelope.session_id,
                acquired_fixture.source.effect_id,
                private_state_root.display()
            )
            .as_bytes(),
        )
        .as_str()
        .to_owned();
        let intent = CommandOutputCaptureIntentV1::try_new(
            capture_id,
            acquired_fixture.source,
            crate::service::inspect_private_state_digest(private_state_root)
                .map_err(|error| error.to_string())?,
            acquired_fixture.max_aggregate_output_bytes,
            1,
        )
        .map_err(|error| error.to_string())?;
        let store = CapabilityCommandOutputStore::open(private_state_root)
            .map_err(|error| error.to_string())?;
        let reservation = store
            .reserve_anchored_capture_v2(
                &intent,
                &acquired_fixture.dispatch_claim_id,
                2,
                &SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            )
            .map_err(|error| error.to_string())?;
        let acquired = reservation
            .into_acquired_anchor_for_handoff()
            .map_err(|error| error.to_string())?;
        let output_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired)
            .map_err(|error| error.to_string())?;
        match &mut envelope.request {
            RunnerRequest::WorkerRunCommand {
                output_capture: existing,
                ..
            }
            | RunnerRequest::FinalVerifierRunCommand {
                output_capture: existing,
                ..
            } => *existing = output_capture,
            _ => return Err("test command envelope changed request class".into()),
        }
        envelope
            .bind_transport_commitment_digest()
            .map_err(|error| error.to_string())?;
        CommandEffectAuthorityV1::from_session_validated(
            crate::service::test_session_validated_command_envelope(
                &envelope,
                &grant.contract().grant_hash,
            ),
        )
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "test command envelope did not mint command authority".into())
    }

    fn test_execution_root_manifest(
        paths: &SupervisorPaths,
        grant: &IssuedWorkspaceGrant,
    ) -> Result<WorkspaceManifest, crate::WorkspacePipelineError> {
        WorkspaceManifest::capture_root(
            paths.shadow_root().expect("test Worker shadow root"),
            grant.contract().grant_hash.clone(),
            1,
        )
    }

    fn test_execution_root_authority(
        authority: &CommandEffectAuthorityV1,
        paths: &SupervisorPaths,
    ) -> Result<SessionValidatedWorkerExecutionRoot, SupervisorError> {
        crate::service::test_session_validated_worker_execution_root(
            authority,
            paths.private_state_root(),
            paths.shadow_root().expect("test Worker shadow root"),
        )
        .map_err(SupervisorError::Authority)
    }

    fn test_command_cleanup_binding(
        command: &PreparedContainedCommand,
    ) -> CommandDomainCleanupBinding {
        let authority = command.command_effect_authority();
        let effect = authority
            .envelope()
            .effect
            .as_ref()
            .expect("prepared command has effect context");
        CommandDomainCleanupBinding::try_new(
            authority.envelope().session_id.clone(),
            effect.effect_id.clone(),
            effect.request_digest.clone(),
        )
        .expect("prepared command has exact cleanup binding")
    }

    #[test]
    fn cancellation_is_one_way_and_shared() {
        let token = CancellationToken::new();
        let other = token.clone();
        assert!(!token.is_cancelled());
        other.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn contained_preparation_retains_exact_argv_environment_and_directory_capabilities() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "prepare",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 3,
                max_memory_bytes: Some(16 * 1024 * 1024),
            },
        );
        let prepared = prepare_contained(grant, policy, &paths, &command)
            .expect("prepare descriptor-bound command");
        assert_eq!(prepared.command(), &command);
        assert_eq!(
            prepared.command().arguments,
            ["literal space", "$HOME", "'quoted'"]
        );
        assert_eq!(prepared.environment().len(), 1);
        assert_eq!(
            prepared.environment().get(OsStr::new("PATH")),
            Some(&OsString::from("/usr/bin:/bin"))
        );
        assert!(!prepared.environment().contains_key(OsStr::new("HOME")));
        assert_eq!(prepared.executable_path(), Path::new("/usr/bin/true"));
        assert!(prepared.execution_root_path().ends_with("shadow"));
        assert!(prepared.working_directory_path().ends_with("shadow/src"));
        for descriptor in [
            prepared.executable_descriptor().as_fd(),
            prepared.private_state_root_descriptor().as_fd(),
            prepared.execution_root_descriptor().as_fd(),
            prepared.working_directory_descriptor().as_fd(),
        ] {
            assert!(
                fcntl_getfd(descriptor)
                    .expect("inspect retained descriptor")
                    .contains(FdFlags::CLOEXEC)
            );
        }
        prepared
            .revalidate()
            .expect("retained authority remains exact");
    }

    #[test]
    fn contained_preparation_retains_exact_command_effect_authority() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "effect-authority",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let execution_root_manifest =
            test_execution_root_manifest(&paths, &grant).expect("capture Worker shadow");
        let authority = worker_command_effect_authority(
            &command,
            &grant,
            &policy,
            &execution_root_manifest.snapshot().snapshot_id,
            "session-effect-authority",
            "effect-effect-authority",
            "request-effect-authority",
        );
        let expected = authority.clone();
        let root_authority =
            test_execution_root_authority(&authority, &paths).expect("retain session root");
        let prepared = contained_boundary::prepare(
            authority,
            grant,
            policy,
            root_authority,
            &paths,
            &execution_root_manifest,
        )
        .expect("prepare authority-bound command");

        assert_eq!(prepared.command_effect_authority(), &expected);
        assert_eq!(prepared.command(), &command);
        prepared
            .revalidate()
            .expect("retained command-effect authority remains exact");
    }

    #[test]
    fn contained_preparation_rejects_crossed_grant_and_policy_authority() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "crossed-effect-authority",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let execution_root_manifest =
            test_execution_root_manifest(&paths, &grant).expect("capture Worker shadow");
        let authority = worker_command_effect_authority(
            &command,
            &grant,
            &policy,
            &execution_root_manifest.snapshot().snapshot_id,
            "session-crossed-authority",
            "effect-crossed-authority",
            "request-crossed-authority",
        );
        let other_workspace = TestDirectory::new("crossed-authority-workspace");
        let (crossed_grant, crossed_grant_policy) = authority_with_limits(
            &other_workspace.0,
            ExecutionNetwork::None,
            policy.contract().resource_limits,
        );
        let crossed_grant_root_authority =
            test_execution_root_authority(&authority, &paths).expect("retain session root");
        let grant_error = contained_boundary::prepare(
            authority.clone(),
            crossed_grant,
            crossed_grant_policy,
            crossed_grant_root_authority,
            &paths,
            &execution_root_manifest,
        )
        .expect_err("crossed grant must fail before descriptor acquisition");
        assert!(grant_error.to_string().contains("grant differs"));

        let crossed_policy = ExecutionPolicyCompiler::compile(
            &grant,
            ExecutionPolicyRequest {
                policy_id: "policy-command-test-crossed".into(),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                environment: vec![EnvironmentVariable {
                    name: "PATH".into(),
                    value: "/usr/bin:/bin".into(),
                }],
                network: ExecutionNetwork::None,
                mutation_mode: MutationMode::ShadowWorkspace,
                resource_limits: ResourceLimits {
                    wall_time_ms: 2_000,
                    max_output_bytes: 1024,
                    max_processes: 1,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile crossed policy");
        let crossed_policy_root_authority =
            test_execution_root_authority(&authority, &paths).expect("retain session root");
        let policy_error = contained_boundary::prepare(
            authority,
            grant,
            crossed_policy,
            crossed_policy_root_authority,
            &paths,
            &execution_root_manifest,
        )
        .expect_err("crossed policy must fail before descriptor acquisition");
        assert!(policy_error.to_string().contains("policy differs"));
    }

    #[test]
    fn contained_preparation_rejects_crossed_execution_snapshot_before_executable_open() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "crossed-execution-snapshot",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let execution_root_manifest =
            test_execution_root_manifest(&paths, &grant).expect("capture Worker shadow");
        let authority = worker_command_effect_authority(
            &command,
            &grant,
            &policy,
            &execution_root_manifest.snapshot().snapshot_id,
            "session-crossed-execution-snapshot",
            "effect-crossed-execution-snapshot",
            "request-crossed-execution-snapshot",
        );
        fs::write(
            paths
                .shadow_root()
                .expect("Worker shadow")
                .join("src/raced.txt"),
            b"raced after effect admission\n",
        )
        .expect("change retained execution root after admission");

        let root_authority =
            test_execution_root_authority(&authority, &paths).expect("retain session root");
        let error = contained_boundary::prepare(
            authority,
            grant,
            policy,
            root_authority,
            &paths,
            &execution_root_manifest,
        )
        .expect_err("crossed execution snapshot must fail before executable retention");
        assert!(error.to_string().contains("effect input snapshot"));
    }

    #[test]
    fn contained_preparation_rejects_same_snapshot_from_crossed_root() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "crossed-execution-root",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let expected_manifest =
            test_execution_root_manifest(&paths, &grant).expect("capture Worker shadow");
        let crossed_root = paths.private_state_root().join("crossed-shadow");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&crossed_root)
            .expect("create crossed shadow root");
        fs::create_dir(crossed_root.join("src")).expect("create crossed shadow cwd");
        let crossed_manifest =
            WorkspaceManifest::capture_root(&crossed_root, grant.contract().grant_hash.clone(), 1)
                .expect("capture same-content crossed root");
        assert_eq!(
            expected_manifest.snapshot().snapshot_id,
            crossed_manifest.snapshot().snapshot_id
        );
        let authority = worker_command_effect_authority(
            &command,
            &grant,
            &policy,
            &expected_manifest.snapshot().snapshot_id,
            "session-crossed-execution-root",
            "effect-crossed-execution-root",
            "request-crossed-execution-root",
        );
        let root_authority =
            test_execution_root_authority(&authority, &paths).expect("retain initialized root");
        let crossed_paths = SupervisorPaths::shadow(paths.private_state_root(), &crossed_root);

        let error = contained_boundary::prepare(
            authority,
            grant,
            policy,
            root_authority,
            &crossed_paths,
            &crossed_manifest,
        )
        .expect_err("fully crossed paths and manifest must not replace session root custody");
        assert!(error.to_string().contains("retained root custody"));
    }

    #[test]
    fn contained_preparation_rejects_root_custody_from_crossed_effect() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "crossed-root-effect",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let execution_root_manifest =
            test_execution_root_manifest(&paths, &grant).expect("capture Worker shadow");
        let first_authority = worker_command_effect_authority(
            &command,
            &grant,
            &policy,
            &execution_root_manifest.snapshot().snapshot_id,
            "session-crossed-root-effect",
            "effect-root-a",
            "request-root-a",
        );
        let crossed_authority = worker_command_effect_authority(
            &command,
            &grant,
            &policy,
            &execution_root_manifest.snapshot().snapshot_id,
            "session-crossed-root-effect",
            "effect-root-b",
            "request-root-b",
        );
        let root_authority = test_execution_root_authority(&first_authority, &paths)
            .expect("retain first effect root custody");

        let error = contained_boundary::prepare(
            crossed_authority,
            grant,
            policy,
            root_authority,
            &paths,
            &execution_root_manifest,
        )
        .expect_err("root custody from another command effect must fail closed");
        assert!(error.to_string().contains("different command effect"));
    }

    #[test]
    fn contained_revalidation_rejects_execution_snapshot_change_before_launch() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "execution-snapshot-revalidation",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let prepared = prepare_contained(grant, policy, &paths, &command)
            .expect("prepare exact execution snapshot");
        fs::write(
            paths
                .shadow_root()
                .expect("Worker shadow")
                .join("src/changed-before-launch.txt"),
            b"changed after preparation\n",
        )
        .expect("change execution root after preparation");

        let error = prepared
            .revalidate()
            .expect_err("changed execution snapshot must fail before preflight or launch");
        assert!(error.to_string().contains("effect input snapshot"));
    }

    #[test]
    fn contained_revalidation_rejects_private_state_mode_change_before_launch() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "private-state-mode-revalidation",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let prepared = prepare_contained(grant, policy, &paths, &command)
            .expect("prepare session-root-bound command");
        fs::set_permissions(
            paths.private_state_root(),
            fs::Permissions::from_mode(0o755),
        )
        .expect("widen private-state mode after preparation");

        let error = prepared
            .revalidate()
            .expect_err("changed private-state parent must fail before preflight or launch");
        assert!(
            error
                .to_string()
                .contains("retained directory identity changed")
        );
        fs::set_permissions(
            paths.private_state_root(),
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore private-state mode for cleanup");
    }

    #[test]
    fn contained_preparation_rejects_worker_read_only_policy() {
        let (_workspace, _private, paths, grant, _policy, command) = contained_fixture(
            "read-only-worker",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let read_only_policy = read_only_command_policy(&grant);
        let execution_root_manifest =
            test_execution_root_manifest(&paths, &grant).expect("capture Worker shadow");
        let worker_authority = worker_command_effect_authority(
            &command,
            &grant,
            &read_only_policy,
            &execution_root_manifest.snapshot().snapshot_id,
            "session-read-only-worker",
            "effect-read-only-worker",
            "request-read-only-worker",
        );
        let root_authority =
            test_execution_root_authority(&worker_authority, &paths).expect("retain session root");
        let worker_error = contained_boundary::prepare(
            worker_authority,
            grant,
            read_only_policy,
            root_authority,
            &paths,
            &execution_root_manifest,
        )
        .expect_err("Worker read-only policy is not the admitted service shape");
        assert!(
            worker_error
                .to_string()
                .contains("exact shadow-workspace policy")
        );
    }

    #[test]
    fn contained_preparation_keeps_final_verifier_fail_closed() {
        let (_workspace, _private, paths, grant, _policy, command) = contained_fixture(
            "final-verifier-blocked",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let read_only_policy = read_only_command_policy(&grant);
        let execution_root_manifest =
            test_execution_root_manifest(&paths, &grant).expect("capture private snapshot");
        let final_authority = final_verifier_command_effect_authority(
            &command,
            &grant,
            &read_only_policy,
            &execution_root_manifest.snapshot().snapshot_id,
        );
        let root_authority = test_execution_root_authority(&final_authority, &paths)
            .expect("retain test root for role refusal");
        let final_error = contained_boundary::prepare(
            final_authority,
            grant,
            read_only_policy,
            root_authority,
            &paths,
            &execution_root_manifest,
        )
        .expect_err("FinalVerifier remains blocked without retained snapshot execution authority");
        assert!(
            final_error
                .to_string()
                .contains("FinalVerifier remains blocked")
        );
    }

    #[test]
    fn contained_launch_digest_binds_session_effect_and_request_identity() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "effect-identity-digest",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let execution_root_manifest =
            test_execution_root_manifest(&paths, &grant).expect("capture Worker shadow");
        let prepare = |session_id: &str, effect_id: &str, request_id: &str| {
            let authority = worker_command_effect_authority(
                &command,
                &grant,
                &policy,
                &execution_root_manifest.snapshot().snapshot_id,
                session_id,
                effect_id,
                request_id,
            );
            let root_authority =
                test_execution_root_authority(&authority, &paths).expect("retain session root");
            contained_boundary::prepare(
                authority,
                grant.clone(),
                policy.clone(),
                root_authority,
                &paths,
                &execution_root_manifest,
            )
            .expect("prepare identity-bound command")
        };
        let baseline = prepare("session-digest-a", "effect-digest-a", "request-digest-a");
        let changed_session = prepare("session-digest-b", "effect-digest-a", "request-digest-a");
        let changed_effect = prepare("session-digest-a", "effect-digest-b", "request-digest-a");
        let changed_request = prepare("session-digest-a", "effect-digest-a", "request-digest-b");

        let digests = BTreeSet::from([
            baseline.launch_digest().clone(),
            changed_session.launch_digest().clone(),
            changed_effect.launch_digest().clone(),
            changed_request.launch_digest().clone(),
        ]);
        assert_eq!(digests.len(), 4);
    }

    #[test]
    fn contained_preparation_rejects_shells_and_symlink_cwd() {
        let (_workspace, _private, paths, grant, policy, mut command) = contained_fixture(
            "nofollow",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let execution_root_manifest =
            test_execution_root_manifest(&paths, &grant).expect("capture Worker shadow");
        command.program = "/bin/sh".into();
        let shell_error = try_worker_command_effect_authority(
            &command,
            &grant,
            &policy,
            &execution_root_manifest.snapshot().snapshot_id,
            "session-shell-rejection",
            "effect-shell-rejection",
            "request-shell-rejection",
        )
        .expect_err("shell cannot acquire command-effect authority");
        assert!(shell_error.to_string().contains("shell"));

        let shadow = paths.shadow_root().expect("shadow path");
        std::os::unix::fs::symlink(shadow.join("src"), shadow.join("linked-cwd"))
            .expect("create cwd symlink");
        command.program = "/usr/bin/true".into();
        command.working_directory = PathBuf::from("linked-cwd");
        let authority = worker_command_effect_authority(
            &command,
            &grant,
            &policy,
            &execution_root_manifest.snapshot().snapshot_id,
            "session-symlink-rejection",
            "effect-symlink-rejection",
            "request-symlink-rejection",
        );
        let root_authority =
            test_execution_root_authority(&authority, &paths).expect("retain session root");
        let error = contained_boundary::prepare(
            authority,
            grant,
            policy,
            root_authority,
            &paths,
            &execution_root_manifest,
        )
        .expect_err("symlink cwd must fail closed");
        assert!(error.to_string().contains("descriptor-capture"));
    }

    #[test]
    fn contained_preflight_requires_every_control_and_never_falls_back() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "controls",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, []);
        backend.controls.remove(&BackendControl::DescriptorExec);
        let error = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect_err("missing descriptor exec must block launch");
        assert!(error.to_string().contains("missing"));
        assert_eq!(state.launch_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn contained_execution_classifies_preflight_failure_before_launch() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 1024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("classified-preflight-failure", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, []);
        backend.controls = contained_boundary::required_controls(limits);
        backend.preflight_error = Some("injected active preflight failure");

        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        let ContainedExecutionOutcome::RefusedBeforeLaunch(error) = outcome else {
            panic!("preflight failure must remain before the native launch boundary")
        };
        assert!(
            error
                .to_string()
                .contains("injected active preflight failure")
        );
        assert_eq!(state.launch_count.load(Ordering::Acquire), 0);
        assert_eq!(state.poll_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn contained_execution_classifies_launch_failure_as_unproven_after_launch() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 1024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, private, paths, grant, policy, command) =
            contained_fixture("classified-launch-failure", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let (intent, _acquired) = prepared_output_capture_authority(&prepared);
        let cleanup_binding = test_command_cleanup_binding(&prepared);
        let native_cleanup_proof =
            crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&cleanup_binding);
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, []);
        backend.controls = contained_boundary::required_controls(limits);
        backend.launch_error = Some("injected ambiguous launch failure");

        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        let ContainedExecutionOutcome::UnprovenAfterLaunch(error) = outcome else {
            panic!("a backend launch error may follow a partial native effect")
        };
        let SupervisorError::CommandOutputCleanup { primary, cleanup } = error else {
            panic!("ambiguous launch must retain its primary error and typed reconciliation")
        };
        assert!(
            primary
                .to_string()
                .contains("injected ambiguous launch failure")
        );
        assert!(matches!(
            cleanup.as_ref(),
            CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(capture_id),
                reason,
                ..
            } if capture_id == &intent.capture_id && reason.contains("generation-four zero-first quarantine")
        ));
        assert_eq!(state.launch_count.load(Ordering::Acquire), 1);
        assert_eq!(state.poll_count.load(Ordering::Acquire), 0);
        let remaining = fs::read_dir(&private.0)
            .expect("enumerate private state after ambiguous launch")
            .map(|entry| {
                entry
                    .expect("read private-state entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(remaining.len(), 4);
        assert!(remaining.contains("shadow"));
        assert!(
            remaining
                .iter()
                .any(|name| name.starts_with("command-output-capture-journal-"))
        );
        assert!(
            remaining
                .iter()
                .any(|name| name.starts_with("sensitive-output-journal-v2-"))
        );
        assert!(remaining.contains(&format!(".command-output-capture-{}", intent.capture_id)));
        assert_post_match_failure_preserved_private_precleanup(&private.0, &intent.capture_id, 4);
        quarantine_generation_four_after_live_error(&private.0, &intent, &native_cleanup_proof);
        assert_eq!(
            state.launch_count.load(Ordering::Acquire),
            1,
            "quarantine must not redispatch the command"
        );
    }

    #[test]
    fn contained_execution_classifies_poll_failure_as_unproven_after_launch() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 1024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("classified-poll-failure", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, []);
        backend.controls = contained_boundary::required_controls(limits);
        backend.poll_error = Some("injected descendant poll failure");

        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        let ContainedExecutionOutcome::UnprovenAfterLaunch(error) = outcome else {
            panic!("a descendant poll error occurs after native launch")
        };
        assert!(
            error
                .to_string()
                .contains("injected descendant poll failure")
        );
        assert_eq!(state.launch_count.load(Ordering::Acquire), 1);
        assert_eq!(state.poll_count.load(Ordering::Acquire), 1);
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 0);
    }

    #[test]
    fn poll_failure_after_nonempty_clean_prefix_retains_custody_until_zero_first_quarantine() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 4_096,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, private, paths, grant, policy, command) =
            contained_fixture("poll-failure-after-clean-prefix", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let (intent, _acquired) = prepared_output_capture_authority(&prepared);
        let cleanup_binding = test_command_cleanup_binding(&prepared);
        let native_cleanup_proof =
            crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&cleanup_binding);
        let ordinary_prefix = vec![b'q'; 1_024];
        let prefix_observation = DomainObservation {
            stdout: ordinary_prefix.clone(),
            stderr: Vec::new(),
            leader: None,
            stdout_closed: false,
            stderr_closed: false,
            domain_empty: false,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [prefix_observation]);
        backend.controls = contained_boundary::required_controls(limits);
        backend.poll_error = Some("injected poll failure after scanner-released clean prefix");
        backend.poll_error_after_observations = 1;

        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        let ContainedExecutionOutcome::UnprovenAfterLaunch(error) = outcome else {
            panic!("poll failure after a released prefix remains launch-bearing Unknown")
        };
        assert!(
            error
                .to_string()
                .contains("injected poll failure after scanner-released clean prefix")
        );
        assert_eq!(state.launch_count.load(Ordering::Acquire), 1);
        assert_eq!(state.poll_count.load(Ordering::Acquire), 2);
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 0);

        assert_post_match_failure_preserved_private_precleanup_with(
            &private.0,
            &intent.capture_id,
            4,
            |stdout, stderr| {
                assert!(
                    !stdout.is_empty(),
                    "the scanner must release a non-empty ordinary prefix before poll failure"
                );
                assert!(ordinary_prefix.starts_with(&stdout));
                assert!(stderr.is_empty());
            },
        );
        let staged_stdout = fs::read(
            private
                .0
                .join(format!(".command-output-capture-{}", intent.capture_id))
                .join("stdout.raw"),
        )
        .expect("read exact scanner-released prefix before quarantine");
        assert!(!staged_stdout.is_empty());
        quarantine_generation_four_after_live_error(&private.0, &intent, &native_cleanup_proof);
        assert_quarantine_retains_no_prefix_derived_metadata(&private.0, &staged_stdout);
        assert_eq!(
            state.launch_count.load(Ordering::Acquire),
            1,
            "zero-first poll-failure quarantine must not redispatch the command"
        );
    }

    #[test]
    fn live_sensitive_rejection_publishes_secret_free_terminal_observation_before_cleanup() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 4_096,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, private, paths, grant, policy, command) =
            contained_fixture("live-sensitive-terminal-observation", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let marker = b"XAI_API_KEY=scanner-fixture-terminal-observation";
        let terminal_marker = DomainObservation {
            stdout: marker.to_vec(),
            stderr: Vec::new(),
            leader: Some(BackendTermination::Exited(7)),
            stdout_closed: true,
            stderr_closed: true,
            domain_empty: true,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [terminal_marker]);
        backend.controls = contained_boundary::required_controls(limits);

        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        let ContainedExecutionOutcome::SensitiveOutputRejected(evidence) = outcome else {
            panic!("a terminal scanner match must use the typed rejection branch")
        };
        assert_eq!(evidence.termination(), CommandTermination::Exited(7));
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 1);

        let store = CapabilityCommandOutputStore::open(&private.0).expect("reopen output store");
        let observation = store
            .reopen_sensitive_output_terminal_observation_v1(evidence.output_capture_id())
            .expect("reopen rejection terminal observation")
            .expect("live rejection publishes one terminal observation");
        observation
            .validate_expected(
                evidence.output_capture_id(),
                crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationBranchV1::Rejection,
                evidence.backend().command_domain_backend(),
                evidence.cleanup_proof().binding(),
                evidence.cleanup_proof(),
            )
            .expect("rejection sidecar rejoins exact live native proof");
        assert_eq!(observation.clean_response(), None);
        assert_eq!(
            observation.termination(),
            grok_build_core::CommandTerminationV1::Exited { code: 7 }
        );
        assert!(
            !observation
                .canonical_bytes()
                .windows(marker.len())
                .any(|window| window == marker),
            "rejection observation cannot retain matched bytes"
        );
        let rejection = store
            .reopen_sensitive_output_rejection_v2(evidence.output_capture_id())
            .expect("reopen exact rejection receipt")
            .expect("rejection branch is terminal");
        assert_eq!(&rejection, evidence.journal_receipt());
    }

    #[test]
    fn sensitive_match_then_termination_failure_never_enters_legacy_cleanup() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 1_024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, private, paths, grant, policy, command) =
            contained_fixture("sensitive-terminate-failure", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let capture_id = prepared_output_capture_id(&prepared);
        let marker = DomainObservation {
            stdout: b"XAI_API_KEY=scanner-fixture-only".to_vec(),
            stderr: Vec::new(),
            leader: None,
            stdout_closed: false,
            stderr_closed: false,
            domain_empty: false,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [marker]);
        backend.controls = contained_boundary::required_controls(limits);
        backend.terminate_error = Some("injected post-match termination failure");
        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        assert!(matches!(
            outcome,
            ContainedExecutionOutcome::UnprovenAfterLaunch(_)
        ));
        assert_eq!(state.launch_count.load(Ordering::Acquire), 1);
        assert_eq!(state.poll_count.load(Ordering::Acquire), 1);
        assert_post_match_failure_preserved_private_precleanup(&private.0, &capture_id, 5);
    }

    #[test]
    fn sensitive_match_then_poll_failure_never_enters_legacy_cleanup() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 1_024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, private, paths, grant, policy, command) =
            contained_fixture("sensitive-poll-failure", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let capture_id = prepared_output_capture_id(&prepared);
        let marker = DomainObservation {
            stdout: b"gb-secret-canary-scanner-fixture-only".to_vec(),
            stderr: Vec::new(),
            leader: None,
            stdout_closed: false,
            stderr_closed: false,
            domain_empty: false,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [marker]);
        backend.controls = contained_boundary::required_controls(limits);
        backend.poll_error = Some("injected post-match poll failure");
        backend.poll_error_after_observations = 1;
        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        assert!(matches!(
            outcome,
            ContainedExecutionOutcome::UnprovenAfterLaunch(_)
        ));
        assert_eq!(state.poll_count.load(Ordering::Acquire), 2);
        assert_post_match_failure_preserved_private_precleanup(&private.0, &capture_id, 5);
    }

    #[test]
    fn sensitive_match_then_cleanup_proof_failure_never_enters_legacy_cleanup() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 1_024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, private, paths, grant, policy, command) =
            contained_fixture("sensitive-proof-failure", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let capture_id = prepared_output_capture_id(&prepared);
        let terminal_marker = DomainObservation {
            stdout: Vec::new(),
            stderr: b"OPENAI_API_KEY=scanner-fixture-only".to_vec(),
            leader: Some(BackendTermination::Exited(0)),
            stdout_closed: true,
            stderr_closed: true,
            domain_empty: true,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [terminal_marker]);
        backend.controls = contained_boundary::required_controls(limits);
        backend.cleanup_proof = None;
        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        assert!(matches!(
            outcome,
            ContainedExecutionOutcome::UnprovenAfterLaunch(_)
        ));
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 1);
        assert_post_match_failure_preserved_private_precleanup(&private.0, &capture_id, 5);
    }

    #[test]
    fn sensitive_match_then_detection_journal_failure_never_enters_legacy_cleanup() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 4_096,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, private, paths, grant, policy, command) =
            contained_fixture("sensitive-journal-failure", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let capture_id = prepared_output_capture_id(&prepared);
        let ordinary_prefix = vec![b'p'; 1_024];
        let prefix_observation = DomainObservation {
            stdout: ordinary_prefix.clone(),
            stderr: Vec::new(),
            leader: None,
            stdout_closed: false,
            stderr_closed: false,
            domain_empty: false,
        };
        let marker = b"ANTHROPIC_API_KEY=scanner-fixture-only".to_vec();
        let terminal_marker = DomainObservation {
            stdout: marker.clone(),
            stderr: Vec::new(),
            leader: Some(BackendTermination::Exited(0)),
            stdout_closed: true,
            stderr_closed: true,
            domain_empty: true,
        };
        let (mut backend, state) =
            FakeContainedBackend::ready_for(&prepared, [prefix_observation, terminal_marker]);
        backend.controls = contained_boundary::required_controls(limits);
        let journal_directory = private
            .0
            .join(format!("sensitive-output-journal-v2-{capture_id}"));
        backend.launch_hook = Some(Box::new({
            let journal_directory = journal_directory.clone();
            move || {
                fs::set_permissions(&journal_directory, fs::Permissions::from_mode(0o500))
                    .expect("make generation-five append fail");
            }
        }));
        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        fs::set_permissions(&journal_directory, fs::Permissions::from_mode(0o700))
            .expect("restore journal directory mode for readback");
        assert!(matches!(
            outcome,
            ContainedExecutionOutcome::UnprovenAfterLaunch(_)
        ));
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 1);
        assert_post_match_failure_preserved_private_precleanup_with(
            &private.0,
            &capture_id,
            4,
            |stdout, stderr| {
                assert!(
                    !stdout.is_empty(),
                    "the scanner must release an ordinary prefix before the later marker"
                );
                assert!(ordinary_prefix.starts_with(&stdout));
                assert!(!stdout.windows(marker.len()).any(|window| window == marker));
                assert!(stderr.is_empty());
            },
        );
    }

    #[test]
    fn contained_execution_classifies_cleanup_failure_as_unproven_after_launch() {
        let limits = ResourceLimits {
            wall_time_ms: 1_000,
            max_output_bytes: 1024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("classified-cleanup-failure", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let terminal = DomainObservation {
            stdout: Vec::new(),
            stderr: Vec::new(),
            leader: Some(BackendTermination::Exited(0)),
            stdout_closed: true,
            stderr_closed: true,
            domain_empty: true,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [terminal]);
        backend.controls = contained_boundary::required_controls(limits);
        backend.cleanup_proof = None;

        let outcome =
            contained_boundary::execute_classified(backend, prepared, &CancellationToken::new());
        let ContainedExecutionOutcome::UnprovenAfterLaunch(error) = outcome else {
            panic!("cleanup-proof failure cannot produce terminal evidence")
        };
        assert!(
            error
                .to_string()
                .contains("without a validated cleanup proof")
        );
        assert_eq!(state.launch_count.load(Ordering::Acquire), 1);
        assert_eq!(state.poll_count.load(Ordering::Acquire), 1);
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 1);
    }

    #[test]
    fn contained_cleanup_deadline_is_checked_at_entry_and_after_terminal_poll() {
        for (label, clock_offsets_ms, expected_polls) in [
            ("entry", vec![0_u64, 0, 0, 2], 1_u64),
            ("after-poll", vec![0_u64, 0, 0, 0, 2], 2_u64),
        ] {
            let limits = ResourceLimits {
                wall_time_ms: 5_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            };
            let (_workspace, _private, paths, grant, policy, command) =
                contained_fixture(&format!("cleanup-deadline-{label}"), limits);
            let prepared =
                prepare_contained(grant, policy, &paths, &command).expect("prepare command");
            let leader_with_descendants = DomainObservation {
                stdout: Vec::new(),
                stderr: Vec::new(),
                leader: Some(BackendTermination::Exited(0)),
                stdout_closed: true,
                stderr_closed: true,
                domain_empty: false,
            };
            let delayed_terminal = DomainObservation {
                domain_empty: true,
                ..leader_with_descendants.clone()
            };
            let (mut backend, state) = FakeContainedBackend::ready_for(
                &prepared,
                [leader_with_descendants, delayed_terminal],
            );
            backend.controls = contained_boundary::required_controls(limits);
            let base = Instant::now();
            let mut scripted_times = clock_offsets_ms
                .into_iter()
                .map(|offset| base + Duration::from_millis(offset))
                .collect::<VecDeque<_>>();

            let outcome = contained_boundary::execute_classified_with_timing(
                backend,
                prepared,
                &CancellationToken::new(),
                Duration::from_millis(1),
                Duration::ZERO,
                move || {
                    scripted_times
                        .pop_front()
                        .expect("supervisor uses only the scripted deadline observations")
                },
            );
            let ContainedExecutionOutcome::UnprovenAfterLaunch(error) = outcome else {
                panic!("an expired cleanup deadline cannot terminalize")
            };
            assert!(error.to_string().contains("before the cleanup deadline"));
            assert_eq!(state.poll_count.load(Ordering::Acquire), expected_polls);
            assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn prepublish_commitment_mismatch_abandons_and_retains_structured_cleanup_authority() {
        let private = TestDirectory::new("prepublish-mismatch");
        let store = CapabilityCommandOutputStore::open(&private.0).expect("open output store");
        let source = CommandOutputArtifactSourceV1 {
            sprint_id: "sprint-prepublish-mismatch".into(),
            runner_launch_id: "launch-prepublish-mismatch".into(),
            runner_session_id: "session-prepublish-mismatch".into(),
            effect_id: "effect-prepublish-mismatch".into(),
            request_digest: Digest::sha256(b"request-prepublish-mismatch"),
        };
        let capture = store
            .reserve_capture(source.clone(), 6)
            .expect("reserve capture");
        let (mut stdout, mut stderr, publisher) = capture.split();
        stdout.append(b"out").expect("append stdout");
        stderr.append(b"err").expect("append stderr");
        let stdout = stdout.finish().expect("finish stdout");
        let stderr = stderr.finish().expect("finish stderr");
        let temp = fs::read_dir(&private.0)
            .expect("enumerate output store")
            .next()
            .expect("temporary reservation exists")
            .expect("read temporary reservation")
            .path();
        let unexpected = temp.join("unexpected");
        fs::write(&unexpected, b"retain on refused cleanup").expect("inject unknown entry");
        fs::set_permissions(&unexpected, fs::Permissions::from_mode(0o600))
            .expect("set unknown entry mode");
        let mismatched_stdout = CapturedOutput {
            bytes: b"out".to_vec(),
            complete_digest: Digest::sha256(b"different"),
            complete_length: 3,
            truncated: false,
        };
        let expected_stderr = CapturedOutput {
            bytes: b"err".to_vec(),
            complete_digest: Digest::sha256(b"err"),
            complete_length: 3,
            truncated: false,
        };

        let error = contained_boundary::publish_matching_output(
            publisher,
            stdout,
            stderr,
            &mismatched_stdout,
            &expected_stderr,
        )
        .expect_err("independent commitment mismatch must precede publication");
        let SupervisorError::CommandOutputCleanup { primary, cleanup } = error else {
            panic!("primary and cleanup errors must remain structurally distinct")
        };
        assert!(matches!(
            primary.as_ref(),
            SupervisorError::CommandOutputStore(CommandOutputStoreError::Reference(message))
                if message.contains("unpublished raw streams differ")
        ));
        assert!(matches!(
            cleanup.as_ref(),
            CommandOutputStoreError::ReconciliationRequired {
                source: retained_source,
                expected_reference: None,
                ..
            } if retained_source.as_ref() == &source
        ));
        assert_eq!(
            fs::read(&unexpected).expect("unknown entry survives refused cleanup"),
            b"retain on refused cleanup"
        );
        assert!(
            fs::read_dir(&private.0)
                .expect("enumerate after mismatch")
                .all(|entry| !entry
                    .expect("read retained entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with("command-output-")),
            "mismatched commitments must never expose a final artifact name"
        );
    }

    #[test]
    fn contained_preflight_rejects_extra_target_descriptor() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "descriptor-report",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, []);
        backend.descriptors.push(9);
        let error = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect_err("extra inherited descriptor must block launch");
        assert!(error.to_string().contains("expected [0, 1, 2]"));
        assert_eq!(state.launch_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn contained_terminal_retains_exact_validated_cleanup_proof() {
        let limits = ResourceLimits {
            wall_time_ms: 5_000,
            max_output_bytes: 1024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, private, paths, grant, policy, command) =
            contained_fixture("terminal-cleanup-proof", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let expected = crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(
            &test_command_cleanup_binding(&prepared),
        );
        let terminal = DomainObservation {
            stdout: Vec::new(),
            stderr: Vec::new(),
            leader: Some(BackendTermination::Exited(0)),
            stdout_closed: true,
            stderr_closed: true,
            domain_empty: true,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [terminal]);
        backend.controls = contained_boundary::required_controls(limits);
        backend.cleanup_proof = Some(expected.clone());

        let evidence = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect("terminal domain yields exact cleanup proof");
        assert_eq!(evidence.cleanup_proof(), &expected);
        assert_eq!(evidence.cleanup_proof().surviving_processes(), 0);
        evidence
            .cleanup_proof()
            .validate()
            .expect("retained cleanup proof remains canonical");
        let store = CapabilityCommandOutputStore::open(&private.0).expect("reopen output store");
        let recovery = store
            .reopen_capture(evidence.output_capture_id())
            .expect("reopen exact published command capture");
        assert_eq!(
            recovery.state(),
            crate::command_output_store::CommandOutputCaptureJournalStateV1::Published
        );
        assert_eq!(
            recovery.finished_store_head(),
            Some(evidence.output_capture_finished_store_head())
        );
        assert_eq!(
            recovery.published_store_head(),
            Some(evidence.output_capture_published_store_head())
        );
        assert_eq!(
            recovery.expected_reference(),
            Some(evidence.output_artifacts())
        );
        assert!(
            evidence
                .output_capture_launch_intended_store_head()
                .generation
                < evidence.output_capture_finished_store_head().generation
        );
        let terminal_observation = store
            .reopen_sensitive_output_terminal_observation_v1(evidence.output_capture_id())
            .expect("reopen clean terminal observation")
            .expect("clean execution publishes one terminal observation");
        terminal_observation
            .validate_expected(
                evidence.output_capture_id(),
                crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationBranchV1::Clean,
                evidence.backend().command_domain_backend(),
                evidence.cleanup_proof().binding(),
                evidence.cleanup_proof(),
            )
            .expect("clean sidecar rejoins exact live native proof");
        let clean = terminal_observation
            .clean_response()
            .expect("clean observation retains exact response reconstruction");
        assert_eq!(clean.output_artifacts(), evidence.output_artifacts());
        assert_eq!(clean.output_digest(), evidence.output_digest());
        assert_eq!(clean.launch_digest(), evidence.launch_digest());
        assert_eq!(clean.preflight_digest(), evidence.preflight_digest());
        assert_eq!(clean.duration_ms(), evidence.duration_ms());
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 1);
    }

    #[test]
    fn contained_terminal_rejects_invalid_backend_exit_and_signal_values() {
        for (label, leader, expected) in [
            (
                "negative-exit",
                BackendTermination::Exited(-1),
                "negative exit code",
            ),
            (
                "zero-signal",
                BackendTermination::Signaled(0),
                "nonpositive signal",
            ),
        ] {
            let limits = ResourceLimits {
                wall_time_ms: 5_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            };
            let (_workspace, _private, paths, grant, policy, command) =
                contained_fixture(label, limits);
            let prepared =
                prepare_contained(grant, policy, &paths, &command).expect("prepare command");
            let terminal = DomainObservation {
                stdout: Vec::new(),
                stderr: Vec::new(),
                leader: Some(leader),
                stdout_closed: true,
                stderr_closed: true,
                domain_empty: true,
            };
            let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [terminal]);
            backend.controls = contained_boundary::required_controls(limits);

            let error = contained_boundary::execute(backend, prepared, &CancellationToken::new())
                .expect_err("invalid backend terminal value must fail before evidence");
            assert!(error.to_string().contains(expected));
            assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn contained_capture_separates_policy_output_limit_from_wire_retention_limit() {
        let complete_length = MAX_INLINE_COMMAND_RETAINED_BYTES + 32 * 1024;
        let limits = ResourceLimits {
            wall_time_ms: 5_000,
            max_output_bytes: u64::try_from(complete_length + 32 * 1024)
                .expect("fixture output ceiling fits u64"),
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("wire-retention-ceiling", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let observations = [
            DomainObservation {
                stdout: vec![b'a'; 64 * 1024],
                stderr: Vec::new(),
                leader: None,
                stdout_closed: false,
                stderr_closed: false,
                domain_empty: false,
            },
            DomainObservation {
                stdout: vec![b'b'; 64 * 1024],
                stderr: Vec::new(),
                leader: None,
                stdout_closed: false,
                stderr_closed: false,
                domain_empty: false,
            },
            DomainObservation {
                stdout: vec![b'c'; 32 * 1024],
                stderr: Vec::new(),
                leader: Some(BackendTermination::Exited(0)),
                stdout_closed: true,
                stderr_closed: true,
                domain_empty: true,
            },
        ];
        let (mut backend, _state) = FakeContainedBackend::ready_for(&prepared, observations);
        backend.controls = contained_boundary::required_controls(limits);

        let evidence = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect("policy-admitted output terminalizes with bounded wire retention");
        assert_eq!(evidence.termination(), CommandTermination::Exited(0));
        assert_eq!(
            evidence.stdout().complete_length(),
            u64::try_from(complete_length).expect("fixture complete length fits u64")
        );
        assert_eq!(
            evidence.stdout().bytes().len(),
            MAX_INLINE_COMMAND_RETAINED_BYTES
        );
        assert!(evidence.stdout().truncated());
    }

    #[test]
    fn contained_domain_empty_without_cleanup_proof_cannot_terminalize() {
        let limits = ResourceLimits {
            wall_time_ms: 5_000,
            max_output_bytes: 1024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("missing-cleanup-proof", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let terminal = DomainObservation {
            stdout: Vec::new(),
            stderr: Vec::new(),
            leader: Some(BackendTermination::Exited(0)),
            stdout_closed: true,
            stderr_closed: true,
            domain_empty: true,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [terminal]);
        backend.controls = contained_boundary::required_controls(limits);
        backend.cleanup_proof = None;

        let error = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect_err("an empty-domain assertion without native proof must fail closed");
        assert!(
            error
                .to_string()
                .contains("without a validated cleanup proof")
        );
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 1);
    }

    #[test]
    fn contained_terminal_rejects_crossed_cleanup_bindings() {
        for (case, crossed) in [("session", 0_u8), ("effect", 1_u8), ("request", 2_u8)] {
            let limits = ResourceLimits {
                wall_time_ms: 5_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            };
            let (_workspace, _private, paths, grant, policy, command) =
                contained_fixture(&format!("crossed-cleanup-{case}"), limits);
            let prepared =
                prepare_contained(grant, policy, &paths, &command).expect("prepare command");
            let expected = test_command_cleanup_binding(&prepared);
            let crossed_binding = CommandDomainCleanupBinding::try_new(
                if crossed == 0 {
                    "crossed-runner-session"
                } else {
                    expected.runner_session_id()
                },
                if crossed == 1 {
                    "crossed-command-effect"
                } else {
                    expected.command_effect_id()
                },
                if crossed == 2 {
                    hash_bytes(b"crossed canonical command request")
                } else {
                    expected.command_request_digest().clone()
                },
            )
            .expect("crossed cleanup binding remains independently valid");
            let terminal = DomainObservation {
                stdout: Vec::new(),
                stderr: Vec::new(),
                leader: Some(BackendTermination::Exited(0)),
                stdout_closed: true,
                stderr_closed: true,
                domain_empty: true,
            };
            let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [terminal]);
            backend.controls = contained_boundary::required_controls(limits);
            backend.cleanup_proof = Some(
                crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&crossed_binding),
            );

            let error = contained_boundary::execute(backend, prepared, &CancellationToken::new())
                .expect_err("crossed native cleanup binding must fail terminalization");
            let SupervisorError::CommandOutputCleanup { primary, cleanup } = error else {
                panic!("crossed cleanup binding must retain primary and output custody errors")
            };
            assert!(matches!(
                primary.as_ref(),
                SupervisorError::CommandDomainCleanupProof(
                    CommandDomainCleanupProofError::ExpectedBindingMismatch
                )
            ));
            assert!(matches!(
                cleanup.as_ref(),
                CommandOutputStoreError::ReconciliationRequired { reason, .. }
                    if reason.contains("zero-first quarantine")
            ));
            assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 1);
        }
    }

    #[test]
    fn contained_terminal_rejects_crossed_cleanup_backend() {
        let limits = ResourceLimits {
            wall_time_ms: 5_000,
            max_output_bytes: 1024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("crossed-cleanup-backend", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let terminal = DomainObservation {
            stdout: Vec::new(),
            stderr: Vec::new(),
            leader: Some(BackendTermination::Exited(0)),
            stdout_closed: true,
            stderr_closed: true,
            domain_empty: true,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [terminal]);
        backend.controls = contained_boundary::required_controls(limits);
        backend.identity = BackendIdentity::new(
            CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            "fake-contained-v1",
            hash_bytes(b"fake backend"),
        );

        let error = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect_err("Linux proof cannot terminalize a macOS command domain");
        let SupervisorError::CommandOutputCleanup { primary, cleanup } = error else {
            panic!("crossed cleanup backend must retain primary and output custody errors")
        };
        assert!(matches!(
            primary.as_ref(),
            SupervisorError::CommandDomainCleanupProof(
                CommandDomainCleanupProofError::ExpectedBackendMismatch
            )
        ));
        assert!(matches!(
            cleanup.as_ref(),
            CommandOutputStoreError::ReconciliationRequired { reason, .. }
                if reason.contains("zero-first quarantine")
        ));
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 1);
    }

    #[test]
    fn contained_preflight_rejects_crossed_cleanup_backend_kind_before_launch() {
        let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
            "preflight-cleanup-backend",
            ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
        );
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, []);
        backend.reported_identity = Some(BackendIdentity::new(
            CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            backend.identity.backend_id().to_owned(),
            backend.identity.implementation_digest().clone(),
        ));

        let error = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect_err("preflight cleanup backend kind must match inspected backend");
        assert!(error.to_string().contains("preflight identity differs"));
        assert_eq!(state.launch_count.load(Ordering::Acquire), 0);
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 0);
    }

    #[test]
    fn contained_cleanup_proof_is_consumed_only_after_full_terminal_state() {
        let limits = ResourceLimits {
            wall_time_ms: 5_000,
            max_output_bytes: 1024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("cleanup-proof-order", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let observations = [
            DomainObservation {
                stdout: b"partial".to_vec(),
                stderr: Vec::new(),
                leader: None,
                stdout_closed: false,
                stderr_closed: false,
                domain_empty: false,
            },
            DomainObservation {
                stdout: Vec::new(),
                stderr: Vec::new(),
                leader: Some(BackendTermination::Exited(0)),
                stdout_closed: true,
                stderr_closed: true,
                domain_empty: true,
            },
        ];
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, observations);
        backend.controls = contained_boundary::required_controls(limits);

        let evidence = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect("proof joins only after complete terminal observation");
        assert_eq!(evidence.termination(), CommandTermination::Exited(0));
        assert_eq!(state.poll_count.load(Ordering::Acquire), 2);
        assert_eq!(state.cleanup_proof_consumptions.load(Ordering::Acquire), 1);
        assert_eq!(
            state.cleanup_proof_consumed_at_poll.load(Ordering::Acquire),
            2
        );
    }

    #[test]
    fn contained_cancellation_kills_and_proves_empty_the_descendant_domain() {
        let limits = ResourceLimits {
            wall_time_ms: 5_000,
            max_output_bytes: 1024,
            max_processes: 3,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("cancel-domain", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let cancellation = CancellationToken::new();
        let terminal = DomainObservation {
            stdout: b"partial stdout".to_vec(),
            stderr: b"partial stderr".to_vec(),
            leader: Some(BackendTermination::Signaled(9)),
            stdout_closed: true,
            stderr_closed: true,
            domain_empty: true,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [terminal]);
        backend.controls = contained_boundary::required_controls(limits);
        backend.cancel_on_launch = Some(cancellation.clone());
        let evidence = contained_boundary::execute(backend, prepared, &cancellation)
            .expect("cancel and reconcile domain");
        assert_eq!(evidence.termination(), CommandTermination::Cancelled);
        assert_eq!(evidence.stdout().bytes(), b"partial stdout");
        assert_eq!(evidence.stderr().bytes(), b"partial stderr");
        evidence
            .cleanup_proof()
            .validate()
            .expect("cancel terminal retains native cleanup proof");
        assert_eq!(
            *state
                .terminations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [DomainTerminationRequest::Cancelled]
        );
    }

    #[test]
    fn contained_normal_leader_exit_still_kills_remaining_descendants() {
        let limits = ResourceLimits {
            wall_time_ms: 5_000,
            max_output_bytes: 1024,
            max_processes: 3,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("orphan-domain", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let observations = [
            DomainObservation {
                stdout: b"done\n".to_vec(),
                stderr: Vec::new(),
                leader: Some(BackendTermination::Exited(0)),
                stdout_closed: true,
                stderr_closed: true,
                domain_empty: false,
            },
            DomainObservation {
                stdout: Vec::new(),
                stderr: Vec::new(),
                leader: Some(BackendTermination::Exited(0)),
                stdout_closed: true,
                stderr_closed: true,
                domain_empty: true,
            },
        ];
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, observations);
        backend.controls = contained_boundary::required_controls(limits);
        let evidence = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect("clean residual descendants");
        assert_eq!(evidence.termination(), CommandTermination::Exited(0));
        evidence
            .cleanup_proof()
            .validate()
            .expect("orphan cleanup retains native proof");
        assert_eq!(
            *state
                .terminations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [DomainTerminationRequest::LeaderExitedWithDescendants]
        );
    }

    #[test]
    fn contained_output_limit_retains_bounded_bytes_and_hashes_complete_streams() {
        let limits = ResourceLimits {
            wall_time_ms: 5_000,
            max_output_bytes: 4,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, private, paths, grant, policy, command) =
            contained_fixture("output-domain", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let observations = [
            DomainObservation {
                stdout: b"abcdef".to_vec(),
                stderr: b"xyz".to_vec(),
                leader: None,
                stdout_closed: false,
                stderr_closed: false,
                domain_empty: false,
            },
            DomainObservation {
                stdout: Vec::new(),
                stderr: Vec::new(),
                leader: Some(BackendTermination::Signaled(9)),
                stdout_closed: true,
                stderr_closed: true,
                domain_empty: true,
            },
        ];
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, observations);
        backend.controls = contained_boundary::required_controls(limits);
        let evidence = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect("terminate output overflow");
        assert_eq!(
            evidence.termination(),
            CommandTermination::OutputLimitExceeded
        );
        assert_eq!(evidence.stdout().bytes(), b"abcd");
        assert!(evidence.stdout().truncated());
        assert_eq!(evidence.stdout().complete_length(), 6);
        assert_eq!(evidence.stdout().complete_digest(), &hash_bytes(b"abcdef"));
        assert!(evidence.stderr().bytes().is_empty());
        assert_eq!(evidence.stderr().complete_length(), 3);
        assert_eq!(evidence.stderr().complete_digest(), &hash_bytes(b"xyz"));
        assert_ne!(evidence.output_digest(), &hash_bytes(b"abcdefxyz"));
        let artifacts = CapabilityCommandOutputStore::open(&private.0)
            .expect("reopen exact private artifact store")
            .reopen(evidence.output_artifacts())
            .expect("terminal evidence references exact immutable raw streams");
        let mut complete_stdout = Vec::new();
        let mut complete_stderr = Vec::new();
        artifacts
            .copy_stdout_to(&mut complete_stdout)
            .expect("copy complete stdout");
        artifacts
            .copy_stderr_to(&mut complete_stderr)
            .expect("copy complete stderr");
        assert_eq!(complete_stdout, b"abcdef");
        assert_eq!(complete_stderr, b"xyz");
        assert_eq!(
            evidence.output_artifacts().source.effect_id,
            "effect-command-test"
        );
        evidence
            .cleanup_proof()
            .validate()
            .expect("output-limit cleanup retains native proof");
        assert_eq!(
            *state
                .terminations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [DomainTerminationRequest::OutputLimitExceeded]
        );
    }
