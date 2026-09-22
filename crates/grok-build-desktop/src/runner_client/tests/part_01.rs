    use std::cell::{Cell, RefCell};
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        AcceptanceCriterion, AcceptanceKind, AgentEventKind, ApplicationReceipt,
        ApplicationValidationEvidence, ApplicationValidationMode, CommandDomainBackend,
        CommandDomainCleanupDisposition, CommandDomainCleanupProof,
        CommandOutputCaptureIntentAdmission, CommandOutputCaptureReconciliationAdmission,
        CommandOutputCaptureStoreHeadV1, CommandOutputCaptureTerminalAnchorV1,
        CommandOutputCaptureTerminalDispositionV1, CommandOutputCleanScanPublicationReceiptV1,
        CommandSpec, CompletionApplication, CompletionReceipt, CriterionEvidenceReceiptV2,
        DescriptorRelativeManifestEntry, DescriptorRelativeWorkspaceManifest, EffectObservation,
        EffectOutcome, ExecutionOrigin, ExecutionPolicyCompiler, ExecutionPolicyRequest,
        FileOperation, FinalReport, HumanAcceptanceDecisionOutcomeV1, LiveStateCaptureEvidence,
        LiveStateCaptureReceipt, PersistedEffect, PostCompletionRollbackCleanupEvidence,
        PostCompletionRollbackCleanupIntent, PostCompletionRollbackObservation,
        PostCompletionRollbackOutcome, PostCompletionRollbackOutcomeKind,
        PostCompletionRollbackTerminal, PostCompletionRollbackUnknownEvidence, ProviderProfile,
        RollbackReference, RollbackRequest, RollbackValidationEvidence, RollbackValidationMode,
        RunnerCleanupTerminalRecord, RunnerLaunchPreparationOutcome, SprintApplicationAdmission,
        SprintApplicationDispatchAdmission, SprintApplicationPreparation, SprintBudget,
        SprintFinalVerificationAdmission, SprintFinalVerificationDispatchAdmission,
        SprintLiveStateCaptureAdmission, SprintLiveStateCaptureDispatchAdmission,
        SprintLiveStateCapturePlan, SprintLiveStateCapturePlanCut, SprintSpec,
        TaskAttemptCandidateBoundary, TaskAttemptDisposition, TaskAttemptDispositionMetadata,
        TaskAttemptEvidence, TaskAttemptEvidenceKind, TaskAttemptFormalCheckAdmission,
        TaskAttemptIntegratedDisposition, TaskAttemptIntegrationAdmission,
        TaskAttemptTerminalEffect, TaskAttemptVerificationBoundary,
        TaskFormalCheckDispatchAdmission, TaskGraph, TaskIntegrationDispatchAdmission,
        TaskIntegrationEvidence, TaskIntegrationReceipt, TaskIntegrationValidationEvidence,
        TaskIntegrationValidationMode, TaskSpec, TaskState, VerificationReceipt,
        WorkerCleanupBackend, WorkerCleanupEvidence, WorkerCleanupReceipt, WorkerCleanupRequest,
        WorkspaceGrant, WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy,
        WorkspacePermissions, WorkspaceSnapshot,
    };
    use grok_build_providers::{ProviderToolCall, encode_tool_call, encode_tool_result};
    use grok_build_runner::{
        CONTAINED_CAPTURE_LAUNCH_SCHEMA, ClaimedCommandOutputV2TestProofBoxInput,
        CommandDomainCleanupBackend as RunnerCommandDomainCleanupBackend,
        CommandDomainCleanupBinding, CommandOutputCaptureJournalStateV1, RunnerResponseV12,
        SensitiveOutputCleanTestCutV1, SensitiveOutputRejectionTestCutV1, ShadowWorkspace,
        StageBundleReference, WireApplicationEvidence, WireCommandBackendIdentity,
        WireCommandCleanupProof, WireExplicitRollbackEvidence, WireRollbackArtifact,
        WireRollbackArtifactKind, WireRollbackArtifactReference, WireRollbackEvidence,
        WireRollbackExpectedEndpoint, WireRollbackLiveConflict, WireRollbackObservedEndpoint,
        WireRollbackPathConflict, WireRollbackPathObservation, WireRollbackTargetContract,
        WireWorkspaceCapture, WorkspaceManifest, complete_sensitive_output_clean_test_proof_box_v1,
        complete_sensitive_output_rejection_test_proof_box_v1,
        cut_sensitive_output_clean_test_proof_box_v1,
        cut_sensitive_output_rejection_test_proof_box_v1,
        cut_sensitive_output_split_launch_test_proof_box_v1, decode_request_frame,
        decode_request_frame_v12, encode_response_frame, encode_response_frame_v12,
    };

    use super::native_launch_service::{
        NativeCommandDomainCleanupObservation, NativeCommandDomainCleanupRequest,
        NativeLaunchCleanupReopenRequest, NativeLaunchCleanupReopener,
    };
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CleanupReopenClaimTrace {
        sprint_id: String,
        launch_id: String,
        session_id: String,
        cleanup_effect_id: String,
        next_event_sequence: u64,
    }

    struct ScriptedNativeCleanupReopener {
        authority: NativeLaunchCleanupAuthority,
        reopen_count: Rc<Cell<u64>>,
        cleanup_count: Rc<Cell<u64>>,
        mutation: ScriptedNativeCleanupMutation,
        claims: Rc<RefCell<Vec<CleanupReopenClaimTrace>>>,
    }

    impl NativeLaunchCleanupReopener for ScriptedNativeCleanupReopener {
        fn reopen_cleanup(
            &mut self,
            request: NativeLaunchCleanupReopenRequest<'_>,
        ) -> Result<Box<dyn NativeLaunchCleanupCustody>, LedgerError> {
            if request
                .expected_platform_binding()
                .is_some_and(|binding| self.authority.platform_binding() != binding)
            {
                return Err(LedgerError::ReferenceMismatch {
                    entity: "test native cleanup reopener",
                    detail: "retained platform binding crossed scripted journal authority".into(),
                });
            }
            self.reopen_count
                .set(self.reopen_count.get().saturating_add(1));
            let claim = request.claim();
            let admission = claim.admission();
            self.claims.borrow_mut().push(CleanupReopenClaimTrace {
                sprint_id: admission.launch.sprint_id.clone(),
                launch_id: admission.launch.launch_id.clone(),
                session_id: admission.launch.session_id.clone(),
                cleanup_effect_id: admission.cleanup_effect.intent.effect_id.clone(),
                next_event_sequence: claim.next_event_sequence(),
            });
            Ok(Box::new(ScriptedNativeCleanupCustody::new(
                self.authority.clone(),
                None,
                Rc::clone(&self.cleanup_count),
                self.mutation,
            )))
        }
    }

    /// Deliberately returns custody even when its authority crosses the
    /// caller's retained platform binding. Production must retain the returned
    /// move-only custody before rejecting it and must not enter native cleanup.
    struct UncheckedNativeCleanupReopener {
        authority: NativeLaunchCleanupAuthority,
        reopen_count: Rc<Cell<u64>>,
        cleanup_count: Rc<Cell<u64>>,
        claims: Rc<RefCell<Vec<CleanupReopenClaimTrace>>>,
    }

    impl NativeLaunchCleanupReopener for UncheckedNativeCleanupReopener {
        fn reopen_cleanup(
            &mut self,
            request: NativeLaunchCleanupReopenRequest<'_>,
        ) -> Result<Box<dyn NativeLaunchCleanupCustody>, LedgerError> {
            self.reopen_count
                .set(self.reopen_count.get().saturating_add(1));
            let claim = request.claim();
            let admission = claim.admission();
            self.claims.borrow_mut().push(CleanupReopenClaimTrace {
                sprint_id: admission.launch.sprint_id.clone(),
                launch_id: admission.launch.launch_id.clone(),
                session_id: admission.launch.session_id.clone(),
                cleanup_effect_id: admission.cleanup_effect.intent.effect_id.clone(),
                next_event_sequence: claim.next_event_sequence(),
            });
            Ok(Box::new(ScriptedNativeCleanupCustody::new(
                self.authority.clone(),
                None,
                Rc::clone(&self.cleanup_count),
                ScriptedNativeCleanupMutation::Exact,
            )))
        }
    }

    struct ClaimDerivedPreSessionCleanupReopener {
        reopen_count: Rc<Cell<u64>>,
        cleanup_count: Rc<Cell<u64>>,
        cross_authority_before_cleanup: bool,
    }

    impl NativeLaunchCleanupReopener for ClaimDerivedPreSessionCleanupReopener {
        fn reopen_cleanup(
            &mut self,
            request: NativeLaunchCleanupReopenRequest<'_>,
        ) -> Result<Box<dyn NativeLaunchCleanupCustody>, LedgerError> {
            self.reopen_count
                .set(self.reopen_count.get().saturating_add(1));
            let binding = request.expected_platform_binding().ok_or_else(|| {
                LedgerError::ReferenceMismatch {
                    entity: "test pre-session cleanup reopener",
                    detail: "pre-session cleanup omitted its exact platform binding".into(),
                }
            })?;
            let claim = request.claim();
            let mut authority = NativeLaunchCleanupAuthority::from_expected_state(
                claim.admission(),
                claim.preparation(),
                binding,
            );
            if self.cross_authority_before_cleanup {
                authority.expected_platform_binding_digest =
                    Digest::sha256(b"crossed-pre-session-cleanup-authority");
            }
            Ok(Box::new(ScriptedNativeCleanupCustody::new(
                authority,
                None,
                Rc::clone(&self.cleanup_count),
                ScriptedNativeCleanupMutation::Exact,
            )))
        }
    }

    struct ReusableScriptedNativeCleanupReopener {
        authorities: Vec<NativeLaunchCleanupAuthority>,
        reopen_count: Rc<Cell<u64>>,
        cleanup_count: Rc<Cell<u64>>,
        claims: Rc<RefCell<Vec<CleanupReopenClaimTrace>>>,
    }

    impl NativeLaunchCleanupReopener for ReusableScriptedNativeCleanupReopener {
        fn reopen_cleanup(
            &mut self,
            request: NativeLaunchCleanupReopenRequest<'_>,
        ) -> Result<Box<dyn NativeLaunchCleanupCustody>, LedgerError> {
            let claim = request.claim();
            let admission = claim.admission();
            let authority = self
                .authorities
                .iter()
                .find(|authority| authority.admission == *admission)
                .cloned()
                .ok_or_else(|| LedgerError::ReferenceMismatch {
                    entity: "test reusable native cleanup reopener",
                    detail: "no exact admitted launch authority for cleanup claim".into(),
                })?;
            if request
                .expected_platform_binding()
                .is_some_and(|binding| authority.platform_binding() != binding)
            {
                return Err(LedgerError::ReferenceMismatch {
                    entity: "test reusable native cleanup reopener",
                    detail: "retained platform binding crossed selected journal authority".into(),
                });
            }
            self.reopen_count
                .set(self.reopen_count.get().saturating_add(1));
            self.claims.borrow_mut().push(CleanupReopenClaimTrace {
                sprint_id: admission.launch.sprint_id.clone(),
                launch_id: admission.launch.launch_id.clone(),
                session_id: admission.launch.session_id.clone(),
                cleanup_effect_id: admission.cleanup_effect.intent.effect_id.clone(),
                next_event_sequence: claim.next_event_sequence(),
            });
            Ok(Box::new(ScriptedNativeCleanupCustody::new(
                authority,
                None,
                Rc::clone(&self.cleanup_count),
                ScriptedNativeCleanupMutation::Exact,
            )))
        }
    }

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    struct TestHarness {
        root: PathBuf,
        workspace: PathBuf,
        database: PathBuf,
        private_state: PathBuf,
        shadow: PathBuf,
        runner_binary: PathBuf,
        authority: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        sprint_id: String,
        sprint_spec: SprintSpec,
        base_snapshot: Digest,
        worker_lease: WorkerLease,
    }

    impl TestHarness {
        fn new(label: &str) -> (Self, EventLedger) {
            Self::new_with_acceptance(label, AcceptanceKind::HumanJudgment)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the durable runner fixture keeps authority, policy, sprint, snapshot, and filesystem setup visible"
        )]
        fn new_with_acceptance(
            label: &str,
            acceptance_kind: AcceptanceKind,
        ) -> (Self, EventLedger) {
            let unique = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let temporary = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
            let root = temporary.join(format!(
                "grok-build-runner-client-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create test root");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("secure test root");
            let workspace = root.join("workspace");
            fs::create_dir(&workspace).expect("create workspace");
            fs::create_dir(workspace.join("src")).expect("create source directory");
            fs::write(workspace.join("README.md"), b"runner-client-fixture\n")
                .expect("write fixture");
            let private_state = root.join("private");
            fs::create_dir(&private_state).expect("create private state");
            fs::set_permissions(&private_state, fs::Permissions::from_mode(0o700))
                .expect("secure private state");
            let shadow = private_state.join("worker-shadow");
            fs::create_dir(&shadow).expect("create fixed shadow root");
            let authority = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: format!("grant-{label}-{unique}"),
                workspace_root: workspace.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
            })
            .expect("issue test grant");
            let policy = ExecutionPolicyCompiler::compile(
                &authority,
                ExecutionPolicyRequest {
                    policy_id: format!("policy-{label}-{unique}"),
                    read_scopes: vec![PathScope::Workspace],
                    write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                    environment: Vec::new(),
                    network: ExecutionNetwork::None,
                    mutation_mode: MutationMode::ShadowWorkspace,
                    resource_limits: ResourceLimits {
                        wall_time_ms: 30_000,
                        max_output_bytes: 1024 * 1024,
                        max_processes: 1,
                        max_memory_bytes: None,
                    },
                    approval_id: None,
                },
            )
            .expect("compile test policy");
            let base_snapshot = Digest::sha256(format!("base-{label}-{unique}").as_bytes());
            let sprint_id = format!("sprint-{label}-{unique}");
            let spec = SprintSpec {
                sprint_id: sprint_id.clone(),
                objective: "exercise the desktop runner lifecycle".into(),
                acceptance_criteria: vec![AcceptanceCriterion {
                    criterion_id: "criterion-1".into(),
                    description: "runner lifecycle evidence is exact".into(),
                    kind: acceptance_kind,
                }],
                provider: ProviderProfile {
                    backend_id: "test-provider".into(),
                    model_id: "test-model".into(),
                    execution_origin: ExecutionOrigin::HostIsolated,
                },
                budget: SprintBudget {
                    max_tasks: 1,
                    max_attempts_per_task: 1,
                    max_tool_calls: 8,
                    max_duration_ms: 30_000,
                },
                max_workers: 1,
                workspace_grant: authority.contract().clone(),
                base_snapshot: base_snapshot.clone(),
            };
            let graph = TaskGraph {
                graph_id: format!("graph-{label}-{unique}"),
                tasks: vec![TaskSpec {
                    task_id: "task-1".into(),
                    goal: "read one fixture file".into(),
                    dependencies: Vec::new(),
                    path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                    acceptance_checks: vec!["criterion-1".into()],
                    base_snapshot: base_snapshot.clone(),
                    required: true,
                }],
            };
            let state = root.join("state");
            fs::create_dir(&state).expect("create state directory");
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
                .expect("secure state directory");
            let database = state.join("ledger.sqlite3");
            let mut ledger = EventLedger::open(&database).expect("open test ledger");
            ledger
                .create_sprint(&spec, &graph, 1_000)
                .expect("create test sprint");
            let ready_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger
                    .next_sequence(&sprint_id)
                    .expect("next ready sequence"),
                event_id: format!("task-ready-{label}-{unique}"),
                sprint_id: sprint_id.clone(),
                task_id: Some("task-1".into()),
                worker_id: None,
                causation_id: None,
                correlation_id: format!("worker-lease-{label}-{unique}"),
                policy_hash: Some(policy.contract().policy_hash.clone()),
                occurred_at_unix_ms: 1_002,
                payload: AgentEventKind::TaskStateChanged {
                    from: "Planned".into(),
                    to: "Ready".into(),
                },
            };
            ledger
                .append_event(&ready_event)
                .expect("make fixture task ready");
            let worker_lease = WorkerLease::new(
                sprint_id.clone(),
                ledger
                    .next_worker_lease_epoch(&sprint_id)
                    .expect("next fixture worker lease epoch"),
                "task-1".into(),
                "worker-1".into(),
                graph.tasks[0].path_scopes.clone(),
                1_003,
            )
            .expect("construct canonical fixture worker lease");
            let leased_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger
                    .next_sequence(&sprint_id)
                    .expect("next leased sequence"),
                event_id: format!("task-leased-{label}-{unique}"),
                sprint_id: sprint_id.clone(),
                task_id: Some("task-1".into()),
                worker_id: Some("worker-1".into()),
                causation_id: Some(ready_event.event_id),
                correlation_id: format!("worker-lease-{label}-{unique}"),
                policy_hash: Some(policy.contract().policy_hash.clone()),
                occurred_at_unix_ms: worker_lease.acquired_at_unix_ms,
                payload: AgentEventKind::TaskStateChanged {
                    from: "Ready".into(),
                    to: "Leased".into(),
                },
            };
            let worker_lease = ledger
                .acquire_task_attempt(&worker_lease, &leased_event)
                .expect("atomically acquire canonical fixture task attempt")
                .worker_lease;
            ledger
                .persist_workspace_snapshot(
                    &sprint_id,
                    &WorkspaceSnapshot {
                        snapshot_id: base_snapshot.clone(),
                        grant_hash: authority.contract().grant_hash.clone(),
                        created_at_unix_ms: 1_001,
                    },
                )
                .expect("persist base snapshot");
            let runner_binary = fs::canonicalize(std::env::current_exe().expect("test binary"))
                .expect("canonical test binary");
            (
                Self {
                    root,
                    workspace,
                    database,
                    private_state,
                    shadow,
                    runner_binary,
                    authority,
                    policy,
                    sprint_id,
                    sprint_spec: spec,
                    base_snapshot,
                    worker_lease,
                },
                ledger,
            )
        }

        fn launch(&self, suffix: &str) -> RunnerClientLaunch {
            RunnerClientLaunch {
                launch_id: format!("launch-{suffix}"),
                session_id: format!("session-{suffix}"),
                sprint_id: self.sprint_id.clone(),
                sprint_spec: self.sprint_spec.clone(),
                role: RunnerRole::Worker,
                worker_id: Some("worker-1".into()),
                worker_lease: Some(self.worker_lease.clone()),
                runner_binary: self.runner_binary.clone(),
                private_state_root: self.private_state.clone(),
                shadow_root: Some(self.shadow.clone()),
                expected_base_snapshot: self.base_snapshot.clone(),
                created_at_unix_ms: 1_100,
            }
        }

        fn identity(&self) -> WireRootIdentity {
            WireRootIdentity {
                device_id: self.authority.identity().device_id(),
                inode: self.authority.identity().inode(),
            }
        }
    }

    impl Drop for TestHarness {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn admit_sessionless_lifecycle_worker_launch(
        harness: &TestHarness,
        ledger: &mut EventLedger,
    ) -> PersistedRunnerLaunchCleanupAdmission {
        let history = ledger
            .load_task_attempt_history(&harness.sprint_id, "task-1")
            .expect("load exact active fixture attempt");
        let attempt = &history
            .active_attempt()
            .expect("fixture retains one active attempt")
            .attempt;
        let mut request = harness.launch("pre-session-unused");
        request.launch_id = format!("{}:worker-launch-v1", attempt.attempt_id);
        request.session_id = format!("{}:worker-session-v1", attempt.attempt_id);
        let prepared = prepare_launch(&harness.authority, &harness.policy, &request)
            .expect("prepare deterministic lifecycle worker launch");
        let cleanup = prepare_ordinary_launch_cleanup(
            ledger,
            &prepared.intent,
            &request.expected_base_snapshot,
        )
        .expect("prepare deterministic worker cleanup admission");
        ledger
            .admit_runner_launch_with_cleanup(
                &prepared.intent,
                &harness.policy,
                &cleanup.intent,
                &cleanup.request_bytes,
                &cleanup.event,
            )
            .expect("admit sessionless lifecycle worker launch")
    }

    #[derive(Clone, Copy)]
    enum ScriptMode {
        Good,
        BadReceipt,
        BadSprintReceipt,
        BadRoleInputReceipt,
        EofAt(u64),
        WriteFailureAt(u64, ScriptWriteProgress),
        UncorrelatedAt(u64),
        SemanticRejectionAt(u64),
        BeforeEffectAt(u64),
        MissingResponseStream,
    }

    #[derive(Clone, Copy)]
    enum ScriptWriteProgress {
        None,
        One,
        AllButOne,
        All,
    }

    struct ScriptedCleanCommandV12 {
        private_state_root: PathBuf,
        backend: WireCommandBackendIdentity,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    struct ScriptedTransport {
        nonce: Digest,
        workspace_identity: WireRootIdentity,
        mode: ScriptMode,
        role: Option<RunnerRole>,
        capture_snapshot: Option<Digest>,
        capture_grant_hash: Option<Digest>,
        private_shadow_present: bool,
        read_bytes: Vec<u8>,
        exchange_count: Option<Rc<Cell<u64>>>,
        rollback_response: Option<RunnerResponse>,
        worker_response: Option<RunnerResponse>,
        before_first_exchange: Option<Box<dyn FnOnce()>>,
        clean_command_v12: Option<ScriptedCleanCommandV12>,
        /// Worker commands this scripted peer served, mirroring the runner's
        /// own `command_effects_admitted`: the production seam builds exactly
        /// one command job per admitted `WorkerRunCommand`, so a peer that
        /// still reported zero would be scripting a runner that no longer
        /// exists and would defeat the client's exact admission correlation.
        worker_commands_served: u64,
    }

    impl ScriptedTransport {
        fn new(
            nonce: Digest,
            workspace_identity: WireRootIdentity,
            mode: ScriptMode,
            private_shadow_present: bool,
            read_bytes: Vec<u8>,
        ) -> Self {
            Self {
                nonce,
                workspace_identity,
                mode,
                role: None,
                capture_snapshot: None,
                capture_grant_hash: None,
                private_shadow_present,
                read_bytes,
                exchange_count: None,
                rollback_response: None,
                worker_response: None,
                before_first_exchange: None,
                clean_command_v12: None,
                worker_commands_served: 0,
            }
        }

        fn with_exchange_count(mut self, exchange_count: Rc<Cell<u64>>) -> Self {
            self.exchange_count = Some(exchange_count);
            self
        }

        fn with_rollback_response(mut self, response: RunnerResponse) -> Self {
            self.rollback_response = Some(response);
            self
        }

        fn with_worker_response(mut self, response: RunnerResponse) -> Self {
            self.worker_response = Some(response);
            self
        }

        fn with_before_first_exchange(mut self, hook: impl FnOnce() + 'static) -> Self {
            self.before_first_exchange = Some(Box::new(hook));
            self
        }

        fn with_clean_command_v12(
            mut self,
            private_state_root: PathBuf,
            backend: WireCommandBackendIdentity,
            stdout: Vec<u8>,
            stderr: Vec<u8>,
        ) -> Self {
            self.clean_command_v12 = Some(ScriptedCleanCommandV12 {
                private_state_root,
                backend,
                stdout,
                stderr,
            });
            self
        }

        fn response(
            &self,
            request: &RunnerRequestEnvelope,
            response: RunnerResponse,
        ) -> Result<Vec<u8>, RunnerClientError> {
            let envelope = RunnerResponseEnvelope {
                protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
                session_id: request.session_id.clone(),
                runner_nonce: self.nonce.clone(),
                sequence: request.sequence,
                request_id: request.request_id.clone(),
                effect: request.effect.clone(),
                response,
            };
            Ok(encode_response_frame(&envelope)?)
        }
    }

    impl RunnerTransport for ScriptedTransport {
        fn precheck_effect_exchange(&self) -> Result<(), RunnerClientError> {
            if matches!(self.mode, ScriptMode::MissingResponseStream) {
                return Err(RunnerClientError::InvalidLifecycle(
                    "runner stdout is already closed".into(),
                ));
            }
            Ok(())
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the fake transport mirrors every closed response variant and exact initialization echo in one contract fixture"
        )]
        fn exchange_frame(
            &mut self,
            outbound: &[u8],
            _deadline: Instant,
        ) -> Result<Vec<u8>, RunnerTransportExchangeFailure> {
            if self.role.is_some() && self.clean_command_v12.is_some() {
                let result = (|| -> Result<Vec<u8>, RunnerClientError> {
                    if let Some(hook) = self.before_first_exchange.take() {
                        hook();
                    }
                    let request = decode_request_frame_v12(outbound)?;
                    if let Some(exchange_count) = &self.exchange_count {
                        exchange_count.set(
                            exchange_count
                                .get()
                                .checked_add(1)
                                .expect("bounded scripted exchange count"),
                        );
                    }
                    let expected_role = match request.request.command_request() {
                        RunnerRequest::WorkerRunCommand { .. } => {
                            self.worker_commands_served = self
                                .worker_commands_served
                                .checked_add(1)
                                .expect("bounded scripted worker command count");
                            RunnerRole::Worker
                        }
                        RunnerRequest::FinalVerifierRunCommand { .. } => RunnerRole::FinalVerifier,
                        _ => {
                            return Err(RunnerClientError::InvalidLifecycle(
                                "scripted v12 proof box received a non-command request".into(),
                            ));
                        }
                    };
                    if self.role != Some(expected_role) {
                        return Err(RunnerClientError::InvalidLifecycle(
                            "scripted v12 proof box request crossed the initialized runner role"
                                .into(),
                        ));
                    }
                    let acquired = match request.request.command_request() {
                        RunnerRequest::WorkerRunCommand { output_capture, .. }
                        | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
                            output_capture.acquired().clone()
                        }
                        _ => unreachable!("role-exact command was already established"),
                    };
                    let grant_hash = self.capture_grant_hash.clone().ok_or_else(|| {
                        RunnerClientError::InvalidLifecycle(
                            "scripted v12 proof box lacks initialized workspace-grant authority"
                                .into(),
                        )
                    })?;
                    let scripted = self.clean_command_v12.take().ok_or_else(|| {
                        RunnerClientError::InvalidLifecycle(
                            "scripted v12 proof box was already consumed".into(),
                        )
                    })?;
                    let proof_box = complete_sensitive_output_clean_test_proof_box_v1(
                        ClaimedCommandOutputV2TestProofBoxInput {
                            private_state_root: scripted.private_state_root,
                            grant_hash,
                            acquired,
                            request,
                            termination: CommandTerminationV1::Exited { code: 0 },
                            backend: scripted.backend,
                        },
                        &scripted.stdout,
                        &scripted.stderr,
                    )
                    .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
                    Ok(encode_response_frame_v12(proof_box.response())?)
                })();
                return result.map_err(|error| {
                    RunnerTransportExchangeFailure::completed(error, outbound.len())
                });
            }
            if let ScriptMode::WriteFailureAt(sequence, progress) = self.mode {
                let request = decode_request_frame(outbound).map_err(|error| {
                    RunnerTransportExchangeFailure::completed(error.into(), outbound.len())
                })?;
                if request.sequence == sequence {
                    if let Some(hook) = self.before_first_exchange.take() {
                        hook();
                    }
                    if let Some(exchange_count) = &self.exchange_count {
                        exchange_count.set(
                            exchange_count
                                .get()
                                .checked_add(1)
                                .expect("bounded scripted exchange count"),
                        );
                    }
                    let written = match progress {
                        ScriptWriteProgress::None => 0,
                        ScriptWriteProgress::One => 1,
                        ScriptWriteProgress::AllButOne => outbound.len().saturating_sub(1),
                        ScriptWriteProgress::All => outbound.len(),
                    };
                    return Err(RunnerTransportExchangeFailure::new(
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "scripted claimed effect transport failure",
                        )
                        .into(),
                        written,
                        outbound.len(),
                    ));
                }
            }
            let result = (|| -> Result<Vec<u8>, RunnerClientError> {
                if let Some(hook) = self.before_first_exchange.take() {
                    hook();
                }
                let request = decode_request_frame(outbound)?;
                if let Some(exchange_count) = &self.exchange_count {
                    exchange_count.set(
                        exchange_count
                            .get()
                            .checked_add(1)
                            .expect("bounded scripted exchange count"),
                    );
                }
                if matches!(self.mode, ScriptMode::EofAt(sequence) if sequence == request.sequence)
                {
                    return Ok(Vec::new());
                }
                match &request.request {
                    RunnerRequest::InitializeSession {
                        launch_id,
                        sprint_id,
                        expected_sprint_spec_digest,
                        logical_worker_id,
                        worker_lease,
                        role,
                        role_input_authority,
                        workspace_grant,
                        execution_policy_request,
                        expected_policy_hash,
                        expected_base_snapshot,
                        expected_private_state_digest,
                        expected_binary_digest,
                        expected_binary_identity,
                        ..
                    } => {
                        self.role = Some(*role);
                        self.capture_snapshot = Some(expected_base_snapshot.clone());
                        self.capture_grant_hash = Some(workspace_grant.grant_hash.clone());
                        let mut receipt = InitializationReceipt {
                            runner_nonce: self.nonce.clone(),
                            launch_id: launch_id.clone(),
                            sprint_id: sprint_id.clone(),
                            sprint_spec_digest: expected_sprint_spec_digest.clone(),
                            logical_worker_id: logical_worker_id.clone(),
                            worker_lease: worker_lease.clone(),
                            role: *role,
                            role_input_authority: role_input_authority.clone(),
                            grant_id: workspace_grant.grant_id.clone(),
                            canonical_root: workspace_grant.canonical_root.clone(),
                            grant_hash: workspace_grant.grant_hash.clone(),
                            policy_id: execution_policy_request.policy_id.clone(),
                            policy_hash: expected_policy_hash.clone(),
                            expected_base_snapshot: expected_base_snapshot.clone(),
                            workspace_identity: self.workspace_identity,
                            private_state_digest: expected_private_state_digest.clone(),
                            binary_digest: expected_binary_digest.clone(),
                            binary_identity: *expected_binary_identity,
                            protocol_digest: runner_protocol_digest(),
                        };
                        if matches!(self.mode, ScriptMode::BadReceipt) {
                            receipt.grant_id = "different-grant".into();
                        }
                        if matches!(self.mode, ScriptMode::BadSprintReceipt) {
                            receipt.sprint_spec_digest =
                                Digest::sha256(b"substituted sprint receipt");
                        }
                        if matches!(self.mode, ScriptMode::BadRoleInputReceipt) {
                            receipt.role_input_authority = RunnerRoleInputAuthority::PlanningBase;
                        }
                        self.response(&request, RunnerResponse::Initialized { receipt })
                    }
                    RunnerRequest::WorkerReadFile { path, .. } => {
                        if let Some(response) = &self.worker_response {
                            return self.response(&request, response.clone());
                        }
                        if matches!(self.mode, ScriptMode::BeforeEffectAt(sequence) if sequence == request.sequence)
                        {
                            self.response(
                                &request,
                                RunnerResponse::Failed {
                                    code: "scripted_before_effect".into(),
                                    class: WireFailureClass::BeforeEffect,
                                    reconciliation: None,
                                    message: "scripted typed refusal".into(),
                                },
                            )
                        } else {
                            let returned_path = if matches!(self.mode, ScriptMode::SemanticRejectionAt(sequence) if sequence == request.sequence)
                            {
                                "crossed-response-path".into()
                            } else {
                                path.clone()
                            };
                            let bytes = self.read_bytes.clone();
                            let frame = self.response(
                                &request,
                                RunnerResponse::FileRead {
                                    path: returned_path,
                                    digest: Digest::sha256(&bytes),
                                    bytes,
                                },
                            )?;
                            if matches!(self.mode, ScriptMode::UncorrelatedAt(sequence) if sequence == request.sequence)
                            {
                                let mut crossed = decode_response_frame(&frame)?;
                                crossed.request_id.push_str("-crossed");
                                Ok(encode_response_frame(&crossed)?)
                            } else {
                                Ok(frame)
                            }
                        }
                    }
                    RunnerRequest::WorkerSearchLiteral { .. } => {
                        let response = self.worker_response.clone().ok_or_else(|| {
                            RunnerClientError::InvalidLifecycle(
                                "scripted search requires one exact worker response".into(),
                            )
                        })?;
                        self.response(&request, response)
                    }
                    RunnerRequest::WorkerStageChanges {
                        expected_bundle, ..
                    } => {
                        let response = self.worker_response.clone().unwrap_or_else(|| {
                            RunnerResponse::StageBundlePersisted {
                                bundle: expected_bundle.clone(),
                            }
                        });
                        self.response(&request, response)
                    }
                    RunnerRequest::ApplierRecoverPending => self.response(
                        &request,
                        RunnerResponse::RecoveryCompleted {
                            recovered_change_sets: Vec::new(),
                            abandoned_preparations: Vec::new(),
                        },
                    ),
                    RunnerRequest::ApplierCaptureLive { created_at_unix_ms } => {
                        let snapshot_id = self.capture_snapshot.clone().ok_or_else(|| {
                            RunnerClientError::InvalidLifecycle(
                                "scripted Applier capture is missing initialized snapshot authority"
                                    .into(),
                            )
                        })?;
                        let grant_hash = self.capture_grant_hash.clone().ok_or_else(|| {
                            RunnerClientError::InvalidLifecycle(
                                "scripted Applier capture is missing initialized grant authority"
                                    .into(),
                            )
                        })?;
                        let entry_count = 0_u64;
                        let mut preimage = b"grok-build/workspace-capture/v1\0".to_vec();
                        preimage.extend_from_slice(snapshot_id.as_str().as_bytes());
                        preimage.extend_from_slice(grant_hash.as_str().as_bytes());
                        preimage.extend_from_slice(&created_at_unix_ms.to_be_bytes());
                        preimage.extend_from_slice(&entry_count.to_be_bytes());
                        self.response(
                            &request,
                            RunnerResponse::WorkspaceCaptured {
                                capture: WireWorkspaceCapture {
                                    snapshot_id,
                                    grant_hash,
                                    created_at_unix_ms: *created_at_unix_ms,
                                    entry_count,
                                    capture_digest: Digest::sha256(&preimage),
                                },
                            },
                        )
                    }
                    RunnerRequest::ApplierApplyBundle { .. } => {
                        let response = self.worker_response.clone().ok_or_else(|| {
                            RunnerClientError::InvalidLifecycle(
                                "scripted application requires one exact effect response".into(),
                            )
                        })?;
                        self.response(&request, response)
                    }
                    RunnerRequest::LiveStateVerifierCapture { .. } => {
                        let response = self.worker_response.clone().ok_or_else(|| {
                            RunnerClientError::InvalidLifecycle(
                                "scripted live-state capture requires one exact effect response"
                                    .into(),
                            )
                        })?;
                        self.response(&request, response)
                    }
                    RunnerRequest::ApplierRollback { .. } => {
                        let response = self.rollback_response.clone().unwrap_or_else(|| {
                            RunnerResponse::Failed {
                                code: "rollback_precondition_rejected".into(),
                                class: WireFailureClass::BeforeEffect,
                                reconciliation: None,
                                message: "typed fixture refusal before effect".into(),
                            }
                        });
                        self.response(&request, response)
                    }
                    RunnerRequest::Shutdown => {
                        let acknowledgement = ShutdownPreparedAcknowledgement::new(
                            &request.session_id,
                            self.nonce.clone(),
                            self.role.expect("initialized fake role"),
                            request.sequence.checked_add(1).expect("bounded sequence"),
                            self.worker_commands_served,
                            self.private_shadow_present,
                        );
                        self.response(
                            &request,
                            RunnerResponse::ShutdownPrepared { acknowledgement },
                        )
                    }
                    _ => Err(RunnerClientError::InvalidLifecycle(
                        "scripted peer received an unsupported request".into(),
                    )),
                }
            })();
            result.map_err(|error| RunnerTransportExchangeFailure::completed(error, outbound.len()))
        }

        fn finish_direct(self: Box<Self>) -> DirectChildOutcome {
            DirectChildOutcome::Exited {
                code: Some(0),
                success: true,
            }
        }
    }

    fn transport(
        nonce: Digest,
        identity: WireRootIdentity,
        mode: ScriptMode,
        private_shadow_present: bool,
        read_bytes: Vec<u8>,
    ) -> impl FnOnce(
        &mut RetainedRunnerExecutable,
        Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError> {
        move |_, expected_binding| {
            Ok(RunnerSpawnOutcome {
                process: Box::new(ScriptedTransport::new(
                    nonce,
                    identity,
                    mode,
                    private_shadow_present,
                    read_bytes,
                )),
                platform_binding: expected_binding.cloned().map(Box::new),
                native_cleanup_custody: None,
            })
        }
    }

    fn transport_with_exchange_count(
        nonce: Digest,
        identity: WireRootIdentity,
        mode: ScriptMode,
        private_shadow_present: bool,
        read_bytes: Vec<u8>,
        exchange_count: Rc<Cell<u64>>,
    ) -> impl FnOnce(
        &mut RetainedRunnerExecutable,
        Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError> {
        move |_, expected_binding| {
            Ok(RunnerSpawnOutcome {
                process: Box::new(
                    ScriptedTransport::new(
                        nonce,
                        identity,
                        mode,
                        private_shadow_present,
                        read_bytes,
                    )
                    .with_exchange_count(exchange_count),
                ),
                platform_binding: expected_binding.cloned().map(Box::new),
                native_cleanup_custody: None,
            })
        }
    }

    fn transport_with_clean_command_v12(
        nonce: Digest,
        identity: WireRootIdentity,
        private_state_root: PathBuf,
        backend: WireCommandBackendIdentity,
        exchange_count: Rc<Cell<u64>>,
    ) -> impl FnOnce(
        &mut RetainedRunnerExecutable,
        Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError> {
        move |_, expected_binding| {
            Ok(RunnerSpawnOutcome {
                process: Box::new(
                    ScriptedTransport::new(nonce, identity, ScriptMode::Good, true, Vec::new())
                        .with_exchange_count(exchange_count)
                        .with_clean_command_v12(
                            private_state_root,
                            backend,
                            b"formal check stdout\n".to_vec(),
                            Vec::new(),
                        ),
                ),
                platform_binding: expected_binding.cloned().map(Box::new),
                native_cleanup_custody: None,
            })
        }
    }

    fn transport_with_worker_response(
        nonce: Digest,
        identity: WireRootIdentity,
        response: RunnerResponse,
        exchange_count: Rc<Cell<u64>>,
    ) -> impl FnOnce(
        &mut RetainedRunnerExecutable,
        Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError> {
        move |_, expected_binding| {
            Ok(RunnerSpawnOutcome {
                process: Box::new(
                    ScriptedTransport::new(nonce, identity, ScriptMode::Good, true, Vec::new())
                        .with_exchange_count(exchange_count)
                        .with_worker_response(response),
                ),
                platform_binding: expected_binding.cloned().map(Box::new),
                native_cleanup_custody: None,
            })
        }
    }

    fn transport_with_optional_effect_response(
        nonce: Digest,
        identity: WireRootIdentity,
        mode: ScriptMode,
        response: Option<RunnerResponse>,
        exchange_count: Rc<Cell<u64>>,
    ) -> impl FnOnce(
        &mut RetainedRunnerExecutable,
        Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError> {
        move |_, expected_binding| {
            let mut scripted = ScriptedTransport::new(nonce, identity, mode, false, Vec::new())
                .with_exchange_count(exchange_count);
            if let Some(response) = response {
                scripted = scripted.with_worker_response(response);
            }
            Ok(RunnerSpawnOutcome {
                process: Box::new(scripted),
                platform_binding: expected_binding.cloned().map(Box::new),
                native_cleanup_custody: None,
            })
        }
    }

    fn precommit_worker_read(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        client: &RunnerLifecycleClient,
        suffix: &str,
    ) -> (
        PersistedEffect,
        FreshRunnerEffectDispatchPermit,
        EffectIntent,
        Vec<u8>,
        RunnerRequest,
    ) {
        let idempotency_key = format!("key-precommitted-read-{suffix}");
        let request_bytes =
            provider_read_request_bytes(harness, &idempotency_key, "README.md", 1_024);
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("effect-precommitted-read-{suffix}"),
            idempotency_key: task_lease_provider_call_effect_key(
                &harness.worker_lease.lease_id,
                &idempotency_key,
            ),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(harness.worker_lease.clone()),
            causation_event_id: None,
            correlation_id: format!("correlation-precommitted-read-{suffix}"),
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
                .expect("next precommitted read proposal sequence"),
        );
        let (persisted, permit) = ledger
            .record_runner_effect_intent_for_dispatch(
                &intent,
                &request_bytes,
                &event,
                &client.session().session_id,
            )
            .expect("commit fresh read and mint its one-use dispatch permit");
        (
            persisted,
            permit,
            intent,
            request_bytes,
            RunnerRequest::WorkerReadFile {
                path: "README.md".into(),
                max_bytes: 1_024,
            },
        )
    }

    fn precommit_worker_search(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        client: &RunnerLifecycleClient,
        suffix: &str,
    ) -> (
        PersistedEffect,
        FreshRunnerEffectDispatchPermit,
        EffectIntent,
        Vec<u8>,
        RunnerRequest,
    ) {
        let idempotency_key = format!("key-precommitted-search-{suffix}");
        let call = ProviderToolCall {
            sprint_id: harness.sprint_id.clone(),
            task_id: "task-1".into(),
            sequence: 1,
            call_id: format!("{idempotency_key}-call"),
            idempotency_key: idempotency_key.clone(),
            intent: ProviderToolIntent::SearchLiteral {
                path: PathBuf::from("README.md"),
                literal: "needle".into(),
                max_matches: 1,
            },
        };
        let request_bytes = encode_tool_call(&call).expect("encode canonical provider search call");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("effect-precommitted-search-{suffix}"),
            idempotency_key: task_lease_provider_call_effect_key(
                &harness.worker_lease.lease_id,
                &idempotency_key,
            ),
            sprint_id: harness.sprint_id.clone(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(harness.worker_lease.clone()),
            causation_event_id: None,
            correlation_id: format!("correlation-precommitted-search-{suffix}"),
            kind: EffectKind::SearchLiteral,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: harness.policy.contract().policy_hash.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            created_at_unix_ms: client.session().registered_at_unix_ms + 1,
        };
        let event = proposal(
            &intent,
            ledger
                .next_sequence(&harness.sprint_id)
                .expect("next precommitted search proposal sequence"),
        );
        let (persisted, permit) = ledger
            .record_runner_effect_intent_for_dispatch(
                &intent,
                &request_bytes,
                &event,
                &client.session().session_id,
            )
            .expect("commit fresh search and mint its one-use dispatch permit");
        (
            persisted,
            permit,
            intent,
            request_bytes,
            RunnerRequest::WorkerSearchLiteral {
                path: "README.md".into(),
                needle: b"needle".to_vec(),
                max_bytes: u64::try_from(MAX_PROVIDER_FILE_BYTES)
                    .expect("provider file bound fits u64"),
                max_matches: 1,
            },
        )
    }

    fn provider_read_request_bytes(
        harness: &TestHarness,
        idempotency_key: &str,
        path: &str,
        max_bytes: usize,
    ) -> Vec<u8> {
        encode_tool_call(&ProviderToolCall {
            sprint_id: harness.sprint_id.clone(),
            task_id: "task-1".into(),
            sequence: 1,
            call_id: format!("{idempotency_key}-call"),
            idempotency_key: idempotency_key.into(),
            intent: ProviderToolIntent::ReadRelativeFile {
                path: PathBuf::from(path),
                max_bytes,
            },
        })
        .expect("encode canonical provider read call")
    }

    fn transport_with_first_exchange_hook(
        nonce: Digest,
        identity: WireRootIdentity,
        hook: impl FnOnce() + 'static,
    ) -> impl FnOnce(
        &mut RetainedRunnerExecutable,
        Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError> {
        move |_, expected_binding| {
            Ok(RunnerSpawnOutcome {
                process: Box::new(
                    ScriptedTransport::new(nonce, identity, ScriptMode::Good, false, Vec::new())
                        .with_before_first_exchange(hook),
                ),
                platform_binding: expected_binding.cloned().map(Box::new),
                native_cleanup_custody: None,
            })
        }
    }

    fn transport_with_preparation_hook(
        nonce: Digest,
        identity: WireRootIdentity,
        hook: impl FnOnce() + 'static,
    ) -> impl FnOnce(
        &mut RetainedRunnerExecutable,
        Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError> {
        move |_, expected_binding| {
            hook();
            Ok(RunnerSpawnOutcome {
                process: Box::new(ScriptedTransport::new(
                    nonce,
                    identity,
                    ScriptMode::Good,
                    false,
                    Vec::new(),
                )),
                platform_binding: expected_binding.cloned().map(Box::new),
                native_cleanup_custody: None,
            })
        }
    }

    fn transport_with_rollback_response(
        nonce: Digest,
        identity: WireRootIdentity,
        response: RunnerResponse,
        exchange_count: Rc<Cell<u64>>,
    ) -> impl FnOnce(
        &mut RetainedRunnerExecutable,
        Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError> {
        move |_, expected_binding| {
            Ok(RunnerSpawnOutcome {
                process: Box::new(
                    ScriptedTransport::new(nonce, identity, ScriptMode::Good, false, Vec::new())
                        .with_exchange_count(exchange_count)
                        .with_rollback_response(response),
                ),
                platform_binding: expected_binding.cloned().map(Box::new),
                native_cleanup_custody: None,
            })
        }
    }

    #[derive(Clone, Copy)]
    enum NativeReleaseMutation {
        Exact,
        SubstitutedJournal,
        SubstitutedBinding,
        SubstitutedProcess,
    }

    struct AdversarialNativeLaunchService<F> {
        disposition: RunnerLaunchPreparationDisposition,
        release_mutation: NativeReleaseMutation,
        spawn: Option<F>,
        prepared: Option<RunnerSpawnOutcome>,
        preparation_failure: Option<NativeLaunchReleaseFailure>,
        prepare_count: Rc<Cell<u64>>,
        release_count: Rc<Cell<u64>>,
        native_cleanup_count: Rc<Cell<u64>>,
        cleanup_mutation: ScriptedNativeCleanupMutation,
    }

    impl<F> AdversarialNativeLaunchService<F> {
        fn new(
            disposition: RunnerLaunchPreparationDisposition,
            release_mutation: NativeReleaseMutation,
            spawn: F,
            prepare_count: Rc<Cell<u64>>,
            release_count: Rc<Cell<u64>>,
        ) -> Self {
            Self {
                disposition,
                release_mutation,
                spawn: Some(spawn),
                prepared: None,
                preparation_failure: None,
                prepare_count,
                release_count,
                native_cleanup_count: Rc::new(Cell::new(0)),
                cleanup_mutation: ScriptedNativeCleanupMutation::Exact,
            }
        }

        fn with_cleanup_script(
            mut self,
            native_cleanup_count: Rc<Cell<u64>>,
            cleanup_mutation: ScriptedNativeCleanupMutation,
        ) -> Self {
            self.native_cleanup_count = native_cleanup_count;
            self.cleanup_mutation = cleanup_mutation;
            self
        }
    }

    impl<F> NativeLaunchService for AdversarialNativeLaunchService<F>
    where
        F: FnOnce(
            &mut RetainedRunnerExecutable,
            Option<&PlatformLaunchBinding>,
        ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError>,
    {
        fn prepare(
            &mut self,
            mut request: native_launch_service::NativeLaunchPreparationRequest<'_>,
        ) -> NativeLaunchPreparationResponse {
            self.prepare_count.set(self.prepare_count.get() + 1);
            let binding = request.binding().clone();
            let mut disposition = self.disposition;
            if disposition == RunnerLaunchPreparationDisposition::HeldChildPrepared {
                let spawn = self
                    .spawn
                    .take()
                    .expect("adversarial fake preparation is one-shot");
                match spawn(request.executable(), Some(&binding)) {
                    Ok(spawned) if spawned.platform_binding.as_deref() == Some(&binding) => {
                        self.prepared = Some(spawned);
                    }
                    Ok(spawned) => {
                        self.preparation_failure = Some(NativeLaunchReleaseFailure {
                            error: RunnerClientError::InvalidLifecycle(
                                "adversarial preparation crossed its platform binding".into(),
                            ),
                            direct_child: spawned.process.finish_direct(),
                        });
                        disposition = RunnerLaunchPreparationDisposition::NativeEffectUncertain;
                    }
                    Err(failure) => {
                        self.preparation_failure = Some(NativeLaunchReleaseFailure {
                            error: failure.error.into(),
                            direct_child: failure.direct_child,
                        });
                        disposition = RunnerLaunchPreparationDisposition::NativeEffectUncertain;
                    }
                }
            }
            NativeLaunchPreparationResponse {
                disposition,
                service_evidence_bytes: format!(
                    "fake-native-preparation:{}:{}",
                    request.claim().attempt().native_journal_id,
                    request.binding().binding_digest()
                )
                .into_bytes(),
                finished_at_unix_ms: request.claim().attempt().claimed_at_unix_ms,
            }
        }

        fn take_preparation_failure(&mut self) -> Option<NativeLaunchReleaseFailure> {
            self.preparation_failure.take()
        }

        fn into_cleanup_custody(
            mut self: Box<Self>,
            authority: NativeLaunchCleanupAuthority,
        ) -> Box<dyn NativeLaunchCleanupCustody> {
            let held_transport = self.prepared.take().map(|spawned| spawned.process);
            Box::new(ScriptedNativeCleanupCustody::new(
                authority,
                held_transport,
                self.native_cleanup_count,
                self.cleanup_mutation,
            ))
        }

        fn release(
            mut self: Box<Self>,
            request: NativeLaunchReleaseRequest<'_>,
        ) -> NativeLaunchReleaseAttempt {
            self.release_count.set(self.release_count.get() + 1);
            let cleanup_authority = NativeLaunchCleanupAuthority::from_expected_state(
                request.claim().admission(),
                Some(request.preparation()),
                request.binding(),
            );
            let preparation = request.preparation().clone();
            let binding = request.binding().clone();
            debug_assert_eq!(request.claim().admission().launch, *binding.launch());
            debug_assert!(
                !request
                    .validated_preparation()
                    .service_evidence_bytes()
                    .is_empty()
            );
            let preparation_evidence_digest = request
                .validated_preparation()
                .native_evidence_digest()
                .clone();
            let released_at_unix_ms = request
                .validated_preparation()
                .finished_at_unix_ms()
                .saturating_add(1);
            let Some(spawned) = self.prepared.take() else {
                return NativeLaunchReleaseAttempt {
                    cleanup_custody: Box::new(ScriptedNativeCleanupCustody::new(
                        cleanup_authority,
                        None,
                        self.native_cleanup_count,
                        self.cleanup_mutation,
                    )),
                    outcome: Err(NativeLaunchReleaseFailure {
                        error: RunnerClientError::InvalidLifecycle(
                            "adversarial release had no prepared held transport".into(),
                        ),
                        direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                    }),
                };
            };
            let exact_process_identity = native_transport_identity_digest(
                &preparation.attempt,
                &preparation_evidence_digest,
                &binding,
            );
            let transport_identity = if matches!(
                self.release_mutation,
                NativeReleaseMutation::SubstitutedProcess
            ) {
                Digest::sha256(b"substituted-native-process")
            } else {
                exact_process_identity.clone()
            };
            NativeLaunchReleaseAttempt {
                cleanup_custody: Box::new(ScriptedNativeCleanupCustody::new(
                    cleanup_authority,
                    None,
                    self.native_cleanup_count,
                    self.cleanup_mutation,
                )),
                outcome: Ok(NativeLaunchReleaseResponse {
                    attempt_id: preparation.attempt.attempt_id.clone(),
                    native_journal_id: if matches!(
                        self.release_mutation,
                        NativeReleaseMutation::SubstitutedJournal
                    ) {
                        format!("{}-substituted", preparation.attempt.native_journal_id)
                    } else {
                        preparation.attempt.native_journal_id.clone()
                    },
                    expected_platform_binding_digest: if matches!(
                        self.release_mutation,
                        NativeReleaseMutation::SubstitutedBinding
                    ) {
                        Digest::sha256(b"substituted-platform-binding")
                    } else {
                        binding.binding_digest().clone()
                    },
                    preparation_evidence_digest,
                    process_identity_digest: exact_process_identity,
                    journal_evidence_bytes: b"fake-durable-release-journal-evidence".to_vec(),
                    released_at_unix_ms,
                    transport: Box::new(NativeIdentityBoundTransport {
                        inner: spawned.process,
                        process_identity_digest: transport_identity,
                    }),
                }),
            }
        }
    }

    fn unique_nonce(label: &str) -> Digest {
        let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        Digest::sha256(format!("nonce-{label}-{sequence}").as_bytes())
    }

    fn forbidden_native_prepare_spawn(
        _: &mut RetainedRunnerExecutable,
        _: Option<&PlatformLaunchBinding>,
    ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError> {
        unreachable!("non-prepared or already-cleaned native state must never reach release")
    }

    fn proposal(intent: &EffectIntent, sequence: u64) -> AgentEvent {
        AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence,
            event_id: format!("event-{}", intent.effect_id),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            causation_id: intent.causation_event_id.clone(),
            correlation_id: intent.correlation_id.clone(),
            policy_hash: Some(intent.policy_hash.clone()),
            occurred_at_unix_ms: intent.created_at_unix_ms,
            payload: AgentEventKind::ToolProposed {
                tool_call_id: intent.idempotency_key.clone(),
                tool_name: intent.kind.tool_name().into(),
            },
        }
    }

    fn observation(
        intent: &EffectIntent,
        observation_id: impl Into<String>,
        outcome: EffectOutcome,
        observed_at_unix_ms: u64,
    ) -> EffectObservation {
        EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: observation_id.into(),
            effect_id: intent.effect_id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            worker_lease: intent.worker_lease.clone(),
            correlation_id: intent.correlation_id.clone(),
            kind: intent.kind,
            request_digest: intent.request_digest.clone(),
            policy_hash: intent.policy_hash.clone(),
            input_snapshot: intent.input_snapshot.clone(),
            outcome,
            observed_at_unix_ms,
        }
    }

    fn terminal_event(
        ledger: &EventLedger,
        intent: &EffectIntent,
        proposed_event_id: &str,
        observation: &EffectObservation,
    ) -> AgentEvent {
        terminal_event_at_sequence(
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("next terminal event sequence"),
            intent,
            proposed_event_id,
            observation,
        )
    }

    fn terminal_event_at_sequence(
        sequence: u64,
        intent: &EffectIntent,
        proposed_event_id: &str,
        observation: &EffectObservation,
    ) -> AgentEvent {
        AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence,
            event_id: format!("event-{}-finished", intent.effect_id),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            causation_id: Some(proposed_event_id.to_owned()),
            correlation_id: intent.correlation_id.clone(),
            policy_hash: Some(intent.policy_hash.clone()),
            occurred_at_unix_ms: observation.observed_at_unix_ms,
            payload: AgentEventKind::ToolFinished {
                tool_call_id: intent.idempotency_key.clone(),
                succeeded: observation.outcome.succeeded(),
            },
        }
    }

    fn terminalize_pre_spawn_cleanup(
        ledger: &mut EventLedger,
        admission: &PersistedRunnerLaunchCleanupAdmission,
    ) {
        let intent = &admission.cleanup_effect.intent;
        let cleaned_at_unix_ms =
            native_cleanup_requested_at_unix_ms(ledger, admission).saturating_add(1);
        let os_evidence_bytes = b"fake-service-zero-descendant-pre-spawn-cleanup".to_vec();
        let evidence = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!("receipt-{}", admission.launch.launch_id),
                sprint_id: admission.launch.sprint_id.clone(),
                launch_id: admission.launch.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                observation_id: format!("observation-{}", intent.effect_id),
                session_id: admission.launch.session_id.clone(),
                worker_lease: admission.launch.worker_lease.clone(),
                policy_hash: admission.launch.policy_hash.clone(),
                grant_hash: admission.launch.grant_hash.clone(),
                policy_version: admission.launch.policy_version,
                platform_backend: admission.cleanup_request.platform_backend,
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
        ledger
            .with_runner_launch_cleanup_exclusion(
                &admission.launch.sprint_id,
                &admission.launch.launch_id,
                |claim| {
                    assert_eq!(claim.admission(), admission);
                    Ok(RunnerCleanupTerminalRecord {
                        event: terminal_event_at_sequence(
                            claim.next_event_sequence(),
                            intent,
                            &admission.cleanup_effect.proposed_event.event_id,
                            &observed,
                        ),
                        observation: observed.clone(),
                        evidence: evidence.clone(),
                    })
                },
            )
            .expect("terminalize cleanup under the live exclusion");
    }

    fn native_cleanup_requested_at_unix_ms(
        ledger: &EventLedger,
        admission: &PersistedRunnerLaunchCleanupAdmission,
    ) -> u64 {
        let mut requested_at_unix_ms = admission
            .launch
            .created_at_unix_ms
            .max(admission.cleanup_effect.intent.created_at_unix_ms)
            .max(admission.cleanup_effect.proposed_event.occurred_at_unix_ms);
        if let Ok(preparation) = ledger.load_runner_launch_preparation(
            &admission.launch.sprint_id,
            &admission.launch.launch_id,
        ) {
            requested_at_unix_ms = requested_at_unix_ms.max(preparation.attempt.claimed_at_unix_ms);
            if let Some(outcome) = preparation.outcome {
                requested_at_unix_ms = requested_at_unix_ms.max(outcome.finished_at_unix_ms);
            }
        }
        requested_at_unix_ms
    }

    fn persist_scripted_native_preparation_authority(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        policy: &CompiledExecutionPolicy,
        admission: &PersistedRunnerLaunchCleanupAdmission,
        label: &str,
    ) -> (NativeLaunchCleanupAuthority, u64) {
        let platform_binding =
            PlatformLaunchBinding::try_from_admission(admission, &harness.authority, policy)
                .expect("reconstruct exact scripted native platform binding");
        let claimed_at_unix_ms = admission
            .launch
            .created_at_unix_ms
            .max(admission.cleanup_effect.intent.created_at_unix_ms);
        let attempt = RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: format!("native-preparation-{label}"),
            sprint_id: admission.launch.sprint_id.clone(),
            launch_id: admission.launch.launch_id.clone(),
            cleanup_effect_id: admission.cleanup_effect.intent.effect_id.clone(),
            native_journal_id: format!("native-journal-{label}"),
            expected_platform_binding_digest: platform_binding.binding_digest().clone(),
            claimed_at_unix_ms,
        };
        let outcome = RunnerLaunchPreparationOutcome {
            disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
            native_evidence_bytes: format!("held-native-child-{label}").into_bytes(),
            finished_at_unix_ms: claimed_at_unix_ms,
        };
        let expected_outcome = outcome.clone();
        let preparation = ledger
            .with_runner_launch_preparation_claim(admission, &attempt, |_| expected_outcome)
            .expect("persist exact scripted native preparation");
        assert_eq!(preparation.attempt, attempt);
        assert_eq!(preparation.outcome.as_ref(), Some(&outcome));
        let authority = NativeLaunchCleanupAuthority::from_expected_state(
            admission,
            Some(&preparation),
            &platform_binding,
        );
        (authority, outcome.finished_at_unix_ms.saturating_add(1))
    }

    fn read_only_policy(harness: &TestHarness, suffix: &str) -> CompiledExecutionPolicy {
        ExecutionPolicyCompiler::compile(
            &harness.authority,
            ExecutionPolicyRequest {
                policy_id: format!("policy-{suffix}"),
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
        .expect("compile read-only test policy")
    }

    struct CompletionRoleAdmission {
        launch: RunnerLaunchIntent,
        cleanup_request: WorkerCleanupRequest,
        cleanup_intent: EffectIntent,
        cleanup_proposed_event_id: String,
        session: RunnerSessionPolicyRecord,
        task_attempt_running: Option<TaskAttemptRunningBoundary>,
    }

    const RESTART_TEST_CLEANUP_EVIDENCE_PREFIX: &[u8] =
        b"grok-build.runner-command-domain-cleanup-proof.v1\0";
    const RESTART_TEST_CLEANUP_FIXTURE_SESSION: &str = "verification-session";
    const RESTART_TEST_CLEANUP_FIXTURE_EFFECT: &str = "verification-effect";
    const RESTART_TEST_CLEANUP_FIXTURE_REQUEST_DIGEST: &str =
        "302065194cfd5e2bebf7fb7d2cb39b98256c895a3910a20cab034b93ceb8de20";
    const RESTART_TEST_CLEANUP_FIXTURE_JSON: &str = r#"{"schema_version":1,"backend":"linux_cgroup_v2","binding":{"runner_session_id":"verification-session","command_effect_id":"verification-effect","command_request_digest":"302065194cfd5e2bebf7fb7d2cb39b98256c895a3910a20cab034b93ceb8de20"},"surviving_processes":0,"platform_evidence":{"kind":"linux_cgroup_v2","evidence":{"journal_record":{"state":"removed","native_launch":{"contract_version":1,"attempt_id":"linux-preparation-attempt-1","native_journal_id":"linux-native-journal-1","expected_platform_binding_digest":"dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986","sprint_id":"sprint-linux-1","launch_id":"launch-linux-1","session_id":"verification-session","cleanup_effect_id":"cleanup-effect-linux-1","input_snapshot":"ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879","grant_hash":"e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71","policy_hash":"e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db","claimed_at_unix_ms":10},"runner_session_id":"verification-session","effect_id":"verification-effect","grant_hash":"e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71","policy_hash":"e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db","command_hash":"67586e98fad27da0b9968bc039a1ef34c939b9b8e523a8bef89d478608c5ecf6","request_digest":"302065194cfd5e2bebf7fb7d2cb39b98256c895a3910a20cab034b93ceb8de20","leaf_name":"gb-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_delegation_identity":{"device":11,"inode":12},"expected_owner_uid":501,"leaf_identity":{"device":41,"inode":42},"requested_limits":{"pids_max":8,"memory_max":"max","memory_swap_max":"max"},"read_back_limits":{"pids_max":8,"memory_max":"max","memory_swap_max":"max","memory_oom_group":true},"staged_launcher":null,"release_authorization":null,"release_binding":null,"release_intent_recorded":false,"release_observation":null,"cleanup_observations":[{"sequence":1,"attempt":1,"file":"cgroup_events","bytes":[112,111,112,117,108,97,116,101,100,32,48,10,102,114,111,122,101,110,32,48,10]},{"sequence":2,"attempt":1,"file":"cgroup_procs","bytes":[]},{"sequence":3,"attempt":1,"file":"cgroup_procs","bytes":[]}],"kill_value":[49,10]}}}}"#;

    fn restart_test_replace_json_string(
        canonical_json: &str,
        expected: &str,
        replacement: &str,
    ) -> String {
        let expected = serde_json::to_string(expected).expect("encode fixture cleanup key");
        let replacement = serde_json::to_string(replacement).expect("encode exact cleanup binding");
        assert!(
            canonical_json.contains(&expected),
            "cleanup fixture contains each replaced authority"
        );
        canonical_json.replace(&expected, &replacement)
    }

    fn restart_test_linux_cleanup(
        runner_session_id: &str,
        effect_id: &str,
        request_digest: &Digest,
    ) -> (WireCommandBackendIdentity, WireCommandCleanupProof) {
        let canonical = restart_test_replace_json_string(
            RESTART_TEST_CLEANUP_FIXTURE_JSON,
            RESTART_TEST_CLEANUP_FIXTURE_SESSION,
            runner_session_id,
        );
        let canonical = restart_test_replace_json_string(
            &canonical,
            RESTART_TEST_CLEANUP_FIXTURE_EFFECT,
            effect_id,
        );
        let canonical = restart_test_replace_json_string(
            &canonical,
            RESTART_TEST_CLEANUP_FIXTURE_REQUEST_DIGEST,
            request_digest.as_str(),
        );
        let mut os_evidence_bytes = RESTART_TEST_CLEANUP_EVIDENCE_PREFIX.to_vec();
        os_evidence_bytes.extend_from_slice(canonical.as_bytes());
        let proof = WireCommandCleanupProof {
            os_evidence_digest: Digest::sha256(&os_evidence_bytes),
            os_evidence_bytes,
        };
        let binding = CommandDomainCleanupBinding::try_new(
            runner_session_id,
            effect_id,
            request_digest.clone(),
        )
        .expect("construct exact restart cleanup binding");
        let _validated = proof
            .readback(RunnerCommandDomainCleanupBackend::LinuxCgroupV2, &binding)
            .expect("restart cleanup fixture remains native-valid after exact rebinding");
        (
            WireCommandBackendIdentity {
                command_domain_backend: RunnerCommandDomainCleanupBackend::LinuxCgroupV2,
                backend_id: "restart-test-linux-cgroup-v2".into(),
                implementation_digest: Digest::sha256(b"restart-test-linux-cgroup-v2/v1"),
            },
            proof,
        )
    }

    struct RestartTaskUnknownCleanupReopener {
        authority: NativeLaunchCleanupAuthority,
        command_cleanup_count: Rc<Cell<u64>>,
        reopen_count: Rc<Cell<u64>>,
        launch_cleanup_count: Rc<Cell<u64>>,
        return_crossed_linux_proof: bool,
        command_cleanup_proof: Option<grok_build_runner::ValidatedCommandDomainCleanupProof>,
    }

    impl NativeLaunchCleanupReopener for RestartTaskUnknownCleanupReopener {
        fn reopen_cleanup(
            &mut self,
            request: NativeLaunchCleanupReopenRequest<'_>,
        ) -> Result<Box<dyn NativeLaunchCleanupCustody>, LedgerError> {
            if self.authority.admission != *request.claim().admission()
                || request
                    .expected_platform_binding()
                    .is_some_and(|binding| self.authority.platform_binding() != binding)
            {
                return Err(LedgerError::ReferenceMismatch {
                    entity: "restart task-command Unknown launch cleanup",
                    detail: "cleanup claim crossed exact native launch authority".into(),
                });
            }
            self.reopen_count
                .set(self.reopen_count.get().saturating_add(1));
            Ok(Box::new(ScriptedNativeCleanupCustody::new(
                self.authority.clone(),
                None,
                Rc::clone(&self.launch_cleanup_count),
                ScriptedNativeCleanupMutation::Exact,
            )))
        }

        fn cleanup_command_domain(
            &mut self,
            request: NativeCommandDomainCleanupRequest<'_>,
        ) -> Result<NativeCommandDomainCleanupObservation, LedgerError> {
            if (!self.return_crossed_linux_proof
                && request.expected_backend() != RunnerCommandDomainCleanupBackend::LinuxCgroupV2)
                || request.effect_binding().session_id
                    != request.runner_binding().runner_session_id()
                || request.effect_binding().effect_id
                    != request.runner_binding().command_effect_id()
                || request.effect_binding().request_digest
                    != *request.runner_binding().command_request_digest()
            {
                return Err(LedgerError::ReferenceMismatch {
                    entity: "restart task-command Unknown command cleanup",
                    detail: "command cleanup request crossed exact effect binding".into(),
                });
            }
            let proof = if let Some(proof) = &self.command_cleanup_proof {
                proof.clone()
            } else {
                let (_, proof) = restart_test_linux_cleanup(
                    request.runner_binding().runner_session_id(),
                    request.runner_binding().command_effect_id(),
                    request.runner_binding().command_request_digest(),
                );
                proof
                    .readback(
                        RunnerCommandDomainCleanupBackend::LinuxCgroupV2,
                        request.runner_binding(),
                    )
                    .map_err(|error| LedgerError::ReferenceMismatch {
                        entity: "restart task-command Unknown command cleanup",
                        detail: error.to_string(),
                    })?
            };
            self.command_cleanup_count
                .set(self.command_cleanup_count.get().saturating_add(1));
            Ok(NativeCommandDomainCleanupObservation {
                effect_binding: request.effect_binding().clone(),
                proof,
                cleaned_at_unix_ms: request.requested_at_unix_ms(),
            })
        }
    }

    struct RestartOrdinaryCommandFixture {
        harness: TestHarness,
        ledger: EventLedger,
        launch: RunnerLaunchIntent,
        session: RunnerSessionPolicyRecord,
        running: TaskAttemptRunningBoundary,
        effect: PersistedEffect,
        provider_call: ProviderToolCall,
        capture_intent: CommandOutputCaptureIntentV1,
        acquired: Option<grok_build_core::CommandOutputCaptureAcquiredV1>,
        wire_request: Option<RunnerRequestEnvelopeV12>,
        observation_authority: Option<RunnerEffectObservationAuthority>,
    }

    impl RestartOrdinaryCommandFixture {
        #[allow(
            clippy::too_many_lines,
            reason = "the fixture constructs one complete exact restart authority chain"
        )]
        fn new(label: &str, claimed: bool) -> Self {
            Self::new_with_backend(label, claimed, WorkerCleanupBackend::LinuxCgroupV2)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the fixture constructs one complete exact restart authority chain"
        )]
        fn new_with_backend(
            label: &str,
            claimed: bool,
            cleanup_backend: WorkerCleanupBackend,
        ) -> Self {
            let (harness, mut ledger) = TestHarness::new(label);
            let role = launch_ordinary_completion_role_with_registration(
                &harness,
                &mut ledger,
                &harness.policy,
                &format!("{label}-worker"),
                RunnerRole::Worker,
                true,
                None,
                Some(cleanup_backend),
            );
            let running = role
                .task_attempt_running
                .expect("restart command fixture enters exact Running authority");
            let command = CommandSpec {
                program: "true".into(),
                arguments: Vec::new(),
                working_directory: PathBuf::new(),
            };
            let provider_call = ProviderToolCall {
                sprint_id: harness.sprint_id.clone(),
                task_id: running.attempt.worker_lease.task_id.clone(),
                sequence: 1,
                call_id: format!("restart-command-call-{label}"),
                idempotency_key: format!("restart-command-key-{label}"),
                intent: ProviderToolIntent::RunCommand {
                    command: command.clone(),
                },
            };
            let request_bytes =
                serde_json::to_vec(&command).expect("encode restart command request");
            let canonical_call = encode_tool_call(&provider_call)
                .expect("encode exact restart provider call correlation preimage");
            let intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: format!("restart-command-effect-{label}"),
                idempotency_key: format!(
                    "task-attempt-{}-{}",
                    Digest::sha256(running.attempt.worker_lease.lease_id.as_bytes()),
                    provider_call.idempotency_key
                ),
                sprint_id: harness.sprint_id.clone(),
                task_id: Some(running.attempt.worker_lease.task_id.clone()),
                worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
                worker_lease: Some(running.attempt.worker_lease.clone()),
                causation_event_id: Some(running.transition_event_id.clone()),
                correlation_id: format!(
                    "{}:walking-skeleton-v1:provider-call-{}",
                    harness.sprint_id,
                    Digest::sha256(&canonical_call)
                ),
                kind: EffectKind::RunCommand,
                request_digest: Digest::sha256(&request_bytes),
                policy_hash: harness.policy.contract().policy_hash.clone(),
                input_snapshot: harness.base_snapshot.clone(),
                created_at_unix_ms: role.session.registered_at_unix_ms.saturating_add(10),
            };
            let proposed = proposal(
                &intent,
                ledger
                    .next_sequence(&harness.sprint_id)
                    .expect("next restart command proposal sequence"),
            );
            let capture_intent = fresh_command_output_capture_intent(
                &intent,
                &role.launch,
                &role.session,
                &harness.policy,
            )
            .expect("construct restart command capture intent");
            let CommandOutputCaptureIntentAdmission::Fresh {
                effect,
                capture,
                permit,
            } = ledger
                .admit_runner_command_output_capture_intent_for_dispatch(
                    &intent,
                    &request_bytes,
                    &proposed,
                    &role.session.session_id,
                    &capture_intent,
                )
                .expect("admit restart command and output capture")
            else {
                panic!("restart command fixture must be fresh")
            };
            assert_eq!(capture.intent, capture_intent);
            let (effect, acquired, wire_request, observation_authority) = if claimed {
                let detector_policy = permit
                    .sensitive_output_detection_policy()
                    .cloned()
                    .expect("restart command permit carries exact detector policy");
                let dispatch_claim_id = permit
                    .expected_output_capture_dispatch_claim_id()
                    .expect("restart command permit carries capture claim identity");
                let store = CapabilityCommandOutputStore::open(&harness.private_state)
                    .expect("open restart command store");
                let acquired = store
                    .reserve_anchored_capture_v2(
                        &capture_intent,
                        &dispatch_claim_id,
                        intent.created_at_unix_ms.saturating_add(1),
                        &detector_policy,
                    )
                    .expect("reserve restart command capture")
                    .into_acquired_anchor_for_handoff()
                    .expect("synchronize restart command acquisition");
                let output_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
                    .expect("construct exact restart wire capture anchor");
                let wire_command = WireCommandSpec {
                    program: command.program.clone(),
                    arguments: command.arguments.clone(),
                    working_directory: command
                        .working_directory
                        .to_str()
                        .expect("restart command working directory is UTF-8")
                        .into(),
                };
                let mut wire_request = RunnerRequestEnvelopeV12 {
                    protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
                    session_id: role.session.session_id.clone(),
                    runner_nonce: role.session.session_nonce.clone(),
                    sequence: 1,
                    request_id: format!("restart-command-request-{label}"),
                    effect: WireEffectContext {
                        contract_version: intent.contract_version,
                        launch_id: role.launch.launch_id.clone(),
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
                    },
                    request: RunnerRequestV12::RunCommand {
                        request: RunnerRequest::WorkerRunCommand {
                            command: wire_command,
                            output_capture,
                        },
                        detector_policy,
                    },
                };
                wire_request
                    .bind_transport_commitment_digest()
                    .expect("bind exact restart transport commitment");
                let request_frame = encode_request_frame_v12(&wire_request)
                    .expect("encode exact restart transport frame");
                let (claimed_effect, transport) = ledger
                    .claim_command_output_capture_dispatch(permit, acquired.clone(), &request_frame)
                    .expect("claim restart command dispatch");
                let observation_authority = transport
                    .validate_transport_request(
                        &intent,
                        &request_bytes,
                        &role.launch,
                        &role.session,
                        Some(&running),
                        &request_frame,
                    )
                    .expect("validate exact restart transport request authority");
                (
                    claimed_effect,
                    Some(acquired),
                    Some(wire_request),
                    Some(observation_authority),
                )
            } else {
                drop(permit);
                (effect, None, None, None)
            };
            Self {
                harness,
                ledger,
                launch: role.launch,
                session: role.session,
                running,
                effect,
                provider_call,
                capture_intent,
                acquired,
                wire_request,
                observation_authority,
            }
        }

        fn persist_invalid_semantic_launch(&self, terminal_prepared: bool) {
            let acquired = self
                .acquired
                .as_ref()
                .expect("launch-bearing fixture has one acquisition");
            let mut crossed_request = self
                .wire_request
                .as_ref()
                .expect("launch-bearing fixture retains its exact wire request")
                .clone();
            crossed_request.request_id.push_str(":transport-crossed");
            crossed_request
                .bind_transport_commitment_digest()
                .expect("bind internally valid crossed v12 request");
            let (backend, _) = restart_test_linux_cleanup(
                &self.session.session_id,
                &self.effect.intent.effect_id,
                &self.effect.intent.request_digest,
            );
            let input = ClaimedCommandOutputV2TestProofBoxInput {
                private_state_root: self.harness.private_state.clone(),
                grant_hash: self.harness.authority.contract().grant_hash.clone(),
                acquired: acquired.clone(),
                request: crossed_request,
                termination: CommandTerminationV1::Exited { code: 0 },
                backend,
            };
            if terminal_prepared {
                complete_sensitive_output_clean_test_proof_box_v1(input, b"restart output\n", &[])
                    .expect("complete current-v2 transport-crossed TerminalPrepared proof box");
            } else {
                cut_sensitive_output_clean_test_proof_box_v1(
                    input,
                    b"restart output\n",
                    &[],
                    SensitiveOutputCleanTestCutV1::Published,
                )
                .expect("persist current-v2 transport-crossed Published proof box");
            }
        }

        fn persist_launch_intended_cut(&self) {
            let acquired = self
                .acquired
                .as_ref()
                .expect("launch-bearing fixture has one acquisition");
            let request = self
                .wire_request
                .as_ref()
                .expect("launch-bearing fixture retains its exact wire request");
            let (backend, _) = restart_test_linux_cleanup(
                &self.session.session_id,
                &self.effect.intent.effect_id,
                &self.effect.intent.request_digest,
            );
            let cut = cut_sensitive_output_clean_test_proof_box_v1(
                ClaimedCommandOutputV2TestProofBoxInput {
                    private_state_root: self.harness.private_state.clone(),
                    grant_hash: self.harness.authority.contract().grant_hash.clone(),
                    acquired: acquired.clone(),
                    request: request.clone(),
                    termination: CommandTerminationV1::Canceled,
                    backend,
                },
                b"clean prefix that must not become restart evidence",
                b"stderr prefix that must not become restart evidence",
                SensitiveOutputCleanTestCutV1::LaunchIntended,
            )
            .expect("persist exact current-v2 generation-four launch cut");
            assert!(matches!(
                cut.recovery().stage(),
                grok_build_runner::SensitiveOutputJournalStageV2::LaunchIntended { .. }
            ));
        }

        fn persist_sensitive_output_clean_cut(
            &self,
            cut: SensitiveOutputCleanTestCutV1,
        ) -> grok_build_runner::ValidatedCommandDomainCleanupProof {
            let acquired = self
                .acquired
                .as_ref()
                .expect("clean-cut fixture has one acquisition");
            let request = self
                .wire_request
                .as_ref()
                .expect("clean-cut fixture retains its exact wire request");
            let (backend, _) = restart_test_linux_cleanup(
                &self.session.session_id,
                &self.effect.intent.effect_id,
                &self.effect.intent.request_digest,
            );
            let proof_box = cut_sensitive_output_clean_test_proof_box_v1(
                ClaimedCommandOutputV2TestProofBoxInput {
                    private_state_root: self.harness.private_state.clone(),
                    grant_hash: self.harness.authority.contract().grant_hash.clone(),
                    acquired: acquired.clone(),
                    request: request.clone(),
                    termination: CommandTerminationV1::Exited { code: 0 },
                    backend,
                },
                b"recovered partial clean stdout\n",
                b"recovered partial clean stderr\n",
                cut,
            )
            .expect("persist exact partial clean cut");
            proof_box.native_cleanup_proof().clone()
        }

        fn restart_owner_with_native_command_proof(
            &mut self,
            suffix: &str,
            native_proof: grok_build_runner::ValidatedCommandDomainCleanupProof,
            command_cleanup_count: Rc<Cell<u64>>,
        ) -> DesktopRunnerLifecycleOwner {
            let cleanup_admission = self
                .ledger
                .load_runner_launch_cleanup_admission(
                    &self.harness.sprint_id,
                    &self.launch.launch_id,
                )
                .expect("load partial-terminal cleanup admission");
            let (cleanup_authority, _) = persist_scripted_native_preparation_authority(
                &self.harness,
                &mut self.ledger,
                &self.harness.policy,
                &cleanup_admission,
                suffix,
            );
            DesktopRunnerLifecycleOwner::with_native_cleanup_reopener(
                RunnerLifecycleOwnerConfig {
                    runner_binary: self.harness.runner_binary.clone(),
                    private_state_root: self.harness.private_state.clone(),
                },
                Box::new(RestartTaskUnknownCleanupReopener {
                    authority: cleanup_authority,
                    command_cleanup_count,
                    reopen_count: Rc::new(Cell::new(0)),
                    launch_cleanup_count: Rc::new(Cell::new(0)),
                    return_crossed_linux_proof: false,
                    command_cleanup_proof: Some(native_proof),
                }),
            )
            .expect("construct partial-terminal native-proof restart owner")
        }

        fn remove_sensitive_output_terminal_observation(&self) {
            fs::remove_file(
                self.harness
                    .private_state
                    .join(format!(
                        "sensitive-output-journal-v2-{}",
                        self.capture_intent.capture_id
                    ))
                    .join(grok_build_runner::SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1),
            )
            .expect("remove terminal sidecar to model the exact pre-publication crash cut");
        }

        fn persist_split_launch_cut(&self) {
            let acquired = self
                .acquired
                .as_ref()
                .expect("split-launch fixture has one acquisition");
            let request = self
                .wire_request
                .as_ref()
                .expect("split-launch fixture retains its exact wire request");
            let (backend, _) = restart_test_linux_cleanup(
                &self.session.session_id,
                &self.effect.intent.effect_id,
                &self.effect.intent.request_digest,
            );
            let cut = cut_sensitive_output_split_launch_test_proof_box_v1(
                ClaimedCommandOutputV2TestProofBoxInput {
                    private_state_root: self.harness.private_state.clone(),
                    grant_hash: self.harness.authority.contract().grant_hash.clone(),
                    acquired: acquired.clone(),
                    request: request.clone(),
                    termination: CommandTerminationV1::Canceled,
                    backend,
                },
                b"split-launch clean stdout prefix that must be zeroed",
                b"split-launch clean stderr prefix that must be zeroed",
            )
            .expect("persist exact crash cut after v1 launch and before v2 generation four");
            assert!(matches!(
                cut.recovery().stage(),
                grok_build_runner::SensitiveOutputJournalStageV2::WriterAttached { .. }
            ));
            assert_eq!(cut.recovery().head().generation, 3);
        }

        fn persist_writer_attached_prelaunch_cut(&self) {
            let acquired = self
                .acquired
                .as_ref()
                .expect("writer-attached fixture has one acquisition");
            let policy = self
                .wire_request
                .as_ref()
                .expect("writer-attached fixture retains its exact wire request")
                .detector_policy();
            let store = CapabilityCommandOutputStore::open(&self.harness.private_state)
                .expect("open writer-attached prelaunch store");
            let capture = store
                .reopen_anchored_capture_v2(acquired, policy)
                .expect("attach exact prelaunch v2 writer");
            let (stdout, stderr, publisher) = capture.split();
            drop(stdout);
            drop(stderr);
            drop(publisher);
            let v2 = store
                .reopen_sensitive_output_journal_v2(&self.capture_intent.capture_id)
                .expect("reopen exact writer-attached v2 prefix");
            assert_eq!(v2.head().generation, 3);
            assert!(matches!(
                v2.stage(),
                grok_build_runner::SensitiveOutputJournalStageV2::WriterAttached { .. }
            ));
            assert!(
                store
                    .reopen_capture(&self.capture_intent.capture_id)
                    .expect("reopen exact writer-attached v1 prefix")
                    .launch_intended_store_head()
                    .is_none()
            );
        }

        fn persist_sensitive_output_rejection_cut(
            &self,
            cut: SensitiveOutputRejectionTestCutV1,
        ) -> grok_build_runner::ValidatedCommandDomainCleanupProof {
            self.persist_sensitive_output_rejection_cut_with_transport(cut, false)
        }

        fn persist_sensitive_output_rejection_cut_with_transport(
            &self,
            cut: SensitiveOutputRejectionTestCutV1,
            crossed_transport: bool,
        ) -> grok_build_runner::ValidatedCommandDomainCleanupProof {
            let acquired = self
                .acquired
                .as_ref()
                .expect("rejection-cut fixture has one acquisition");
            let mut request = self
                .wire_request
                .as_ref()
                .expect("rejection-cut fixture retains its exact wire request")
                .clone();
            if crossed_transport {
                request.request_id.push_str(":transport-crossed");
                request
                    .bind_transport_commitment_digest()
                    .expect("bind internally valid crossed partial-rejection transport");
            }
            let (backend, _) = restart_test_linux_cleanup(
                &self.session.session_id,
                &self.effect.intent.effect_id,
                &self.effect.intent.request_digest,
            );
            let proof_box = cut_sensitive_output_rejection_test_proof_box_v1(
                ClaimedCommandOutputV2TestProofBoxInput {
                    private_state_root: self.harness.private_state.clone(),
                    grant_hash: self.harness.authority.contract().grant_hash.clone(),
                    acquired: acquired.clone(),
                    request,
                    termination: CommandTerminationV1::Canceled,
                    backend,
                },
                cut,
            )
            .expect("persist exact sensitive-output rejection cut");
            proof_box.native_cleanup_proof().clone()
        }

        fn persist_terminal_sensitive_output_rejection(
            &self,
        ) -> grok_build_runner::ValidatedCommandDomainCleanupProof {
            self.persist_terminal_sensitive_output_rejection_with_transport(false)
        }

        fn persist_terminal_sensitive_output_rejection_with_transport(
            &self,
            crossed_transport: bool,
        ) -> grok_build_runner::ValidatedCommandDomainCleanupProof {
            let acquired = self
                .acquired
                .as_ref()
                .expect("terminal rejection fixture has one acquisition");
            let mut request = self
                .wire_request
                .as_ref()
                .expect("terminal rejection fixture retains its exact wire request")
                .clone();
            if crossed_transport {
                request.request_id.push_str(":transport-crossed");
                request
                    .bind_transport_commitment_digest()
                    .expect("bind internally valid crossed rejection transport");
            }
            let (backend, _) = restart_test_linux_cleanup(
                &self.session.session_id,
                &self.effect.intent.effect_id,
                &self.effect.intent.request_digest,
            );
            let proof_box = complete_sensitive_output_rejection_test_proof_box_v1(
                ClaimedCommandOutputV2TestProofBoxInput {
                    private_state_root: self.harness.private_state.clone(),
                    grant_hash: self.harness.authority.contract().grant_hash.clone(),
                    acquired: acquired.clone(),
                    request,
                    termination: CommandTerminationV1::Canceled,
                    backend,
                },
            )
            .expect("persist exact terminal sensitive-output rejection");
            proof_box.native_cleanup_proof().clone()
        }

        fn persist_invalid_semantic_launch_cut(&self) {
            let acquired = self
                .acquired
                .as_ref()
                .expect("launch-cut fixture has one acquisition");
            let detector_policy = self
                .wire_request
                .as_ref()
                .expect("launch-cut fixture retains its exact v12 request")
                .detector_policy();
            let store = CapabilityCommandOutputStore::open(&self.harness.private_state)
                .expect("open launch-cut restart store");
            let capture = store
                .reopen_anchored_capture_v2(acquired, detector_policy)
                .expect("reopen exact v2 launch-cut restart capture");
            let (stdout, stderr, mut publisher) = capture.split();
            publisher
                .record_launch_intended(
                    CONTAINED_CAPTURE_LAUNCH_SCHEMA,
                    br#"{"substituted":"launch-cut"}"#.to_vec(),
                )
                .expect("persist exact launch-cut bytes");
            // Model a process boundary: closing raw writer descriptors and the
            // journal lease leaves the durable LaunchIntended cut unchanged.
            drop(stdout);
            drop(stderr);
            drop(publisher);
        }

        fn persist_live_ambiguous_unknown(&mut self) {
            let acquired = self
                .acquired
                .as_ref()
                .expect("live Unknown fixture has one acquisition");
            let authority = self
                .observation_authority
                .take()
                .expect("live Unknown fixture retains one observation authority");
            let evidence_bytes = b"live command transport became ambiguous after launch";
            let observed_at_unix_ms = self.effect.intent.created_at_unix_ms.saturating_add(20);
            let observation = observation(
                &self.effect.intent,
                format!("{}:live-unknown", self.effect.intent.effect_id),
                EffectOutcome::Unknown {
                    evidence_digest: Digest::sha256(evidence_bytes),
                },
                observed_at_unix_ms,
            );
            let event = terminal_event(
                &self.ledger,
                &self.effect.intent,
                &self.effect.proposed_event.event_id,
                &observation,
            );
            let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
                &self.capture_intent,
                Some(acquired),
                &observation,
                CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
                acquired.store_head.clone(),
                Digest::sha256(evidence_bytes),
                None,
                observed_at_unix_ms,
            )
            .expect("construct exact live ambiguous Unknown capture terminal");
            self.effect = self
                .ledger
                .record_claimed_command_unknown_with_capture_reconciliation_required(
                    authority,
                    &observation,
                    evidence_bytes,
                    &event,
                    &terminal,
                )
                .expect("persist exact live ambiguous Unknown terminal");
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the production-restart fixture keeps the reconstructed request, private launch authority, physical output, strict terminal, and native-valid cleanup proof adjacent"
        )]
        fn persist_valid_terminal_prepared(&self) {
            let acquired = self
                .acquired
                .as_ref()
                .expect("successful restart fixture has one acquisition");
            let request = self
                .wire_request
                .as_ref()
                .expect("successful restart fixture retains its exact wire request");
            let (backend, _) = restart_test_linux_cleanup(
                &self.session.session_id,
                &self.effect.intent.effect_id,
                &self.effect.intent.request_digest,
            );
            let stdout_bytes = b"recovered restart output\n";
            let proof_box = complete_sensitive_output_clean_test_proof_box_v1(
                ClaimedCommandOutputV2TestProofBoxInput {
                    private_state_root: self.harness.private_state.clone(),
                    grant_hash: self.harness.authority.contract().grant_hash.clone(),
                    acquired: acquired.clone(),
                    request: request.clone(),
                    termination: CommandTerminationV1::Exited { code: 0 },
                    backend,
                },
                stdout_bytes,
                &[],
            )
            .expect("complete exact v12 successful TerminalPrepared proof box");
            let recovery = proof_box
                .store()
                .reopen_capture(&self.capture_intent.capture_id)
                .expect("reopen exact v12 successful TerminalPrepared capture");
            assert!(matches!(
                recovery.state(),
                CommandOutputCaptureJournalStateV1::TerminalPrepared
            ));
        }

        fn reconcile(
            &mut self,
            owner: &mut DesktopRunnerLifecycleOwner,
        ) -> Result<
            crate::durable_coordinator::WalkingSkeletonTaskCommandRestartOutcome,
            crate::DurableCoordinatorError,
        > {
            crate::WalkingSkeletonRunnerLifecycle::reconcile_task_command_after_restart(
                owner,
                &mut self.ledger,
                crate::durable_coordinator::WalkingSkeletonTaskCommandRestart {
                    sprint_spec: &self.harness.sprint_spec,
                    workspace_grant: &self.harness.authority,
                    policy: &self.harness.policy,
                    running_boundary: &self.running,
                    runner_launch: &self.launch,
                    runner_session: &self.session,
                    effect: &self.effect,
                    provider_call: &self.provider_call,
                },
            )
        }
    }

    fn launch_ordinary_completion_role(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        policy: &CompiledExecutionPolicy,
        suffix: &str,
        role: RunnerRole,
    ) -> CompletionRoleAdmission {
        launch_ordinary_completion_role_with_registration(
            harness, ledger, policy, suffix, role, true, None, None,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test constructor keeps session admission, timestamp, and simulated cleanup-backend authority explicit"
    )]
    fn launch_ordinary_completion_role_with_registration(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        policy: &CompiledExecutionPolicy,
        suffix: &str,
        role: RunnerRole,
        register_session: bool,
        created_at_unix_ms: Option<u64>,
        cleanup_backend_override: Option<WorkerCleanupBackend>,
    ) -> CompletionRoleAdmission {
        assert!(
            register_session || role == RunnerRole::Applier,
            "only an unadmitted trusted-Applier fixture may remain sessionless"
        );
        let mut launch = harness.launch(suffix);
        if let Some(created_at_unix_ms) = created_at_unix_ms {
            launch.created_at_unix_ms = created_at_unix_ms;
        }
        launch.role = role;
        if role != RunnerRole::Worker {
            launch.worker_id = None;
            launch.worker_lease = None;
        }
        if role == RunnerRole::Applier {
            launch.shadow_root = None;
        }
        let prepared = prepare_launch(&harness.authority, policy, &launch)
            .expect("prepare exact retained completion runner");
        let launch = prepared.intent.clone();
        drop(prepared);
        let backend = cleanup_backend_override.unwrap_or_else(|| {
            ordinary_cleanup_backend(launch.purpose)
                .expect("derive completion launch backend from role and compile target")
        });
        let request = WorkerCleanupRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: launch.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: launch.session_id.clone(),
            policy_hash: launch.policy_hash.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            platform_backend: backend,
        };
        let request_bytes = serde_json::to_vec(&request).expect("encode launch cleanup request");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("cleanup-admission-effect-{suffix}"),
            idempotency_key: format!("cleanup-admission-key-{suffix}"),
            sprint_id: launch.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: launch.worker_lease.clone(),
            causation_event_id: None,
            correlation_id: format!("cleanup-admission-correlation-{suffix}"),
            kind: EffectKind::CleanupWorkerDomain,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: launch.policy_hash.clone(),
            input_snapshot: harness.base_snapshot.clone(),
            created_at_unix_ms: launch.created_at_unix_ms,
        };
        let event = proposal(
            &intent,
            ledger
                .next_sequence(&launch.sprint_id)
                .expect("next launch cleanup admission sequence"),
        );
        let cleanup = ledger
            .admit_runner_launch_with_cleanup(&launch, policy, &intent, &request_bytes, &event)
            .expect("atomically admit completion launch and cleanup");
        let session = RunnerSessionPolicyRecord {
            contract_version: CONTRACT_VERSION,
            sprint_id: launch.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: launch.session_id.clone(),
            purpose: launch.purpose,
            worker_id: launch.worker_id.clone(),
            worker_lease: launch.worker_lease.clone(),
            policy_hash: launch.policy_hash.clone(),
            session_nonce: unique_nonce(&format!("{suffix}-session")),
            runner_binary_digest: launch.runner_binary_digest.clone(),
            protocol_digest: launch.protocol_digest.clone(),
            private_state_digest: launch.private_state_digest.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            registered_at_unix_ms: launch.created_at_unix_ms + 1,
        };
        let task_attempt_running = if register_session {
            ledger
                .register_runner_session(&session, policy)
                .expect("register admitted completion runner session");
            RunnerLaunchLedger::Ordinary(ledger)
                .start_worker_attempt(&launch, &session)
                .expect("start exact completion task attempt")
        } else {
            None
        };
        CompletionRoleAdmission {
            launch: cleanup.launch,
            cleanup_request: cleanup.cleanup_request,
            cleanup_intent: cleanup.cleanup_effect.intent,
            cleanup_proposed_event_id: cleanup.cleanup_effect.proposed_event.event_id,
            session,
            task_attempt_running,
        }
    }

    fn launch_live_state_completion_role(
        harness: &TestHarness,
        ledger: &mut EventLedger,
        policy: &CompiledExecutionPolicy,
        plan: &SprintLiveStateCapturePlan,
        suffix: &str,
    ) -> CompletionRoleAdmission {
        launch_live_state_completion_role_with_registration(
            harness, ledger, policy, plan, suffix, true,
        )
    }
