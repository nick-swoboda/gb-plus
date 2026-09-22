    impl ModelProvider for MutationProvider {
        fn profile(&self) -> grok_build_core::ProviderProfile {
            FakeProvider::new().profile()
        }

        fn plan_sprint(&self, sprint: &SprintSpec) -> Result<ProviderResponse, ProviderError> {
            let mut response = FakeProvider::new().plan_sprint(sprint)?;
            if self.reverse_acceptance_checks {
                response.task_graph.tasks[0].acceptance_checks.reverse();
            }
            if self.duplicate_task {
                let mut second = response.task_graph.tasks[0].clone();
                second.task_id = format!("{}:task-2", sprint.sprint_id);
                second.goal = "Second task requiring an explicit integration rebase".into();
                response.task_graph.tasks.push(second);
            }
            response.validate_for_sprint(sprint)?;
            Ok(response)
        }

        fn next_turn(
            &self,
            sprint: &SprintSpec,
            task_graph: &TaskGraph,
            request: &ProviderTurnRequest,
        ) -> Result<ProviderTurn, ProviderError> {
            self.turns.set(self.turns.get().saturating_add(1));
            let index = usize::try_from(request.next_turn_sequence.saturating_sub(1))
                .map_err(|_| ProviderError::InvalidTurn("turn index exceeds usize".into()))?;
            let intent = self
                .intents
                .get(index)
                .cloned()
                .unwrap_or(ProviderToolIntent::TaskReadyForVerification);
            let sequence = request.next_turn_sequence;
            let turn = ProviderTurn {
                sprint_id: request.sprint_id.clone(),
                task_id: request.task_id.clone(),
                sequence,
                call: ProviderToolCall {
                    sprint_id: request.sprint_id.clone(),
                    task_id: request.task_id.clone(),
                    sequence,
                    call_id: format!("mutation-call-{sequence}"),
                    idempotency_key: format!("mutation-key-{sequence}"),
                    intent,
                },
            };
            turn.validate_for_request(sprint, task_graph, request)?;
            Ok(turn)
        }
    }

    #[derive(Clone, Default)]
    struct ProfileDriftProvider {
        calls: Rc<Cell<u32>>,
    }

    impl ModelProvider for ProfileDriftProvider {
        fn profile(&self) -> grok_build_core::ProviderProfile {
            let mut profile = FakeProvider::new().profile();
            profile.model_id = "different-model".into();
            profile
        }

        fn plan_sprint(&self, sprint: &SprintSpec) -> Result<ProviderResponse, ProviderError> {
            self.calls.set(self.calls.get().saturating_add(1));
            FakeProvider::new().plan_sprint(sprint)
        }
    }

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "grok-build-durable-{label}-{}-{sequence}",
                std::process::id()
            ));
            if root.exists() {
                fs::remove_dir_all(&root).expect("remove stale test directory");
            }
            fs::create_dir(&root).expect("create test directory");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("make test directory private");
            Self { root }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct Harness {
        directory: TestDirectory,
        workspace: PathBuf,
        database: PathBuf,
        authority: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        shadow: ShadowWorkspace,
        spec: SprintSpec,
        base: WorkspaceSnapshot,
    }

    impl Harness {
        fn new(label: &str) -> Self {
            Self::new_with_workspace(label, true)
        }

        fn new_empty(label: &str) -> Self {
            Self::new_with_workspace(label, false)
        }

        fn new_with_workspace(label: &str, populate_fixture: bool) -> Self {
            let directory = TestDirectory::new(label);
            let workspace = directory.path("workspace");
            fs::create_dir(&workspace).expect("create fixture workspace");
            if populate_fixture {
                fs::create_dir(workspace.join("src")).expect("create fixture source directory");
                write_file(&workspace.join("AGENTS.md"), FIXTURE_AGENTS);
                write_file(&workspace.join("Cargo.toml"), FIXTURE_MANIFEST);
                write_file(&workspace.join("Cargo.lock"), FIXTURE_LOCK);
                write_file(&workspace.join("README.md"), FIXTURE_README);
                write_file(&workspace.join("src/lib.rs"), FIXTURE_SOURCE);
            }

            let authority = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: format!("grant-{label}"),
                workspace_root: workspace.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
            })
            .expect("issue fixture grant");
            let manifest =
                WorkspaceManifest::capture(&authority, 1_000).expect("capture fixture base");
            let base = manifest.snapshot().clone();
            let sprint_id = format!("sprint-{label}");
            let spec = SprintSpec {
                sprint_id,
                objective: "Complete the deterministic walking-skeleton fixture".into(),
                acceptance_criteria: vec![AcceptanceCriterion {
                    criterion_id: "fixture-ready".into(),
                    description: "The deterministic fixture test passes".into(),
                    kind: AcceptanceKind::Automated(fixture_acceptance_command()),
                }],
                provider: FakeProvider::new().profile(),
                budget: SprintBudget {
                    max_tasks: 1,
                    max_attempts_per_task: 1,
                    max_tool_calls: 8,
                    max_duration_ms: 60_000,
                },
                max_workers: 1,
                workspace_grant: authority.contract().clone(),
                base_snapshot: base.snapshot_id.clone(),
            };
            let policy = ExecutionPolicyCompiler::compile(
                &authority,
                ExecutionPolicyRequest {
                    policy_id: format!("policy-{label}"),
                    read_scopes: vec![PathScope::Workspace],
                    write_scopes: vec![
                        PathScope::Relative(PathBuf::from("docs")),
                        PathScope::Relative(PathBuf::from("src")),
                    ],
                    environment: Vec::new(),
                    network: ExecutionNetwork::None,
                    mutation_mode: MutationMode::ShadowWorkspace,
                    resource_limits: ResourceLimits {
                        wall_time_ms: 60_000,
                        max_output_bytes: 1024 * 1024,
                        max_processes: 1,
                        max_memory_bytes: None,
                    },
                    approval_id: None,
                },
            )
            .expect("compile fixture policy");
            let shadow =
                ShadowWorkspace::create(&authority, &manifest, directory.path("private-shadow"))
                    .expect("create private shadow");
            let database = directory.path("state/ledger.sqlite3");
            fs::create_dir(database.parent().expect("database parent"))
                .expect("create database directory");
            fs::set_permissions(
                database.parent().expect("database parent"),
                fs::Permissions::from_mode(0o700),
            )
            .expect("make database directory private");

            Self {
                directory,
                workspace,
                database,
                authority,
                policy,
                shadow,
                spec,
                base,
            }
        }

        fn coordinator(
            &self,
            provider: CountingProvider,
        ) -> DurableWalkingSkeleton<CountingProvider, StrictFakeRunnerLifecycle> {
            self.coordinator_with_runner(provider, StrictFakeRunnerLifecycle)
        }

        fn coordinator_with_runner<P: ModelProvider, R: WalkingSkeletonRunnerLifecycle>(
            &self,
            provider: P,
            runner_lifecycle: R,
        ) -> DurableWalkingSkeleton<P, R> {
            DurableWalkingSkeleton::open_with_runner_lifecycle(
                &self.database,
                provider,
                runner_lifecycle,
            )
            .expect("open coordinator")
        }

        fn initialize<P: ModelProvider>(&self, provider: P) {
            let mut coordinator = self.coordinator_with_runner(provider, StrictFakeRunnerLifecycle);
            coordinator
                .create_draft(&self.authority, &self.spec, &self.base, 1_001)
                .expect("create draft sprint");
        }

        fn fresh_base_shadow(&self, name: &str) -> ShadowWorkspace {
            let manifest = WorkspaceManifest::capture(&self.authority, 1_500)
                .expect("recapture unchanged live base");
            ShadowWorkspace::create(&self.authority, &manifest, self.directory.path(name))
                .expect("create replacement base shadow")
        }
    }

    struct TaskDoneTrampolineScenario {
        harness: Harness,
        coordinator:
            Box<DurableWalkingSkeleton<MutationProvider, FinalVerificationScriptRunnerLifecycle>>,
        candidate: WalkingSkeletonStatus,
        launch_count: Rc<Cell<u32>>,
        dispatch_count: Rc<Cell<u32>>,
    }

    impl TaskDoneTrampolineScenario {
        fn new(label: &str) -> Self {
            let harness = Harness::new(label);
            let launch_count = Rc::new(Cell::new(0));
            let dispatch_count = Rc::new(Cell::new(0));
            let acknowledgements = Rc::new(Cell::new(0));
            let cleanup_count = Rc::new(Cell::new(0));
            let runner = FinalVerificationScriptRunnerLifecycle::new(
                FinalVerificationDispatchBehavior::Exact,
                Rc::clone(&launch_count),
                Rc::clone(&dispatch_count),
                acknowledgements,
                cleanup_count,
            );
            let mut coordinator = Box::new(
                DurableWalkingSkeleton::open_with_runner_lifecycle(
                    &harness.database,
                    MutationProvider::new(Vec::new()),
                    runner,
                )
                .expect("open TaskDone trampoline scenario"),
            );
            coordinator
                .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
                .expect("create TaskDone trampoline draft");
            let formal_checks = coordinator
                .run_until_blocked_inner(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                    PlanningPause::None,
                    false,
                    false,
                )
                .expect("reach exact durable FormalChecks handoff");
            let WalkingSkeletonStatus::FormalChecksReady {
                task_id,
                sealed_snapshot,
                allow_fresh_dispatch,
            } = formal_checks
            else {
                panic!("TaskDone trampoline scenario requires exact FormalChecks handoff")
            };
            let candidate = coordinator
                .continue_formal_checks_handoff(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                    &task_id,
                    &sealed_snapshot,
                    allow_fresh_dispatch,
                )
                .expect("continue exact FormalChecks handoff to Candidate");
            assert!(matches!(
                candidate,
                WalkingSkeletonStatus::CandidateReadyForIntegration { .. }
            ));
            assert_eq!(launch_count.get(), 0);
            assert_eq!(dispatch_count.get(), 0);
            Self {
                harness,
                coordinator,
                candidate,
                launch_count,
                dispatch_count,
            }
        }

        fn advance_to_task_done(&mut self, now_unix_ms: u64) -> WalkingSkeletonStatus {
            let WalkingSkeletonStatus::CandidateReadyForIntegration {
                task_id,
                change_set_id,
                sealed_snapshot,
            } = &self.candidate
            else {
                panic!("TaskDone trampoline scenario requires exact Candidate handoff")
            };
            let status = self
                .coordinator
                .continue_candidate_handoff(
                    &self.harness.spec.sprint_id,
                    &self.harness.authority,
                    &self.harness.policy,
                    &self.harness.shadow,
                    now_unix_ms,
                    task_id,
                    change_set_id,
                    sealed_snapshot,
                )
                .expect("advance exact Candidate through integration and cleanup");
            assert!(matches!(status, WalkingSkeletonStatus::TaskDone { .. }));
            assert_eq!(self.launch_count.get(), 0);
            assert_eq!(self.dispatch_count.get(), 0);
            status
        }

        fn continue_task_done(
            &mut self,
            status: &WalkingSkeletonStatus,
            now_unix_ms: u64,
        ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
            let WalkingSkeletonStatus::TaskDone {
                task_id,
                integration_receipt_id,
                result_snapshot,
            } = status
            else {
                panic!("TaskDone continuation requires exact TaskDone status")
            };
            self.coordinator.continue_task_done_handoff(
                &self.harness.spec.sprint_id,
                &self.harness.authority,
                &self.harness.policy,
                &self.harness.shadow,
                now_unix_ms,
                task_id,
                integration_receipt_id,
                result_snapshot,
            )
        }
    }

    struct ApplicationScenario {
        coordinator:
            Box<DurableWalkingSkeleton<MutationProvider, ApplicationScriptRunnerLifecycle>>,
        harness: Harness,
        final_snapshot: Digest,
        final_verification_receipt_id: String,
        launch_count: Rc<Cell<u32>>,
        dispatch_count: Rc<Cell<u32>>,
        cleanup_count: Rc<Cell<u32>>,
    }

    impl ApplicationScenario {
        fn new(
            label: &str,
            behavior: ApplicationDispatchBehavior,
            nonempty_change_set: bool,
        ) -> Self {
            let harness = Harness::new(label);
            Self::new_with_harness(harness, label, behavior, nonempty_change_set)
        }

        fn new_empty(label: &str, behavior: ApplicationDispatchBehavior) -> Self {
            Self::new_with_harness(Harness::new_empty(label), label, behavior, false)
        }

        fn new_human_empty(label: &str, behavior: ApplicationDispatchBehavior) -> Self {
            let mut harness = Harness::new_empty(label);
            harness.spec.acceptance_criteria = vec![
                automated_criterion("automated"),
                human_criterion("human-review"),
            ];
            let launch_count = Rc::new(Cell::new(0));
            let dispatch_count = Rc::new(Cell::new(0));
            let cleanup_count = Rc::new(Cell::new(0));
            let mut coordinator = Box::new(
                DurableWalkingSkeleton::open_with_runner_lifecycle(
                    &harness.database,
                    MutationProvider::new(Vec::new()),
                    ApplicationScriptRunnerLifecycle::new(
                        behavior,
                        Rc::clone(&launch_count),
                        Rc::clone(&dispatch_count),
                        Rc::clone(&cleanup_count),
                    ),
                )
                .expect("open human application scenario coordinator"),
            );
            coordinator
                .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
                .expect("create human application scenario draft");
            assert!(matches!(
                coordinator
                    .run_until_blocked(
                        &harness.spec.sprint_id,
                        &harness.authority,
                        &harness.policy,
                        &harness.shadow,
                        2_000,
                    )
                    .expect("reach human application acceptance handoff"),
                WalkingSkeletonStatus::AwaitingAcceptance { .. }
            ));
            let prompt = coordinator
                .issue_human_acceptance_prompt_for_ui(
                    &harness.spec.sprint_id,
                    "human-application-ui-session",
                    "human-review",
                )
                .expect("issue human application prompt")
                .prompt;
            let decided_at = coordinator
                .load_sprint(&harness.spec.sprint_id)
                .expect("reload human prompt event cut")
                .events
                .last()
                .expect("human prompt requires an existing sprint event")
                .occurred_at_unix_ms
                .checked_add(1)
                .expect("human prompt fixture timestamp remains representable");
            coordinator
                .consume_human_acceptance_prompt_from_ui(
                    &prompt.prompt_id,
                    "human-application-ui-session",
                    HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
                    decided_at,
                )
                .expect("accept human application prompt");
            let ready = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    4_000,
                )
                .expect("reach exact human application handoff");
            let WalkingSkeletonStatus::ReadyForApplication {
                final_snapshot,
                verification_receipt_id: final_verification_receipt_id,
            } = ready
            else {
                panic!("unexpected human pre-application status: {ready:?}")
            };
            Self {
                coordinator,
                harness,
                final_snapshot,
                final_verification_receipt_id,
                launch_count,
                dispatch_count,
                cleanup_count,
            }
        }

        fn new_with_harness(
            harness: Harness,
            label: &str,
            behavior: ApplicationDispatchBehavior,
            nonempty_change_set: bool,
        ) -> Self {
            let intents = if nonempty_change_set {
                vec![ProviderToolIntent::CreateRegularFile {
                    path: PathBuf::from("docs/application.txt"),
                    contents: format!("application scenario {label}\n").into_bytes(),
                }]
            } else {
                Vec::new()
            };
            let provider = MutationProvider::new(intents);
            let launch_count = Rc::new(Cell::new(0));
            let dispatch_count = Rc::new(Cell::new(0));
            let cleanup_count = Rc::new(Cell::new(0));
            let runner = ApplicationScriptRunnerLifecycle::new(
                behavior,
                Rc::clone(&launch_count),
                Rc::clone(&dispatch_count),
                Rc::clone(&cleanup_count),
            );
            let mut coordinator = Box::new(
                DurableWalkingSkeleton::open_with_runner_lifecycle(
                    &harness.database,
                    provider,
                    runner,
                )
                .expect("open application scenario coordinator"),
            );
            coordinator
                .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
                .expect("create application scenario draft");
            let ready = coordinator
                .run_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &harness.shadow,
                    2_000,
                )
                .expect("reach exact application handoff");
            let WalkingSkeletonStatus::ReadyForApplication {
                final_snapshot,
                verification_receipt_id: final_verification_receipt_id,
            } = ready
            else {
                panic!("unexpected pre-application status: {ready:?}")
            };
            Self {
                coordinator,
                harness,
                final_snapshot,
                final_verification_receipt_id,
                launch_count,
                dispatch_count,
                cleanup_count,
            }
        }

        fn continue_application(
            &mut self,
            now_unix_ms: u64,
        ) -> Result<WalkingSkeletonStatus, DurableCoordinatorError> {
            self.coordinator.run_application_until_blocked(
                &self.harness.spec.sprint_id,
                &self.harness.authority,
                &self.harness.policy,
                &self.final_snapshot,
                &self.final_verification_receipt_id,
                now_unix_ms,
            )
        }

        fn restart(self, behavior: ApplicationDispatchBehavior) -> Self {
            let Self {
                coordinator,
                harness,
                final_snapshot,
                final_verification_receipt_id,
                ..
            } = self;
            drop(coordinator);
            let launch_count = Rc::new(Cell::new(0));
            let dispatch_count = Rc::new(Cell::new(0));
            let cleanup_count = Rc::new(Cell::new(0));
            let coordinator = Box::new(
                DurableWalkingSkeleton::open_with_runner_lifecycle(
                    &harness.database,
                    MutationProvider::new(Vec::new()),
                    ApplicationScriptRunnerLifecycle::new(
                        behavior,
                        Rc::clone(&launch_count),
                        Rc::clone(&dispatch_count),
                        Rc::clone(&cleanup_count),
                    ),
                )
                .expect("reopen application scenario coordinator"),
            );
            Self {
                coordinator,
                harness,
                final_snapshot,
                final_verification_receipt_id,
                launch_count,
                dispatch_count,
                cleanup_count,
            }
        }
    }

    fn applied_live_state_fixture(name: &str) -> (Harness, String) {
        let mut scenario = ApplicationScenario::new(name, ApplicationDispatchBehavior::Exact, true);
        let applied = scenario
            .continue_application(8_000)
            .expect("persist exact applied branch for live-state fixture");
        assert!(matches!(
            applied,
            WalkingSkeletonStatus::ApplicationApplied { .. }
        ));
        let ApplicationScenario {
            coordinator,
            harness,
            final_verification_receipt_id,
            ..
        } = scenario;
        drop(coordinator);
        (harness, final_verification_receipt_id)
    }

    #[test]
    fn application_custody_remains_indirect_and_stack_bounded() {
        let authority_size = std::mem::size_of::<RunnerEffectObservationAuthority>();
        assert!(
            std::mem::size_of::<WalkingSkeletonApplicationOutcome>() <= 64,
            "successful application evidence must remain indirect"
        );
        assert!(
            std::mem::size_of::<WalkingSkeletonClaimedApplicationResponse>() <= authority_size + 64,
            "the complete repeated application response must remain indirect"
        );
        assert!(
            std::mem::size_of::<PendingClaimedTerminal>() <= authority_size + 3_072,
            "application artifacts must not expand every pending-terminal variant inline"
        );
    }

    #[test]
    fn live_state_capture_custody_remains_indirect_and_stack_bounded() {
        let authority_size = std::mem::size_of::<RunnerEffectObservationAuthority>();
        assert!(
            std::mem::size_of::<WalkingSkeletonLiveStateCaptureOutcome>() <= 64,
            "successful live-state capture evidence must remain indirect"
        );
        assert!(
            std::mem::size_of::<ClaimedLiveStateCaptureTerminal>() <= authority_size + 256,
            "sealed capture evidence must remain indirect beside its authority"
        );
        assert!(
            std::mem::size_of::<WalkingSkeletonClaimedLiveStateCaptureResponse>() <= 32,
            "the public claimed live-state response must contain only indirect custody"
        );
        assert!(
            std::mem::size_of::<PendingClaimedTerminal>() <= authority_size + 3_072,
            "live-state artifacts must not expand every pending-terminal variant inline"
        );
    }

    #[test]
    fn public_task_done_trampoline_equals_three_explicit_durable_handoffs() {
        let label = "task-done-trampoline-equivalence";
        let public_harness = Harness::new(label);
        let public_launches = Rc::new(Cell::new(0));
        let public_dispatches = Rc::new(Cell::new(0));
        let public_runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&public_launches),
            Rc::clone(&public_dispatches),
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
        );
        let mut public = Box::new(
            DurableWalkingSkeleton::open_with_runner_lifecycle(
                &public_harness.database,
                MutationProvider::new(Vec::new()),
                public_runner,
            )
            .expect("open public TaskDone trampoline coordinator"),
        );
        public
            .create_draft(
                &public_harness.authority,
                &public_harness.spec,
                &public_harness.base,
                1_001,
            )
            .expect("create public TaskDone trampoline draft");
        let public_result = public
            .run_until_blocked(
                &public_harness.spec.sprint_id,
                &public_harness.authority,
                &public_harness.policy,
                &public_harness.shadow,
                2_000,
            )
            .expect("run public FormalChecks, Candidate, and TaskDone trampoline");

        let mut explicit = TaskDoneTrampolineScenario::new(label);
        let task_done = explicit.advance_to_task_done(2_000);
        let explicit_result = explicit
            .continue_task_done(&task_done, 2_000)
            .expect("continue exact TaskDone handoff explicitly");

        assert_eq!(public_result, explicit_result);
        assert!(matches!(
            public_result,
            WalkingSkeletonStatus::ReadyForApplication { .. }
        ));
        assert_eq!((public_launches.get(), public_dispatches.get()), (1, 1));
        assert_eq!(
            (explicit.launch_count.get(), explicit.dispatch_count.get()),
            (1, 1)
        );
    }

    #[test]
    fn task_done_handoff_rejects_substituted_identity_before_final_verifier_launch() {
        let mut scenario = TaskDoneTrampolineScenario::new("task-done-crossed-handoff");
        let task_done = scenario.advance_to_task_done(3_000);
        let WalkingSkeletonStatus::TaskDone {
            task_id,
            integration_receipt_id,
            result_snapshot,
        } = &task_done
        else {
            unreachable!("scenario guarantees TaskDone")
        };

        let substitutions = [
            (
                "crossed task",
                "crossed-task".to_owned(),
                integration_receipt_id.clone(),
                result_snapshot.clone(),
            ),
            (
                "crossed integration receipt",
                task_id.clone(),
                "crossed-integration-receipt".to_owned(),
                result_snapshot.clone(),
            ),
            (
                "crossed result snapshot",
                task_id.clone(),
                integration_receipt_id.clone(),
                Digest::sha256(b"crossed TaskDone result snapshot"),
            ),
        ];
        for (label, task_id, receipt_id, snapshot) in substitutions {
            let error = scenario
                .coordinator
                .continue_task_done_handoff(
                    &scenario.harness.spec.sprint_id,
                    &scenario.harness.authority,
                    &scenario.harness.policy,
                    &scenario.harness.shadow,
                    4_000,
                    &task_id,
                    &receipt_id,
                    &snapshot,
                )
                .expect_err("crossed TaskDone handoff must fail closed");
            assert!(
                matches!(error, DurableCoordinatorError::Protocol(_)),
                "unexpected {label} result: {error}"
            );
        }
        assert_eq!(scenario.launch_count.get(), 0);
        assert_eq!(scenario.dispatch_count.get(), 0);
    }

    #[test]
    fn task_done_shadow_drift_blocks_before_final_verifier_launch() {
        let mut scenario = TaskDoneTrampolineScenario::new("task-done-shadow-drift");
        let task_done = scenario.advance_to_task_done(3_000);
        fs::write(
            scenario.harness.shadow.root().join("README.md"),
            b"adversarial shadow drift after TaskDone\n",
        )
        .expect("drift private shadow after TaskDone");

        let error = scenario
            .continue_task_done(&task_done, 4_000)
            .expect_err("shadow drift must block final verification");
        assert!(matches!(
            error,
            DurableCoordinatorError::Protocol(ref message)
                if message.contains("private shadow snapshot changed")
        ));
        assert_eq!(scenario.launch_count.get(), 0);
        assert_eq!(scenario.dispatch_count.get(), 0);
    }

    #[test]
    fn recovered_candidate_never_remints_integration_dispatch() {
        let scenario = TaskDoneTrampolineScenario::new("candidate-restart-no-remint");
        let TaskDoneTrampolineScenario {
            harness,
            coordinator,
            candidate,
            ..
        } = scenario;
        assert!(matches!(
            &candidate,
            WalkingSkeletonStatus::CandidateReadyForIntegration { .. }
        ));
        drop(coordinator);

        let preparations = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let acknowledgements = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let runner = IntegrationScriptRunnerLifecycle::new(
            IntegrationDispatchBehavior::Exact,
            Rc::clone(&preparations),
            Rc::clone(&dispatches),
            acknowledgements,
            cleanups,
        );
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            runner,
        )
        .expect("reopen durable Candidate");
        let status = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                4_000,
            )
            .expect("recover Candidate without integration authority");
        assert_eq!(
            status,
            WalkingSkeletonStatus::TaskPhaseReconciliationRequired {
                task_id: match candidate {
                    WalkingSkeletonStatus::CandidateReadyForIntegration { task_id, .. } => task_id,
                    _ => unreachable!("candidate was checked above"),
                },
                phase: "Candidate",
            }
        );
        assert_eq!(preparations.get(), 0);
        assert_eq!(dispatches.get(), 0);
    }

    #[test]
    fn phase_handoff_guard_rejects_no_progress_and_excess_before_downstream_effect() {
        let formal_checks = WalkingSkeletonStatus::FormalChecksReady {
            task_id: "task-1".into(),
            sealed_snapshot: Digest::sha256(b"candidate-1"),
            allow_fresh_dispatch: true,
        };
        let candidate = WalkingSkeletonStatus::CandidateReadyForIntegration {
            task_id: "task-1".into(),
            change_set_id: "change-set-1".into(),
            sealed_snapshot: Digest::sha256(b"candidate-1"),
        };
        let task_done = WalkingSkeletonStatus::TaskDone {
            task_id: "task-1".into(),
            integration_receipt_id: "receipt-1".into(),
            result_snapshot: Digest::sha256(b"candidate-1"),
        };
        let another_candidate = WalkingSkeletonStatus::CandidateReadyForIntegration {
            task_id: "task-2".into(),
            change_set_id: "change-set-2".into(),
            sealed_snapshot: Digest::sha256(b"candidate-2"),
        };

        let downstream_effects = Cell::new(0_u32);
        let mut no_progress = DurablePhaseHandoffTracker::default();
        assert_eq!(
            no_progress
                .observe(&candidate)
                .expect("accept first handoff"),
            Some(DurablePhaseHandoffKind::Candidate)
        );
        downstream_effects.set(downstream_effects.get() + 1);
        assert!(matches!(
            no_progress.observe(&candidate),
            Err(DurableCoordinatorError::Protocol(ref message))
                if message.contains("no durable handoff progress")
        ));
        assert_eq!(downstream_effects.get(), 1);

        let mut bounded = DurablePhaseHandoffTracker::default();
        for status in [&formal_checks, &candidate, &task_done] {
            bounded.observe(status).expect("accept bounded handoff");
            downstream_effects.set(downstream_effects.get() + 1);
        }
        let before_excess = downstream_effects.get();
        assert!(matches!(
            bounded.observe(&another_candidate),
            Err(DurableCoordinatorError::Protocol(ref message))
                if message.contains("exceeded FormalChecks, Candidate, and TaskDone bounds")
        ));
        assert_eq!(downstream_effects.get(), before_excess);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "both stale TaskDone continuations prove a distinct unresolved terminal class blocks final-verifier relaunch"
    )]
    fn task_done_handoff_cannot_relaunch_across_pending_terminal_or_command_unknown() {
        let label = "task-done-terminal-guards";
        let mut pending = TaskDoneTrampolineScenario::new(label);
        let task_done = pending.advance_to_task_done(3_000);
        pending
            .coordinator
            .inject_final_terminal_precommit_failure_for_test(LedgerError::Io(io::Error::other(
                "injected TaskDone final terminal contention",
            )));
        assert!(matches!(
            pending.continue_task_done(&task_done, 4_000),
            Err(DurableCoordinatorError::Ledger(LedgerError::Io(_)))
        ));
        assert!(pending.coordinator.pending_claimed_terminal.is_some());
        let effects_before_retry = (pending.launch_count.get(), pending.dispatch_count.get());
        assert!(matches!(
            pending
                .continue_task_done(&task_done, 5_000)
                .expect("pending final terminal remains reconciliation-only"),
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::RunCommand,
                ..
            }
        ));
        assert_eq!(
            (pending.launch_count.get(), pending.dispatch_count.get()),
            effects_before_retry,
            "unresolved claimed terminal must not mint a replacement final verifier"
        );

        let stale_task_done = task_done;
        let mut unknown_harness = Harness::new(label);
        unknown_harness.spec.acceptance_criteria = vec![automated_criterion("only")];
        let order = Rc::new(RefCell::new(Vec::new()));
        let acknowledgements = Rc::new(Cell::new(0));
        let mut unknown_writer = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &unknown_harness.database,
            MutationProvider::new(Vec::new()),
            FormalScriptRunnerLifecycle::new(
                FormalDispatchBehavior::PartialWrite,
                order,
                acknowledgements,
            ),
        )
        .expect("open task-command Unknown branch");
        unknown_writer
            .create_draft(
                &unknown_harness.authority,
                &unknown_harness.spec,
                &unknown_harness.base,
                1_001,
            )
            .expect("create task-command Unknown branch");
        assert!(matches!(
            unknown_writer
                .run_until_blocked(
                    &unknown_harness.spec.sprint_id,
                    &unknown_harness.authority,
                    &unknown_harness.policy,
                    &unknown_harness.shadow,
                    2_000,
                )
                .expect("terminalize exact task-command Unknown"),
            WalkingSkeletonStatus::SprintUnknown { .. }
        ));
        drop(unknown_writer);

        let unknown_launches = Rc::new(Cell::new(0));
        let unknown_dispatches = Rc::new(Cell::new(0));
        let runner = FinalVerificationScriptRunnerLifecycle::new(
            FinalVerificationDispatchBehavior::Exact,
            Rc::clone(&unknown_launches),
            Rc::clone(&unknown_dispatches),
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
        );
        let mut unknown_reader = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &unknown_harness.database,
            MutationProvider::new(Vec::new()),
            runner,
        )
        .expect("reopen terminal task-command Unknown branch");
        let WalkingSkeletonStatus::TaskDone {
            task_id,
            integration_receipt_id,
            result_snapshot,
        } = stale_task_done
        else {
            unreachable!("pending scenario produced TaskDone")
        };
        assert!(matches!(
            unknown_reader.continue_task_done_handoff(
                &unknown_harness.spec.sprint_id,
                &unknown_harness.authority,
                &unknown_harness.policy,
                &unknown_harness.shadow,
                6_000,
                &task_id,
                &integration_receipt_id,
                &result_snapshot,
            ),
            Err(DurableCoordinatorError::Protocol(_))
        ));
        assert_eq!(unknown_launches.get(), 0);
        assert_eq!(unknown_dispatches.get(), 0);
    }

    #[test]
    fn coordinator_retries_only_after_cleanup_disposition_then_exhausts() {
        let mut harness = Harness::new("pre-session-retry-exhaustion");
        harness.spec.budget.max_attempts_per_task = 2;
        let trace = Rc::new(RefCell::new(Vec::new()));
        let provider = CountingProvider::default();
        let mut coordinator = harness.coordinator_with_runner(
            provider.clone(),
            PreSessionRetryScriptLifecycle::new(Rc::clone(&trace)),
        );
        coordinator
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create retry/exhaustion draft");
        let status = coordinator
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("drive both refused attempts through atomic cleanup disposition");
        let WalkingSkeletonStatus::TaskAttemptsExhausted {
            task_id,
            attempt_id,
            launch_id,
            disposition_id,
        } = &status
        else {
            panic!("unexpected pre-session exhaustion status: {status:?}");
        };
        assert!(!task_id.is_empty());
        assert!(!attempt_id.is_empty());
        assert!(!launch_id.is_empty());
        assert!(!disposition_id.is_empty());
        let trace = trace.borrow();
        assert_eq!(trace.len(), 4);
        let first_attempt = trace[0]
            .strip_prefix("ensure:")
            .expect("first trace is ensure");
        assert_eq!(trace[1], format!("cleanup:{first_attempt}:Retryable"));
        let second_attempt = trace[2]
            .strip_prefix("ensure:")
            .expect("third trace is second ensure");
        assert_ne!(first_attempt, second_attempt);
        assert_eq!(
            trace[3],
            format!("cleanup:{second_attempt}:AttemptsExhausted")
        );
        assert_eq!(attempt_id, second_attempt);
        assert_eq!(provider.planning_calls(), 1);
        assert_eq!(provider.turn_calls(), 0);
    }

    #[test]
    fn coordinator_reopens_exact_task_attempts_exhausted_status_without_lifecycle_calls() {
        let mut harness = Harness::new("pre-session-exhaustion-reopen");
        harness.spec.budget.max_attempts_per_task = 2;
        let initial_trace = Rc::new(RefCell::new(Vec::new()));
        let mut initial = harness.coordinator_with_runner(
            CountingProvider::default(),
            PreSessionRetryScriptLifecycle::new(Rc::clone(&initial_trace)),
        );
        initial
            .create_draft(&harness.authority, &harness.spec, &harness.base, 1_001)
            .expect("create exhaustion-reopen draft");
        let status = initial
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                2_000,
            )
            .expect("persist exact AttemptsExhausted status");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::TaskAttemptsExhausted { .. }
        ));
        assert_eq!(initial_trace.borrow().len(), 4);
        drop(initial);

        let restart_trace = Rc::new(RefCell::new(Vec::new()));
        let restart_provider = CountingProvider::default();
        let mut restarted = harness.coordinator_with_runner(
            restart_provider.clone(),
            PreSessionRetryScriptLifecycle::new(Rc::clone(&restart_trace)),
        );
        let recovered = restarted
            .run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                3_000,
            )
            .expect("reconstruct exact exhausted status after reopen");
        assert_eq!(recovered, status);
        assert!(restart_trace.borrow().is_empty());
        assert_eq!(restart_provider.planning_calls(), 0);
        assert_eq!(restart_provider.turn_calls(), 0);
    }

    #[test]
    fn application_success_commits_rollback_cleans_applier_and_existing_never_reexecutes() {
        let mut scenario = ApplicationScenario::new(
            "application-success-existing",
            ApplicationDispatchBehavior::Exact,
            true,
        );
        let status = scenario
            .continue_application(8_000)
            .expect("apply exact assembled change set");
        let WalkingSkeletonStatus::ApplicationApplied {
            final_snapshot,
            application_receipt_id,
            rollback_reference_id,
        } = status
        else {
            panic!("unexpected application result: {status:?}")
        };
        assert_eq!(final_snapshot, scenario.final_snapshot);
        assert_eq!(scenario.launch_count.get(), 1);
        assert_eq!(scenario.dispatch_count.get(), 1);
        assert_eq!(scenario.cleanup_count.get(), 1);
        let evidence = scenario
            .coordinator
            .ledger
            .load_application_evidence(&application_receipt_id)
            .expect("load exact application evidence");
        let rollback = scenario
            .coordinator
            .ledger
            .load_rollback_reference(&rollback_reference_id)
            .expect("load atomically reopened rollback reference");
        assert_eq!(
            rollback.reference.application_receipt_id,
            evidence.receipt.receipt_id
        );
        let admission = scenario
            .coordinator
            .ledger
            .load_sprint_application_admission(&application_identity(
                &scenario.harness.spec.sprint_id,
                "admission",
            ))
            .expect("load application admission");
        assert!(
            application_runner_cleanup_complete(&scenario.coordinator.ledger, &admission)
                .expect("assess exact Applier cleanup")
        );

        let ApplicationScenario {
            coordinator,
            harness,
            final_snapshot,
            final_verification_receipt_id,
            ..
        } = scenario;
        drop(coordinator);
        let restart_launches = Rc::new(Cell::new(0));
        let restart_dispatches = Rc::new(Cell::new(0));
        let restart_cleanups = Rc::new(Cell::new(0));
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            ApplicationScriptRunnerLifecycle::new(
                ApplicationDispatchBehavior::Exact,
                Rc::clone(&restart_launches),
                Rc::clone(&restart_dispatches),
                Rc::clone(&restart_cleanups),
            ),
        )
        .expect("reopen applied application");
        assert!(matches!(
            restarted
                .run_application_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &final_snapshot,
                    &final_verification_receipt_id,
                    9_000,
                )
                .expect("recover application by exact readback"),
            WalkingSkeletonStatus::ApplicationApplied { .. }
        ));
        assert_eq!(restart_launches.get(), 0);
        assert_eq!(restart_dispatches.get(), 0);
        assert_eq!(restart_cleanups.get(), 0);
    }

    #[test]
    fn applied_live_state_capture_is_typed_cleaned_and_existing_is_readback_only() {
        let mut scenario = ApplicationScenario::new(
            "live-state-applied-fresh-existing",
            ApplicationDispatchBehavior::Exact,
            true,
        );
        let applied = scenario
            .continue_application(8_000)
            .expect("persist exact applied branch");
        assert!(matches!(
            applied,
            WalkingSkeletonStatus::ApplicationApplied { .. }
        ));
        let ApplicationScenario {
            coordinator,
            harness,
            final_verification_receipt_id,
            ..
        } = scenario;
        drop(coordinator);

        let mut capture = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            StrictFakeRunnerLifecycle,
        )
        .expect("open applied capture continuation");
        let status = capture
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect("capture and clean applied live state");
        let WalkingSkeletonStatus::LiveStateCaptured {
            capture_receipt_id,
            expected_snapshot,
            observed_snapshot,
            matches_expected_snapshot,
        } = status
        else {
            panic!("unexpected applied capture status: {status:?}")
        };
        assert_ne!(expected_snapshot, observed_snapshot);
        assert!(!matches_expected_snapshot);
        let evidence = capture
            .ledger
            .load_live_state_capture_evidence(&capture_receipt_id)
            .expect("load typed applied live-state evidence");
        let admission = capture
            .ledger
            .load_sprint_live_state_capture_admission(&live_state_capture_identity(
                &harness.spec.sprint_id,
                "admission",
            ))
            .expect("load applied capture admission");
        let effect = capture
            .ledger
            .load_effect(&admission.effect_id)
            .expect("load terminal applied capture");
        assert!(matches!(
            admission.plan.branch,
            LiveStateCaptureBranch::Applied { .. }
        ));
        assert_eq!(effect.dispatch_claim.as_ref().map(|_| 1), Some(1));
        assert!(
            live_state_capture_cleanup_complete(&capture.ledger, &admission, &effect)
                .expect("assess applied verifier cleanup")
        );
        assert_eq!(evidence.receipt.observed_snapshot, observed_snapshot);
        drop(capture);

        let mut restarted =
            DurableWalkingSkeleton::open(&harness.database, MutationProvider::new(Vec::new()))
                .expect("reopen with unavailable lifecycle");
        let replay = restarted
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                13_000,
            )
            .expect("existing capture is pure readback");
        assert_eq!(
            replay,
            WalkingSkeletonStatus::LiveStateCaptured {
                capture_receipt_id,
                expected_snapshot,
                observed_snapshot,
                matches_expected_snapshot: false,
            }
        );
    }

    #[test]
    fn verified_no_op_live_state_capture_uses_exact_task_done_source() {
        let mut scenario = ApplicationScenario::new(
            "live-state-verified-no-op",
            ApplicationDispatchBehavior::Exact,
            false,
        );
        let no_op = scenario
            .continue_application(8_000)
            .expect("classify exact verified no-op");
        assert!(matches!(
            no_op,
            WalkingSkeletonStatus::VerifiedNoOpCaptureRequired { .. }
        ));
        let ApplicationScenario {
            coordinator,
            harness,
            final_verification_receipt_id,
            ..
        } = scenario;
        drop(coordinator);
        let mut capture = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            StrictFakeRunnerLifecycle,
        )
        .expect("open verified-no-op capture continuation");
        let status = capture
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect("capture verified-no-op live state");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::LiveStateCaptured { .. }
        ));
        let admission = capture
            .ledger
            .load_sprint_live_state_capture_admission(&live_state_capture_identity(
                &harness.spec.sprint_id,
                "admission",
            ))
            .expect("load verified-no-op capture admission");
        let LiveStateCaptureBranch::VerifiedNoOp {
            final_verification_receipt_id: stored_final,
            task_integration_receipt_id,
        } = admission.plan.branch
        else {
            panic!("expected VerifiedNoOp capture plan")
        };
        assert_eq!(stored_final, final_verification_receipt_id);
        assert!(
            capture
                .ledger
                .load_task_integration_receipt(&task_integration_receipt_id)
                .is_ok()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The fixture asserts one complete no-op completion and restart proof.
    fn verified_no_op_completion_is_exact_and_restart_is_readback_only() {
        let mut scenario = ApplicationScenario::new_empty(
            "completion-verified-no-op",
            ApplicationDispatchBehavior::Exact,
        );
        assert!(matches!(
            scenario
                .continue_application(8_000)
                .expect("classify exact completion no-op"),
            WalkingSkeletonStatus::VerifiedNoOpCaptureRequired { .. }
        ));
        let ApplicationScenario {
            coordinator,
            harness,
            final_verification_receipt_id,
            ..
        } = scenario;
        drop(coordinator);

        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            StrictFakeRunnerLifecycle,
        )
        .expect("open no-op completion capture continuation");
        let capture = coordinator
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect("capture exact no-op live state");
        let WalkingSkeletonStatus::LiveStateCaptured {
            capture_receipt_id,
            expected_snapshot,
            observed_snapshot,
            matches_expected_snapshot: true,
        } = capture
        else {
            panic!("unexpected no-op capture state: {capture:?}")
        };
        assert_eq!(expected_snapshot, observed_snapshot);

        let completed = WalkingSkeletonStatus::Completed {
            completion_receipt_id: completion_identity(&harness.spec.sprint_id, "receipt"),
            final_report_id: completion_identity(&harness.spec.sprint_id, "report"),
            completion_event_id: completion_identity(&harness.spec.sprint_id, "event"),
            final_snapshot: expected_snapshot.clone(),
        };
        coordinator.inject_terminalization_postcommit_uncertainty_for_test();
        assert!(matches!(
            coordinator.run_completion_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &capture_receipt_id,
                14_000,
            ),
            Err(DurableCoordinatorError::Ledger(
                LedgerError::PostCommitStateUncertain { .. }
            ))
        ));
        let durable = coordinator
            .ledger
            .load_completion(&harness.spec.sprint_id)
            .expect("load exact desktop completion")
            .expect("desktop completion is durable");
        assert!(matches!(
            durable.live_state_authority,
            PersistedCompletionLiveStateAuthority::Linked { .. }
        ));
        let event_count = coordinator
            .ledger
            .load_sprint(&harness.spec.sprint_id)
            .expect("inspect committed completion behind poisoned test handle")
            .events
            .len();
        assert!(matches!(
            coordinator.run_completion_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &capture_receipt_id,
                15_000,
            ),
            Err(DurableCoordinatorError::Protocol(message))
                if message.contains("dropped and reopened")
        ));
        assert!(matches!(
            coordinator.run_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &harness.shadow,
                15_000,
            ),
            Err(DurableCoordinatorError::Protocol(message))
                if message.contains("dropped and reopened")
        ));
        assert!(matches!(
            coordinator.load_sprint(&harness.spec.sprint_id),
            Err(DurableCoordinatorError::Protocol(message))
                if message.contains("dropped and reopened")
        ));
        assert!(matches!(
            coordinator.create_draft(&harness.authority, &harness.spec, &harness.base, 15_000),
            Err(DurableCoordinatorError::Protocol(message))
                if message.contains("dropped and reopened")
        ));
        assert_eq!(
            coordinator
                .ledger
                .load_sprint(&harness.spec.sprint_id)
                .expect("inspect poisoned handle after rejected re-entry")
                .events
                .len(),
            event_count,
            "poisoned same-handle re-entry must not append or retry completion"
        );
        drop(coordinator);

        let mut restarted =
            DurableWalkingSkeleton::open(&harness.database, MutationProvider::new(Vec::new()))
                .expect("reopen completed sprint without any runner lifecycle");
        assert_eq!(
            restarted
                .run_completion_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &capture_receipt_id,
                    0,
                )
                .expect("completed restart is exact readback before clock validation"),
            completed
        );
        assert_eq!(
            restarted
                .load_sprint(&harness.spec.sprint_id)
                .expect("reload completed sprint after readback")
                .events
                .len(),
            event_count,
            "completion readback must not append a second event"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end human-criterion proof crosses TaskDone, one-to-one acceptance, final verification, no-op, live capture, completion, and report vocabulary"
    )]
    fn accepted_by_you_human_criterion_reaches_exact_completed_with_separate_evidence_words() {
        let mut scenario = ApplicationScenario::new_human_empty(
            "completion-human-accepted-by-you",
            ApplicationDispatchBehavior::Exact,
        );
        assert!(matches!(
            scenario
                .continue_application(8_000)
                .expect("classify exact human-criterion no-op"),
            WalkingSkeletonStatus::VerifiedNoOpCaptureRequired { .. }
        ));
        let ApplicationScenario {
            coordinator,
            harness,
            final_verification_receipt_id,
            ..
        } = scenario;
        drop(coordinator);

        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            StrictFakeRunnerLifecycle,
        )
        .expect("open human completion capture continuation");
        let capture = coordinator
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect("capture exact human completion live state");
        let WalkingSkeletonStatus::LiveStateCaptured {
            capture_receipt_id,
            matches_expected_snapshot: true,
            ..
        } = capture
        else {
            panic!("unexpected human completion capture: {capture:?}")
        };
        assert!(matches!(
            coordinator
                .run_completion_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &capture_receipt_id,
                    14_000,
                )
                .expect("persist exact human Completed terminal"),
            WalkingSkeletonStatus::Completed { .. }
        ));
        let completed = coordinator
            .ledger
            .load_completion(&harness.spec.sprint_id)
            .expect("load human completion")
            .expect("human completion is durable");
        assert_eq!(
            completed.receipt.satisfied_criterion_ids,
            ["automated", "human-review"]
        );
        assert_eq!(completed.receipt.criterion_evidence_receipt_ids.len(), 2);
        assert!(matches!(
            coordinator.ledger.load_criterion_evidence_receipt_v2(
                &gate1_criterion_evidence_receipt_identity(&harness.spec.sprint_id, 0)
            ),
            Ok(CriterionEvidenceReceiptV2::Verified { .. })
        ));
        assert!(matches!(
            coordinator.ledger.load_criterion_evidence_receipt_v2(
                &gate1_criterion_evidence_receipt_identity(&harness.spec.sprint_id, 1)
            ),
            Ok(CriterionEvidenceReceiptV2::AcceptedByYou {
                backing: HumanAcceptanceBackingV1::OneToOne,
                ..
            })
        ));
        let report = &completed.final_report.body;
        assert!(report.contains("evidence=verified backing=verification-receipt"));
        assert!(report.contains("evidence=accepted-by-you backing=1:1"));
        assert!(!report.contains("evidence=accepted backing="));
        assert!(!report.contains("evidence=verified backing=1:1"));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end proof checks initial terminalization, exact typed authority, duplicate no-write behavior, and unavailable-lifecycle restart readback"
    )]
    fn completion_terminalizes_live_state_drift_once_and_restart_reads_it_back() {
        let mut scenario = ApplicationScenario::new(
            "completion-live-state-drift",
            ApplicationDispatchBehavior::Exact,
            false,
        );
        assert!(matches!(
            scenario
                .continue_application(8_000)
                .expect("classify drift scenario no-op"),
            WalkingSkeletonStatus::VerifiedNoOpCaptureRequired { .. }
        ));
        fs::write(
            scenario.harness.workspace.join("src/lib.rs"),
            b"external live drift before descriptor capture\n",
        )
        .expect("mutate live workspace before drift capture");
        let ApplicationScenario {
            coordinator,
            harness,
            final_verification_receipt_id,
            ..
        } = scenario;
        drop(coordinator);

        let mut coordinator = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            StrictFakeRunnerLifecycle,
        )
        .expect("open drift capture continuation");
        let capture = coordinator
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect("persist exact drift capture evidence");
        let WalkingSkeletonStatus::LiveStateCaptured {
            capture_receipt_id,
            expected_snapshot,
            observed_snapshot,
            matches_expected_snapshot: false,
        } = capture
        else {
            panic!("unexpected drift capture state: {capture:?}")
        };
        assert_ne!(expected_snapshot, observed_snapshot);
        let before = coordinator
            .load_sprint(&harness.spec.sprint_id)
            .expect("load exact pre-completion drift state");
        assert!(before.completion.is_none());

        let expected = WalkingSkeletonStatus::LiveStateDriftBlocked {
            terminal_record_id: live_state_drift_identity(&harness.spec.sprint_id, "terminal"),
            capture_receipt_id: capture_receipt_id.clone(),
            expected_snapshot: expected_snapshot.clone(),
            observed_snapshot: observed_snapshot.clone(),
        };
        coordinator.inject_terminalization_postcommit_uncertainty_for_test();
        assert!(matches!(
            coordinator.run_completion_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &capture_receipt_id,
                14_000,
            ),
            Err(DurableCoordinatorError::Ledger(
                LedgerError::PostCommitStateUncertain { .. }
            ))
        ));
        let after = coordinator
            .ledger
            .load_sprint(&harness.spec.sprint_id)
            .expect("inspect committed drift terminal behind poisoned handle");
        assert_eq!(after.events.len(), before.events.len() + 1);
        assert!(after.completion.is_none());
        let terminal = after
            .terminal_outcome
            .as_ref()
            .expect("drift writes one unsuccessful terminal");
        assert_eq!(terminal.evidence.state, NonSuccessTerminalState::Blocked);
        assert!(matches!(
            &terminal.proof,
            PersistedTerminalProof::LiveStateDriftBlocked {
                proof,
                capture_evidence,
                verifier_cleanup_evidence,
            } if proof.capture_receipt_id == capture_receipt_id
                && capture_evidence.receipt.receipt_id == capture_receipt_id
                && verifier_cleanup_evidence.receipt.sprint_id == harness.spec.sprint_id
        ));
        let exact_terminal = terminal.clone();
        let projection = DurableUiProjection::from_persisted(&after)
            .expect("project exact drift-Blocked terminal");
        assert!(!projection.is_done());
        assert!(matches!(
            projection.events().last().map(DurableUiEvent::payload),
            Some(DurableUiEventKind::SprintTerminal {
                state: crate::UiNonSuccessTerminalState::Blocked,
                cause: Some(UiTerminalCause::LiveStateDrift {
                    capture_receipt_id: projected_capture,
                    expected_snapshot: projected_expected,
                    observed_snapshot: projected_observed,
                }),
                safe_next_action: Some(
                    UiSafeNextAction::StartNewSprintFromObservedWorkspace
                ),
                ..
            }) if projected_capture == &capture_receipt_id
                && projected_expected == &expected_snapshot
                && projected_observed == &observed_snapshot
        ));
        let mut crossed_running_boundary = after.clone();
        crossed_running_boundary
            .effects
            .iter_mut()
            .find(|effect| effect.intent.kind == EffectKind::CaptureWorkspaceState)
            .and_then(|effect| effect.dispatch_claim.as_mut())
            .expect("drift capture retains its dispatch claim")
            .running_boundary_id = Some("crossed-task-running-boundary".into());
        assert!(matches!(
            DurableUiProjection::from_persisted(&crossed_running_boundary),
            Err(UiProjectionError::InvalidEffect { reason, .. })
                if reason.contains("claim")
        ));
        let mut unrelated_terminal_proof = after.clone();
        unrelated_terminal_proof
            .terminal_outcome
            .as_mut()
            .expect("drift terminal remains present")
            .proof = PersistedTerminalProof::UnknownNoProof;
        assert!(matches!(
            DurableUiProjection::from_persisted(&unrelated_terminal_proof),
            Err(UiProjectionError::InvalidEffect { reason, .. })
                if reason.contains("omits or replaces")
        ));
        let event_count = after.events.len();
        assert!(matches!(
            coordinator.run_completion_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &capture_receipt_id,
                0,
            ),
            Err(DurableCoordinatorError::Protocol(message))
                if message.contains("dropped and reopened")
        ));
        assert!(matches!(
            coordinator.run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                0,
            ),
            Err(DurableCoordinatorError::Protocol(message))
                if message.contains("dropped and reopened")
        ));
        assert!(matches!(
            coordinator.load_sprint(&harness.spec.sprint_id),
            Err(DurableCoordinatorError::Protocol(message))
                if message.contains("dropped and reopened")
        ));
        assert_eq!(
            coordinator
                .ledger
                .load_sprint(&harness.spec.sprint_id)
                .expect("poisoned handle remains physically read-only in test")
                .events
                .len(),
            event_count
        );
        drop(coordinator);

        let mut restarted =
            DurableWalkingSkeleton::open(&harness.database, MutationProvider::new(Vec::new()))
                .expect("reopen drift-Blocked sprint without a runner lifecycle");
        assert_eq!(
            restarted
                .run_completion_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &capture_receipt_id,
                    0,
                )
                .expect("restart reads exact drift terminal before clock validation"),
            expected
        );
        assert_eq!(
            restarted
                .ledger
                .record_live_state_drift_blocked_outcome(
                    &exact_terminal.evidence,
                    &capture_receipt_id,
                )
                .expect("core exact replay returns existing drift authority"),
            exact_terminal
        );
        let mut wrong_state = exact_terminal.evidence.clone();
        wrong_state.state = NonSuccessTerminalState::Failed;
        assert!(matches!(
            restarted
                .ledger
                .record_live_state_drift_blocked_outcome(&wrong_state, &capture_receipt_id),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        assert!(matches!(
            restarted.ledger.record_live_state_drift_blocked_outcome(
                &exact_terminal.evidence,
                "crossed:capture-receipt",
            ),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        assert_eq!(
            restarted
                .run_completion_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &capture_receipt_id,
                    0,
                )
                .expect("repeated restarted drift readback remains exact"),
            expected
        );
        assert_eq!(
            restarted
                .load_sprint(&harness.spec.sprint_id)
                .expect("reload restarted drift terminal")
                .events
                .len(),
            event_count
        );
    }

    #[test]
    fn live_state_preclaim_failure_closes_definitely_before_effect_and_never_redispatches() {
        let (harness, final_verification_receipt_id) =
            applied_live_state_fixture("live-state-preclaim-failure");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let mut capture = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::FailBeforeClaim,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&cleanups),
            ),
        )
        .expect("open preclaim live-state continuation");
        let status = capture
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect("close preclaim live-state failure");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::TaskEffectFailedBeforeEffect { .. }
        ));
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 1, 1)
        );
        let admission = capture
            .ledger
            .load_sprint_live_state_capture_admission(&live_state_capture_identity(
                &harness.spec.sprint_id,
                "admission",
            ))
            .expect("load preclaim capture admission");
        let effect = capture
            .ledger
            .load_effect(&admission.effect_id)
            .expect("load preclaim capture terminal");
        assert!(effect.dispatch_claim.is_none());
        assert!(matches!(
            effect.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ));
        assert!(
            live_state_capture_cleanup_complete(&capture.ledger, &admission, &effect)
                .expect("assess preclaim verifier cleanup")
        );
        drop(capture);

        let restart_launches = Rc::new(Cell::new(0));
        let restart_dispatches = Rc::new(Cell::new(0));
        let restart_cleanups = Rc::new(Cell::new(0));
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::Exact,
                Rc::clone(&restart_launches),
                Rc::clone(&restart_dispatches),
                Rc::clone(&restart_cleanups),
            ),
        )
        .expect("reopen terminal preclaim capture");
        assert!(matches!(
            restarted
                .run_live_state_capture_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &final_verification_receipt_id,
                    13_000,
                )
                .expect("read back terminal preclaim capture"),
            WalkingSkeletonStatus::TaskEffectFailedBeforeEffect { .. }
        ));
        assert_eq!(
            (
                restart_launches.get(),
                restart_dispatches.get(),
                restart_cleanups.get()
            ),
            (0, 0, 0)
        );
    }

    #[test]
    fn dropped_fresh_live_state_permit_restarts_to_unclaimed_terminal_and_cleanup_only() {
        let (harness, final_verification_receipt_id) =
            applied_live_state_fixture("live-state-drop-fresh-permit");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let mut capture = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::Exact,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&cleanups),
            ),
        )
        .expect("open dropped-Fresh live-state continuation");
        capture.inject_live_state_stop_after_admission_for_test();
        capture
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect_err("stop after committing admission and dropping Fresh permit");
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 0, 0)
        );
        let admission = capture
            .ledger
            .load_sprint_live_state_capture_admission(&live_state_capture_identity(
                &harness.spec.sprint_id,
                "admission",
            ))
            .expect("load stranded fresh capture admission");
        let effect = capture
            .ledger
            .load_effect(&admission.effect_id)
            .expect("load stranded unclaimed capture");
        assert!(effect.dispatch_claim.is_none());
        assert!(effect.observation.is_none());
        drop(capture);

        let restart_launches = Rc::new(Cell::new(0));
        let restart_dispatches = Rc::new(Cell::new(0));
        let restart_cleanups = Rc::new(Cell::new(0));
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::Exact,
                Rc::clone(&restart_launches),
                Rc::clone(&restart_dispatches),
                Rc::clone(&restart_cleanups),
            ),
        )
        .expect("reopen stranded unclaimed capture");
        assert!(matches!(
            restarted
                .run_live_state_capture_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &final_verification_receipt_id,
                    13_000,
                )
                .expect("close stranded unclaimed capture and cleanup"),
            WalkingSkeletonStatus::TaskEffectFailedBeforeEffect { .. }
        ));
        assert_eq!(
            (
                restart_launches.get(),
                restart_dispatches.get(),
                restart_cleanups.get()
            ),
            (0, 0, 1)
        );
        let recovered = restarted
            .ledger
            .load_effect(&admission.effect_id)
            .expect("load recovered unclaimed capture terminal");
        assert!(recovered.dispatch_claim.is_none());
        assert!(matches!(
            recovered.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::FailedBeforeEffect { .. })
        ));
        assert!(
            live_state_capture_cleanup_complete(&restarted.ledger, &admission, &recovered)
                .expect("assess dropped-Fresh recovery cleanup")
        );
    }

    #[test]
    fn claimed_live_state_response_loss_restarts_to_atomic_unknown_and_cleanup() {
        let (harness, final_verification_receipt_id) =
            applied_live_state_fixture("live-state-claimed-response-loss");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let mut capture = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::ClaimThenLoseResponse,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&cleanups),
            ),
        )
        .expect("open claimed-response-loss continuation");
        let status = capture
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect("stop at claimed response loss");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::ReconciliationRequired {
                kind: EffectKind::CaptureWorkspaceState,
                ..
            }
        ));
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 1, 0)
        );
        let admission = capture
            .ledger
            .load_sprint_live_state_capture_admission(&live_state_capture_identity(
                &harness.spec.sprint_id,
                "admission",
            ))
            .expect("load claimed capture admission");
        let claimed = capture
            .ledger
            .load_effect(&admission.effect_id)
            .expect("load claimed unobserved capture");
        assert!(claimed.dispatch_claim.is_some());
        assert!(claimed.observation.is_none());
        drop(capture);

        let restart_launches = Rc::new(Cell::new(0));
        let restart_dispatches = Rc::new(Cell::new(0));
        let restart_cleanups = Rc::new(Cell::new(0));
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::Exact,
                Rc::clone(&restart_launches),
                Rc::clone(&restart_dispatches),
                Rc::clone(&restart_cleanups),
            ),
        )
        .expect("reopen claimed capture for atomic recovery");
        assert!(matches!(
            restarted
                .run_live_state_capture_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &final_verification_receipt_id,
                    13_000,
                )
                .expect("atomically terminalize and clean claimed capture"),
            WalkingSkeletonStatus::TaskEffectOutcomeUnknown { .. }
        ));
        assert_eq!(
            (
                restart_launches.get(),
                restart_dispatches.get(),
                restart_cleanups.get()
            ),
            (0, 0, 1)
        );
        let recovered = restarted
            .ledger
            .load_effect(&admission.effect_id)
            .expect("load recovered unknown capture");
        assert!(matches!(
            recovered.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::Unknown { .. })
        ));
        assert!(
            live_state_capture_cleanup_complete(&restarted.ledger, &admission, &recovered)
                .expect("assess atomic claimed recovery cleanup")
        );
    }

    #[test]
    fn successful_live_state_terminal_restarts_cleanup_only_without_redispatch() {
        let (harness, final_verification_receipt_id) =
            applied_live_state_fixture("live-state-success-cleanup-restart");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let mut capture = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::CleanupRequired,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&cleanups),
            ),
        )
        .expect("open cleanup-paused live-state continuation");
        let status = capture
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect("persist capture before cleanup pause");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::LiveStateCaptureCleanupRequired {
                capture_receipt_id: Some(_),
                ..
            }
        ));
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 1, 1)
        );
        drop(capture);

        let restart_launches = Rc::new(Cell::new(0));
        let restart_dispatches = Rc::new(Cell::new(0));
        let restart_cleanups = Rc::new(Cell::new(0));
        let mut restarted = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::Exact,
                Rc::clone(&restart_launches),
                Rc::clone(&restart_dispatches),
                Rc::clone(&restart_cleanups),
            ),
        )
        .expect("reopen cleanup-paused capture");
        assert!(matches!(
            restarted
                .run_live_state_capture_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &final_verification_receipt_id,
                    13_000,
                )
                .expect("complete cleanup-only recovery"),
            WalkingSkeletonStatus::LiveStateCaptured { .. }
        ));
        assert_eq!(
            (
                restart_launches.get(),
                restart_dispatches.get(),
                restart_cleanups.get()
            ),
            (0, 0, 1)
        );
    }

    #[test]
    fn live_state_terminal_precommit_retry_keeps_sealed_custody_and_never_reexecutes() {
        let (harness, final_verification_receipt_id) =
            applied_live_state_fixture("live-state-terminal-precommit-retry");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let mut capture = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::Exact,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&cleanups),
            ),
        )
        .expect("open live-state terminal retry continuation");
        capture.inject_claimed_terminal_precommit_failure_for_test(LedgerError::Io(
            io::Error::other("injected live-state typed-terminal precommit failure"),
        ));
        capture
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect_err("retain sealed terminal after definite precommit failure");
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 1, 0)
        );
        let admission = capture
            .ledger
            .load_sprint_live_state_capture_admission(&live_state_capture_identity(
                &harness.spec.sprint_id,
                "admission",
            ))
            .expect("load capture admission awaiting typed terminal retry");
        let claimed = capture
            .ledger
            .load_effect(&admission.effect_id)
            .expect("load capture claim awaiting typed terminal retry");
        assert!(claimed.dispatch_claim.is_some());
        assert!(claimed.observation.is_none());
        assert!(capture.pending_claimed_terminal.is_some());

        assert!(matches!(
            capture
                .run_live_state_capture_until_blocked(
                    &harness.spec.sprint_id,
                    &harness.authority,
                    &harness.policy,
                    &final_verification_receipt_id,
                    13_000,
                )
                .expect("retry exact sealed terminal, read back, and clean verifier"),
            WalkingSkeletonStatus::LiveStateCaptured { .. }
        ));
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 1, 1)
        );
        assert!(capture.pending_claimed_terminal.is_none());
        let completed = capture
            .ledger
            .load_effect(&admission.effect_id)
            .expect("load typed terminal after sealed retry");
        assert!(matches!(
            completed.observation.as_ref().map(|value| &value.outcome),
            Some(EffectOutcome::Succeeded { .. })
        ));
        assert!(
            live_state_capture_cleanup_complete(&capture.ledger, &admission, &completed)
                .expect("assess terminal-retry verifier cleanup")
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the restart regression proves unavailable, retained, completed, and readback-only launch-gap cleanup in one closed lifecycle"
    )]
    fn live_state_launch_without_admission_is_cleanup_only_after_restart() {
        let (harness, final_verification_receipt_id) =
            applied_live_state_fixture("live-state-launch-before-admission");
        let launches = Rc::new(Cell::new(0));
        let dispatches = Rc::new(Cell::new(0));
        let cleanups = Rc::new(Cell::new(0));
        let mut capture = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::LaunchThenError,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&cleanups),
            ),
        )
        .expect("open launch-gap live-state continuation");
        capture
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                12_000,
            )
            .expect_err("stop after durable verifier launch");
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 0, 0)
        );
        assert!(matches!(
            capture
                .ledger
                .load_sprint_live_state_capture_admission(&live_state_capture_identity(
                    &harness.spec.sprint_id,
                    "admission"
                )),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        drop(capture);

        let mut restarted =
            DurableWalkingSkeleton::open(&harness.database, MutationProvider::new(Vec::new()))
                .expect("reopen launch-gap capture without lifecycle authority");
        let status = restarted
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                13_000,
            )
            .expect("recover launch gap as cleanup-only");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::LiveStateVerifierLaunchCleanupRequired { .. }
        ));
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 0, 0)
        );
        drop(restarted);

        let mut pending = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::CleanupRequired,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&cleanups),
            ),
        )
        .expect("reopen launch-gap capture with pending cleanup lifecycle");
        let status = pending
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                14_000,
            )
            .expect("retain launch-gap cleanup authority");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::LiveStateVerifierLaunchCleanupRequired {
                ref reason,
                ..
            } if reason == "injected unadmitted live-state verifier cleanup pause"
        ));
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 0, 1)
        );
        drop(pending);

        let mut cleaner = DurableWalkingSkeleton::open_with_runner_lifecycle(
            &harness.database,
            MutationProvider::new(Vec::new()),
            LiveStateScriptRunnerLifecycle::new(
                LiveStateScriptBehavior::Exact,
                Rc::clone(&launches),
                Rc::clone(&dispatches),
                Rc::clone(&cleanups),
            ),
        )
        .expect("reopen launch-gap capture with exact cleanup lifecycle");
        let status = cleaner
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                15_000,
            )
            .expect("close launch-gap verifier without capture authority");
        let WalkingSkeletonStatus::LiveStateVerifierLaunchCleanedWithoutCapture {
            launch_id,
            plan_id,
            cleanup_effect_id,
        } = status
        else {
            panic!("exact launch-gap cleanup did not reach its closed endpoint")
        };
        assert_eq!(
            launch_id,
            live_state_capture_identity(&harness.spec.sprint_id, "launch")
        );
        assert_eq!(
            plan_id,
            live_state_capture_identity(&harness.spec.sprint_id, "plan")
        );
        assert!(matches!(
            cleaner
                .ledger
                .load_effect(&cleanup_effect_id)
                .expect("read exact closed launch-gap cleanup")
                .finish_receipt,
            PersistedFinishReceipt::WorkerCleanup(_)
        ));
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 0, 2)
        );
        let replay = cleaner
            .run_live_state_capture_until_blocked(
                &harness.spec.sprint_id,
                &harness.authority,
                &harness.policy,
                &final_verification_receipt_id,
                16_000,
            )
            .expect("closed launch-gap cleanup replays by readback only");
        assert!(matches!(
            replay,
            WalkingSkeletonStatus::LiveStateVerifierLaunchCleanedWithoutCapture { .. }
        ));
        assert_eq!(
            (launches.get(), dispatches.get(), cleanups.get()),
            (1, 0, 2),
            "closed launch-gap recovery cannot relaunch, dispatch, or clean twice"
        );
        assert!(matches!(
            cleaner
                .ledger
                .load_sprint_live_state_capture_admission(&live_state_capture_identity(
                    &harness.spec.sprint_id,
                    "admission"
                )),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
    }

    #[test]
    fn empty_change_set_requires_real_live_capture_and_never_launches_applier() {
        let mut scenario = ApplicationScenario::new(
            "application-no-op-live-diverged",
            ApplicationDispatchBehavior::Exact,
            false,
        );
        fs::write(
            scenario.harness.workspace.join("src/lib.rs"),
            b"live workspace diverged after verification\n",
        )
        .expect("diverge live workspace before no-op capture");
        let status = scenario
            .continue_application(8_000)
            .expect("classify empty change set without manufacturing live equality");
        assert!(matches!(
            status,
            WalkingSkeletonStatus::VerifiedNoOpCaptureRequired { .. }
        ));
        assert_eq!(scenario.launch_count.get(), 0);
        assert_eq!(scenario.dispatch_count.get(), 0);
        assert_eq!(scenario.cleanup_count.get(), 0);
        assert!(matches!(
            scenario.coordinator.ledger.load_runner_launch_intent(
                &scenario.harness.spec.sprint_id,
                &application_identity(&scenario.harness.spec.sprint_id, "launch")
            ),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert!(matches!(
            scenario
                .coordinator
                .ledger
                .load_sprint_application_admission(&application_identity(
                    &scenario.harness.spec.sprint_id,
                    "admission"
                )),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert!(matches!(
            scenario
                .coordinator
                .ledger
                .load_verified_no_op_receipt(&application_identity(
                    &scenario.harness.spec.sprint_id,
                    "verified-no-op-receipt"
                )),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one restart audit proves retained cleanup, exact closure, and absence of every downstream authority"
    )]
    fn launch_without_application_admission_is_cleaned_once_and_restart_stable() {
        let mut scenario = ApplicationScenario::new(
            "application-launch-before-admission",
            ApplicationDispatchBehavior::LaunchThenError,
            true,
        );
        scenario
            .continue_application(8_000)
            .expect_err("test stops after durable Applier launch");
        assert_eq!(scenario.launch_count.get(), 1);
        assert_eq!(scenario.dispatch_count.get(), 0);
        assert_eq!(scenario.cleanup_count.get(), 0);

        let sprint_id = scenario.harness.spec.sprint_id.clone();
        let expected_launch_id = application_identity(&sprint_id, "launch");
        let expected_session_id = application_identity(&sprint_id, "session");
        let expected_admission_id = application_identity(&sprint_id, "admission");
        let expected_application_receipt_id = application_identity(&sprint_id, "receipt");
        let expected_rollback_reference_id = application_identity(&sprint_id, "rollback-reference");
        let expected_capture_admission_id = live_state_capture_identity(&sprint_id, "admission");
        let expected_capture_receipt_id = live_state_capture_identity(&sprint_id, "receipt");
        let open_cleanup = scenario
            .coordinator
            .ledger
            .load_runner_launch_cleanup_admission(&sprint_id, &expected_launch_id)
            .expect("load exact open unadmitted trusted-Applier cleanup");
        let expected_cleanup_effect_id = open_cleanup.cleanup_effect.intent.effect_id.clone();
        assert_eq!(open_cleanup.launch.launch_id, expected_launch_id);
        assert_eq!(open_cleanup.launch.session_id, expected_session_id);
        assert_eq!(open_cleanup.launch.purpose, RunnerSessionPurpose::Applier);
        assert_eq!(
            open_cleanup.cleanup_request.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        );
        assert_eq!(
            open_cleanup.cleanup_effect.intent.input_snapshot,
            scenario.harness.spec.base_snapshot
        );
        assert!(open_cleanup.cleanup_effect.dispatch_claim.is_none());
        assert!(open_cleanup.cleanup_effect.observation.is_none());
        assert!(open_cleanup.cleanup_effect.evidence_bytes.is_none());
        assert!(open_cleanup.cleanup_effect.terminal_event.is_none());
        assert_eq!(
            open_cleanup.cleanup_effect.finish_receipt,
            PersistedFinishReceipt::NotRequired
        );

        let assert_no_application_or_downstream_authority = |ledger: &EventLedger| {
            assert!(matches!(
                ledger.load_sprint_application_admission(&expected_admission_id),
                Err(LedgerError::ArtifactNotFound { .. })
            ));
            assert!(matches!(
                ledger.load_application_evidence(&expected_application_receipt_id),
                Err(LedgerError::ArtifactNotFound { .. })
            ));
            assert!(matches!(
                ledger.load_rollback_reference(&expected_rollback_reference_id),
                Err(LedgerError::ArtifactNotFound { .. })
            ));
            assert!(matches!(
                ledger.load_sprint_live_state_capture_admission(&expected_capture_admission_id),
                Err(LedgerError::ArtifactNotFound { .. })
            ));
            assert!(matches!(
                ledger.load_live_state_capture_evidence(&expected_capture_receipt_id),
                Err(LedgerError::ArtifactNotFound { .. })
            ));
            assert!(
                ledger
                    .load_completion(&sprint_id)
                    .expect("load absent unadmitted trusted-Applier completion")
                    .is_none()
            );
            let sprint = ledger
                .load_sprint(&sprint_id)
                .expect("load nonterminal unadmitted trusted-Applier sprint");
            assert!(sprint.completion.is_none());
            assert!(sprint.terminal_outcome.is_none());
            assert!(sprint.events.iter().all(|event| !matches!(
                event.payload,
                AgentEventKind::CompletionRecorded(_)
                    | AgentEventKind::SprintTerminalRecorded { .. }
            )));
        };
        assert_no_application_or_downstream_authority(&scenario.coordinator.ledger);

        let mut pending =
            scenario.restart(ApplicationDispatchBehavior::UnadmittedCleanupRequiredOnce);
        assert_eq!(
            pending
                .continue_application(9_000)
                .expect("retain cleanup-only trusted-Applier custody"),
            WalkingSkeletonStatus::ApplicationLaunchCleanupRequired {
                launch_id: expected_launch_id.clone(),
                reason: "test unadmitted trusted-Applier cleanup handoff remains pending".into(),
            }
        );
        assert_eq!(pending.launch_count.get(), 0, "restart did not relaunch");
        assert_eq!(pending.dispatch_count.get(), 0);
        assert_eq!(pending.cleanup_count.get(), 1);
        assert_eq!(
            pending
                .coordinator
                .ledger
                .load_effect(&expected_cleanup_effect_id)
                .expect("load retained trusted-Applier cleanup effect"),
            open_cleanup.cleanup_effect
        );
        assert_no_application_or_downstream_authority(&pending.coordinator.ledger);

        let mut cleaned = pending.restart(ApplicationDispatchBehavior::Exact);
        let expected_closed_status = WalkingSkeletonStatus::ApplicationLaunchCleanedWithoutPhase {
            launch_id: expected_launch_id.clone(),
            cleanup_effect_id: expected_cleanup_effect_id.clone(),
        };
        assert_eq!(
            cleaned
                .continue_application(10_000)
                .expect("close trusted-Applier launch without application admission"),
            expected_closed_status
        );
        assert_eq!(cleaned.launch_count.get(), 0);
        assert_eq!(cleaned.dispatch_count.get(), 0);
        assert_eq!(cleaned.cleanup_count.get(), 1);
        let closed_cleanup = cleaned
            .coordinator
            .ledger
            .load_runner_launch_cleanup_admission(&sprint_id, &expected_launch_id)
            .expect("load closed unadmitted trusted-Applier cleanup");
        assert_eq!(closed_cleanup.launch, open_cleanup.launch);
        assert_eq!(closed_cleanup.cleanup_request, open_cleanup.cleanup_request);
        assert_eq!(
            closed_cleanup.cleanup_effect.intent,
            open_cleanup.cleanup_effect.intent
        );
        assert_eq!(
            closed_cleanup.cleanup_effect.request_bytes,
            open_cleanup.cleanup_effect.request_bytes
        );
        assert_eq!(
            closed_cleanup.cleanup_effect.proposed_event,
            open_cleanup.cleanup_effect.proposed_event
        );
        let completed = cleaned
            .coordinator
            .ledger
            .load_effect(&expected_cleanup_effect_id)
            .expect("load exact completed unadmitted trusted-Applier cleanup");
        assert_eq!(completed, closed_cleanup.cleanup_effect);
        assert!(completed.dispatch_claim.is_none());
        let observation = completed
            .observation
            .as_ref()
            .expect("closed trusted-Applier cleanup has successful observation");
        let PersistedFinishReceipt::WorkerCleanup(evidence) = &completed.finish_receipt else {
            panic!("closed trusted-Applier cleanup must retain typed zero-survivor evidence")
        };
        evidence
            .validate()
            .expect("validate unadmitted trusted-Applier cleanup evidence");
        assert_eq!(evidence.receipt.sprint_id, sprint_id);
        assert_eq!(evidence.receipt.launch_id, expected_launch_id);
        assert_eq!(evidence.receipt.session_id, expected_session_id);
        assert_eq!(evidence.receipt.effect_id, expected_cleanup_effect_id);
        assert_eq!(evidence.receipt.observation_id, observation.observation_id);
        assert_eq!(evidence.receipt.worker_lease, None);
        assert_eq!(evidence.receipt.surviving_processes, 0);
        assert_eq!(
            evidence.receipt.platform_backend,
            WorkerCleanupBackend::TrustedApplierDirectChildWait
        );
        let canonical_evidence =
            serde_json::to_vec(evidence).expect("encode trusted-Applier cleanup evidence");
        assert_eq!(
            observation.outcome,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&canonical_evidence),
            }
        );
        assert_eq!(
            completed.evidence_bytes.as_deref(),
            Some(canonical_evidence.as_slice())
        );
        assert_no_application_or_downstream_authority(&cleaned.coordinator.ledger);

        let mut replayed = cleaned.restart(ApplicationDispatchBehavior::Exact);
        let status = replayed
            .continue_application(9_000)
            .expect("read back closed trusted-Applier launch cleanup");
        assert_eq!(status, expected_closed_status);
        assert_eq!(replayed.launch_count.get(), 0);
        assert_eq!(replayed.dispatch_count.get(), 0);
        assert_eq!(
            replayed.cleanup_count.get(),
            0,
            "closed cleanup is not repeated"
        );
        assert_eq!(
            replayed
                .coordinator
                .ledger
                .load_runner_launch_cleanup_admission(&sprint_id, &expected_launch_id)
                .expect("read back restart-stable trusted-Applier cleanup"),
            closed_cleanup
        );
        assert_no_application_or_downstream_authority(&replayed.coordinator.ledger);
    }

    #[test]
    fn unadmitted_application_applier_false_completed_without_terminal_is_rejected() {
        let mut scenario = ApplicationScenario::new(
            "unadmitted-application-applier-false-completed",
            ApplicationDispatchBehavior::LaunchThenError,
            true,
        );
        scenario
            .continue_application(8_000)
            .expect_err("stop after durable trusted-Applier launch");
        let sprint_id = scenario.harness.spec.sprint_id.clone();
        let launch_id = application_identity(&sprint_id, "launch");
        let admission_id = application_identity(&sprint_id, "admission");
        let open_cleanup = scenario
            .coordinator
            .ledger
            .load_runner_launch_cleanup_admission(&sprint_id, &launch_id)
            .expect("load open false-completed trusted-Applier cleanup");

        let mut restarted = scenario.restart(ApplicationDispatchBehavior::UnadmittedFalseCompleted);
        assert!(matches!(
            restarted.continue_application(9_000),
            Err(DurableCoordinatorError::Protocol(detail))
                if detail
                    == "unadmitted trusted-Applier cleanup returned without exact durable zero-survivor readback"
        ));
        assert_eq!(restarted.launch_count.get(), 0);
        assert_eq!(restarted.dispatch_count.get(), 0);
        assert_eq!(restarted.cleanup_count.get(), 1);
        assert_eq!(
            restarted
                .coordinator
                .ledger
                .load_runner_launch_cleanup_admission(&sprint_id, &launch_id)
                .expect("read back unchanged false-completed cleanup"),
            open_cleanup
        );
        assert!(matches!(
            restarted
                .coordinator
                .ledger
                .load_sprint_application_admission(&admission_id),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert!(
            restarted
                .coordinator
                .ledger
                .load_completion(&sprint_id)
                .expect("load absent completion after false Completed")
                .is_none()
        );
    }
