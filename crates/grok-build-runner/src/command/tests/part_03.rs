    /// Exercises the walking-skeleton acceptance command through the development
    /// macOS helper, with its separate identity pool, state root and requirement.
    /// These results do not qualify the production helper.
    ///
    /// `fixtures/walking-skeleton/README.md` locks the acceptance command to
    /// `cargo test --offline --locked`, and the fixture starts incomplete:
    /// `src/lib.rs` still returns `"TODO"` and embeds `docs/report.txt`, which
    /// the fixture deliberately omits. The baseline therefore MUST terminate
    /// with a nonzero exit code.
    // The gate is widened to Linux so this module's *helpers* -- which mint a
    // grant, a policy, a capture anchor and a real `PreparedContainedCommand`,
    // and contain nothing platform-specific -- can build a command on the host
    // where the contained backend actually runs. Every test that was in here
    // keeps its original `#[cfg(target_os = "macos")]`, individually, so
    // nothing that ran before runs anywhere new.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    mod macos_contained_walking_skeleton_command {
        #[allow(
            clippy::wildcard_imports,
            reason = "the slice test reuses the same production-shape command fixtures as the rest of this module"
        )]
        use super::*;
        use crate::wire::{
            COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION, RUNNER_WIRE_PROTOCOL_VERSION_V12,
            RunnerRequestEnvelopeV12, RunnerRequestV12,
        };

        const SESSION_ID: &str = "session-walking-skeleton-contained";
        const SPRINT_ID: &str = "sprint-walking-skeleton-contained";
        const TASK_ID: &str = "task-walking-skeleton-contained";
        const WORKER_ID: &str = "worker-walking-skeleton-contained";
        const EFFECT_ID: &str = "effect-walking-skeleton-contained";
        const LAUNCH_ID: &str = "launch-walking-skeleton-contained";
        const REQUEST_ID: &str = "request-walking-skeleton-contained";

        fn walking_skeleton_fixture_root() -> PathBuf {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("fixtures")
                .join("walking-skeleton");
            fs::canonicalize(&root).unwrap_or_else(|error| {
                panic!(
                    "walking-skeleton fixture must exist at {}: {error}",
                    root.display()
                )
            })
        }

        fn copy_fixture_tree(source: &Path, destination: &Path) {
            for entry in fs::read_dir(source).expect("read walking-skeleton fixture directory") {
                let entry = entry.expect("read walking-skeleton fixture entry");
                let file_type = entry.file_type().expect("inspect fixture entry type");
                let target = destination.join(entry.file_name());
                if file_type.is_dir() {
                    let mut builder = fs::DirBuilder::new();
                    builder.mode(0o700);
                    builder.create(&target).expect("create fixture subdirectory");
                    copy_fixture_tree(&entry.path(), &target);
                } else if file_type.is_file() {
                    fs::copy(entry.path(), &target).expect("copy fixture file");
                } else {
                    panic!(
                        "walking-skeleton fixture must contain only files and directories: {}",
                        entry.path().display()
                    );
                }
            }
        }

        /// Returns a controlled PATH that can resolve the locked command's
        /// `cargo` program. Cargo exports `CARGO` to every test process, so the
        /// toolchain directory is exact rather than discovered from the host.
        fn controlled_path_value() -> String {
            let cargo = PathBuf::from(
                std::env::var_os("CARGO").expect("cargo test exports the CARGO program path"),
            );
            let directory = cargo
                .parent()
                .expect("the CARGO program path has a parent directory");
            format!("{}:/usr/bin:/bin", directory.display())
        }

        fn walking_skeleton_authority(
            live_root: &Path,
            limits: ResourceLimits,
        ) -> (IssuedWorkspaceGrant, CompiledExecutionPolicy) {
            let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: "grant-walking-skeleton-contained".into(),
                workspace_root: live_root.to_path_buf(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
            })
            .expect("issue walking-skeleton workspace grant");
            let policy = ExecutionPolicyCompiler::compile(
                &grant,
                ExecutionPolicyRequest {
                    policy_id: "policy-walking-skeleton-contained".into(),
                    read_scopes: vec![PathScope::Workspace],
                    write_scopes: vec![
                        PathScope::Relative(PathBuf::from("docs")),
                        PathScope::Relative(PathBuf::from("src")),
                        PathScope::Relative(PathBuf::from("target")),
                    ],
                    environment: vec![EnvironmentVariable {
                        name: "PATH".into(),
                        value: controlled_path_value(),
                    }],
                    network: ExecutionNetwork::None,
                    mutation_mode: MutationMode::ShadowWorkspace,
                    resource_limits: limits,
                    approval_id: None,
                },
            )
            .expect("compile walking-skeleton execution policy");
            (grant, policy)
        }

        /// Durably reserves the exact command-output capture anchor in the real
        /// private-state store, the same way the rest of this module's
        /// contained-backend tests anchor a production-shape capture.
        fn walking_skeleton_capture_anchor(
            policy: &CompiledExecutionPolicy,
            request_digest: &Digest,
            private_state_root: &Path,
        ) -> WireCommandOutputCaptureAnchorV1 {
            let source = CommandOutputArtifactSourceV1 {
                sprint_id: SPRINT_ID.into(),
                runner_launch_id: LAUNCH_ID.into(),
                runner_session_id: SESSION_ID.into(),
                effect_id: EFFECT_ID.into(),
                request_digest: request_digest.clone(),
            };
            let maximum =
                command_output_capture_maximum(policy.contract().resource_limits.max_output_bytes)
                    .expect("walking-skeleton aggregate capture ceiling");
            let fixture_anchor = test_command_output_capture_anchor(
                source.clone(),
                hash_bytes(b"walking-skeleton-private-state"),
                maximum,
                1,
            );
            let dispatch_claim_id = fixture_anchor.acquired().dispatch_claim_id.clone();
            let capture_id = Digest::sha256(
                format!("{SESSION_ID}:{EFFECT_ID}:{}", private_state_root.display()).as_bytes(),
            )
            .as_str()
            .to_owned();
            let intent = CommandOutputCaptureIntentV1::try_new(
                capture_id,
                source,
                crate::service::inspect_private_state_digest(private_state_root)
                    .expect("inspect walking-skeleton private-state digest"),
                maximum,
                1,
            )
            .expect("construct walking-skeleton capture intent");
            let store = CapabilityCommandOutputStore::open(private_state_root)
                .expect("open walking-skeleton command-output store");
            let acquired = store
                .reserve_anchored_capture_v2(
                    &intent,
                    &dispatch_claim_id,
                    2,
                    &SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
                )
                .expect("durably reserve the walking-skeleton capture anchor")
                .into_acquired_anchor_for_handoff()
                .expect("acquire the walking-skeleton capture anchor");
            WireCommandOutputCaptureAnchorV1::try_new(acquired)
                .expect("wrap the walking-skeleton capture anchor")
        }

        /// Builds the exact v12 command-effect authority for the locked command
        /// with a capture anchor durably reserved in the real private-state
        /// store, using the same production-shape builders as the rest of this
        /// module's contained-backend tests.
        fn walking_skeleton_command_authority_v2(
            command: &CommandSpec,
            grant: &IssuedWorkspaceGrant,
            policy: &CompiledExecutionPolicy,
            input_snapshot: &Digest,
            private_state_root: &Path,
        ) -> CommandEffectAuthorityV2 {
            let request_digest = Digest::sha256(
                &serde_json::to_vec(command).expect("encode the locked walking-skeleton command"),
            );
            let output_capture =
                walking_skeleton_capture_anchor(policy, &request_digest, private_state_root);
            let worker_lease = WorkerLease::new(
                SPRINT_ID.into(),
                1,
                TASK_ID.into(),
                WORKER_ID.into(),
                vec![PathScope::Relative(PathBuf::from("src"))],
                1,
            )
            .expect("construct walking-skeleton worker lease");
            let mut envelope = RunnerRequestEnvelopeV12 {
                protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
                session_id: SESSION_ID.into(),
                runner_nonce: hash_bytes(b"walking-skeleton runner nonce"),
                sequence: 1,
                request_id: REQUEST_ID.into(),
                effect: WireEffectContext {
                    contract_version: CONTRACT_VERSION,
                    launch_id: LAUNCH_ID.into(),
                    effect_id: EFFECT_ID.into(),
                    idempotency_key: "idempotency-walking-skeleton-contained".into(),
                    sprint_id: SPRINT_ID.into(),
                    task_id: Some(TASK_ID.into()),
                    worker_id: Some(WORKER_ID.into()),
                    worker_lease: Some(worker_lease),
                    policy_hash: policy.contract().policy_hash.clone(),
                    input_snapshot: input_snapshot.clone(),
                    request_digest,
                    transport_commitment_digest: hash_bytes(b"unbound transport commitment"),
                },
                request: RunnerRequestV12::RunCommand {
                    request: RunnerRequest::WorkerRunCommand {
                        command: WireCommandSpec {
                            program: command.program.clone(),
                            arguments: command.arguments.clone(),
                            working_directory: command
                                .working_directory
                                .to_str()
                                .expect("locked command working directory is UTF-8")
                                .into(),
                        },
                        output_capture,
                    },
                    detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
                },
            };
            envelope
                .bind_transport_commitment_digest()
                .expect("bind the walking-skeleton v12 transport commitment");
            let authority: CommandEffectAuthorityV2 = serde_json::from_value(serde_json::json!({
                "schema_version": COMMAND_EFFECT_AUTHORITY_V2_SCHEMA_VERSION,
                "contract_version": CONTRACT_VERSION,
                "grant_hash": grant.contract().grant_hash,
                "role": RunnerRole::Worker,
                "envelope": envelope,
            }))
            .expect("decode the exact walking-skeleton v12 command authority");
            authority
                .validate_integrity()
                .expect("validate the walking-skeleton v12 command authority");
            authority
        }

        /// Asserts the complete terminal evidence the slice requires: a nonzero
        /// baseline exit, a `MacOsDedicatedIdentity` backend, complete stream
        /// digests, monotonic `LaunchIntended < Finished < Published` capture
        /// heads, and a cleanup proof bound to this exact session and effect.
        /// Genuinely macOS-specific, unlike this module's other helpers: it
        /// asserts a `MacOsDedicatedIdentity` backend by name, so it stays
        /// gated where that backend exists.
        #[cfg(target_os = "macos")]
        fn assert_walking_skeleton_baseline_evidence(
            evidence: &contained_boundary::ContainedExecutionEvidence,
        ) {
            match evidence.termination() {
                CommandTermination::Exited(code) => assert_ne!(
                    code, 0,
                    "the walking-skeleton baseline must fail before the fake provider repairs it"
                ),
                other => panic!(
                    "the walking-skeleton baseline must exit normally, observed: {other:?}"
                ),
            }
            assert_eq!(
                evidence.backend().command_domain_backend(),
                CommandDomainCleanupBackend::MacOsDedicatedIdentity
            );
            assert_eq!(
                evidence.backend().backend_id(),
                macos_backend::MACOS_DEDICATED_IDENTITY_DEV_BACKEND_ID,
                "development evidence must self-identify as the development backend"
            );
            assert_eq!(evidence.stdout().complete_digest().as_str().len(), 64);
            assert_eq!(evidence.stderr().complete_digest().as_str().len(), 64);
            assert!(
                evidence.stderr().complete_length() > 0,
                "a failing cargo baseline must observe complete stderr bytes"
            );
            assert_eq!(evidence.output_digest().as_str().len(), 64);

            let launch_intended = evidence.output_capture_launch_intended_store_head();
            let finished = evidence.output_capture_finished_store_head();
            let published = evidence.output_capture_published_store_head();
            assert!(
                launch_intended.generation < finished.generation,
                "LaunchIntended must precede Finished: {launch_intended:?} then {finished:?}"
            );
            assert!(
                finished.generation < published.generation,
                "Finished must precede Published: {finished:?} then {published:?}"
            );

            let cleanup_proof = evidence.cleanup_proof();
            cleanup_proof
                .validate()
                .expect("the terminal cleanup proof revalidates");
            assert_eq!(
                cleanup_proof.backend(),
                CommandDomainCleanupBackend::MacOsDedicatedIdentity
            );
            assert_eq!(cleanup_proof.binding().runner_session_id(), SESSION_ID);
            assert_eq!(cleanup_proof.binding().command_effect_id(), EFFECT_ID);
        }

        /// Everything one walking-skeleton contained attempt needs, retained so
        /// the private roots outlive the prepared command.
        /// Builds one prepared command whose target is a **static** ELF.
        ///
        /// Compiled here rather than checked in, from the same source the spine
        /// test uses, so the binary always matches the toolchain running it.
        #[cfg(target_os = "linux")]
        /// The static-target attempt under a supplied grant and policy.
        ///
        /// There is deliberately no variant that mints its own authority: a
        /// command that issues its own grant can never run on a composed
        /// service, so such a helper would only ever build something the
        /// backend refuses.
        #[cfg(target_os = "linux")]
        pub(crate) fn linux_static_attempt_under(
            grant: IssuedWorkspaceGrant,
            policy: CompiledExecutionPolicy,
        ) -> WalkingSkeletonAttempt {
            let command = linux_static_command_spec();
            prepare_walking_skeleton_attempt_under(&command, 64, grant, policy)
        }

        /// Builds the static measurement target and names it as a command.
        #[cfg(target_os = "linux")]
        fn linux_static_command_spec() -> CommandSpec {
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("fixtures")
                .join("walking-skeleton-baseline")
                .join("baseline_exit.rs")
                .canonicalize()
                .expect("canonicalize the walking-skeleton baseline source");
            let directory = std::env::temp_dir().join(format!(
                "gbd-measurement-target-{}",
                std::process::id()
            ));
            let _ = fs::create_dir_all(&directory);
            let artefact = directory.join("baseline-exit");
            let output = std::process::Command::new("rustc")
                .args(["--edition", "2021", "--crate-name", "baseline_exit", "-O"])
                .args(["-C", "target-feature=+crt-static"])
                .args(["-C", "relocation-model=static"])
                .arg("-o")
                .arg(&artefact)
                .arg(source)
                .output()
                .expect("run rustc to build the static measurement target");
            assert!(
                output.status.success(),
                "building the static measurement target must succeed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            CommandSpec {
                program: artefact.display().to_string(),
                arguments: Vec::new(),
                working_directory: PathBuf::new(),
            }
        }

        // `grant` and `policy` are read by the macOS arms only; the Linux arm
        // builds the attempt through `prepare_walking_skeleton_attempt_under`,
        // which supplies both from the caller and never reads them back.
        #[cfg_attr(
            target_os = "linux",
            allow(
                dead_code,
                reason = "read by the macOS arms; the Linux arm supplies both from its caller"
            )
        )]
        pub(crate) struct WalkingSkeletonAttempt {
            _live: Option<TestDirectory>,
            _private: TestDirectory,
            pub(crate) grant: IssuedWorkspaceGrant,
            pub(crate) policy: CompiledExecutionPolicy,
            pub(crate) paths: SupervisorPaths,
            pub(crate) prepared: contained_boundary::PreparedContainedCommand,
        }

        /// Copies the fixture, mints the exact v12 authority, and prepares the
        /// locked command through the real contained boundary.
        #[cfg(target_os = "macos")]
        fn prepare_walking_skeleton_attempt() -> WalkingSkeletonAttempt {
            prepare_walking_skeleton_attempt_with(64)
        }

        /// The same preparation with one variable free: the configured
        /// descendant ceiling. Two attempts that differ only in this value are
        /// what turn the descendant verdicts into a comparison.
        #[cfg(target_os = "macos")]
        fn prepare_walking_skeleton_attempt_with(
            max_processes: u32,
        ) -> WalkingSkeletonAttempt {
            // The locked acceptance command from
            // fixtures/walking-skeleton/README.md.
            prepare_walking_skeleton_attempt_for(
                &CommandSpec {
                    program: "cargo".into(),
                    arguments: vec!["test".into(), "--offline".into(), "--locked".into()],
                    working_directory: PathBuf::new(),
                },
                max_processes,
            )
        }

        /// The same preparation with the command itself free.
        ///
        /// The locked `cargo` command is what the walking skeleton's own
        /// acceptance requires, and it is dynamically linked. A measurement of
        /// what the contained release path *installs* needs a target that can
        /// actually reach its own entry point under that path, which on Linux
        /// means a static one -- so the command is a parameter rather than a
        /// constant.
        #[cfg(target_os = "macos")]
        fn prepare_walking_skeleton_attempt_for(
            command: &CommandSpec,
            max_processes: u32,
        ) -> WalkingSkeletonAttempt {
            prepare_walking_skeleton_attempt_inner(command, max_processes, None)
        }

        /// The same preparation under an **externally supplied** grant and
        /// policy, over that grant's own workspace root.
        ///
        /// `service_owned` refuses a handoff journaled under a different grant
        /// or execution policy than the backend was composed from, so a command
        /// meant to run on a composed service cannot issue its own. This is the
        /// one variant that takes them instead of minting them, and the live
        /// root is the grant's own canonical root rather than a fresh temporary
        /// directory -- a grant over one tree and a command in another is the
        /// same disagreement one level up.
        #[cfg(target_os = "linux")]
        pub(crate) fn prepare_walking_skeleton_attempt_under(
            command: &CommandSpec,
            max_processes: u32,
            grant: IssuedWorkspaceGrant,
            policy: CompiledExecutionPolicy,
        ) -> WalkingSkeletonAttempt {
            prepare_walking_skeleton_attempt_inner(
                command,
                max_processes,
                Some((grant, policy)),
            )
        }

        fn prepare_walking_skeleton_attempt_inner(
            command: &CommandSpec,
            max_processes: u32,
            supplied: Option<(IssuedWorkspaceGrant, CompiledExecutionPolicy)>,
        ) -> WalkingSkeletonAttempt {
            // When a grant is supplied its workspace already exists and is
            // owned by whoever built it, so this must not create or delete one.
            let owned_live = match supplied.as_ref() {
                Some(_) => None,
                None => Some(TestDirectory::new("walking-skeleton-live")),
            };
            let live_root = match (supplied.as_ref(), owned_live.as_ref()) {
                (Some((grant, _)), _) => grant.contract().canonical_root.clone(),
                (None, Some(directory)) => directory.0.clone(),
                (None, None) => unreachable!("one of the two arms always creates a root"),
            };
            let private = TestDirectory::new("walking-skeleton-private");
            let shadow = private.0.join("shadow");
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(&shadow)
                .expect("create the private walking-skeleton shadow root");
            let fixture = walking_skeleton_fixture_root();
            copy_fixture_tree(&fixture, &live_root);
            copy_fixture_tree(&fixture, &shadow);
            assert!(
                !shadow.join("docs").join("report.txt").exists(),
                "the walking-skeleton baseline requires the missing report the fixture omits"
            );

            let limits = ResourceLimits {
                wall_time_ms: 600_000,
                max_output_bytes: 4 * 1024 * 1024,
                max_processes,
                max_memory_bytes: None,
            };
            let (grant, policy) = match supplied {
                Some(supplied) => supplied,
                None => walking_skeleton_authority(&live_root, limits),
            };
            let paths = SupervisorPaths::shadow(&private.0, &shadow);
            let manifest = WorkspaceManifest::capture_root(
                &shadow,
                grant.contract().grant_hash.clone(),
                1,
            )
            .expect("capture the walking-skeleton shadow execution root");
            let authority = walking_skeleton_command_authority_v2(
                command,
                &grant,
                &policy,
                &manifest.snapshot().snapshot_id,
                paths.private_state_root(),
            );
            let projection = authority
                .v11_execution_projection()
                .expect("project the walking-skeleton v12 authority");
            let root_authority = crate::service::test_session_validated_worker_execution_root(
                &projection,
                paths.private_state_root(),
                &shadow,
            )
            .expect("retain the session-minted walking-skeleton execution root");
            let prepared = contained_boundary::prepare_v12(
                authority,
                grant.clone(),
                policy.clone(),
                root_authority,
                &paths,
                &manifest,
            )
            .expect("prepare the locked walking-skeleton command under real containment");
            assert_eq!(prepared.command(), command);
            WalkingSkeletonAttempt {
                _live: owned_live,
                _private: private,
                grant,
                policy,
                paths,
                prepared,
            }
        }

        // This fixture needs controls unavailable on an unprivileged macOS host:
        // a descriptor-exec bridge and a 64-process dedicated execution account.
        // Seatbelt can prohibit forks for a one-process ceiling, but cannot express
        // a counted limit. The neighboring tests exercise the resulting preflight
        // refusal and the controls that the development helper can prove.
        #[cfg(target_os = "macos")]
        #[test]
        #[ignore = "measured on this host: no fexecve on macOS, and this fixture's 64-process ceiling exceeds the only root-free macOS ceiling (a Seatbelt profile refusing process-fork expresses exactly 1), so DescriptorExec, DescendantLimit, and DescendantDomainKill are unprovable"]
        fn walking_skeleton_baseline_command_dev_contained_execution() {
            let attempt = prepare_walking_skeleton_attempt();
            let backend = macos_backend::MacosDedicatedIdentityBackend::development(
                attempt.grant.clone(),
                attempt.policy.clone(),
                &attempt.paths,
                SESSION_ID,
            )
            .expect("compose the development macOS dedicated-identity backend");
            let outcome = contained_boundary::execute_classified(
                backend,
                attempt.prepared,
                &CancellationToken::new(),
            );
            let evidence = match outcome {
                ContainedExecutionOutcome::Terminal(evidence) => evidence,
                other => panic!(
                    "the locked walking-skeleton baseline must reach a contained terminal outcome under the development macOS dedicated-identity backend, observed: {other:?}"
                ),
            };

            assert_walking_skeleton_baseline_evidence(&evidence);
        }

        /// The development helper's live canary suite, end to end.
        ///
        /// This is the executing counterpart of the ignored target above. It
        /// starts the separately named development helper, authenticates the
        /// peer in both directions, reserves one development identity
        /// generation, runs the whole canary suite inside that generation
        /// against the fixture's real locked command authority, and then
        /// asserts three things that together make the development claim
        /// honest:
        ///
        /// 1. `enforced_controls()` contains exactly the controls a canary
        ///    proved on this host, and nothing else;
        /// 2. the refusal names exactly the controls no canary could prove, and
        ///    carries the live measurement behind each one; and
        /// 3. the contained boundary therefore refuses before launch, so no
        ///    unproven control ever reaches a permit.
        #[cfg(target_os = "macos")]
        #[test]
        #[allow(
            clippy::too_many_lines,
            reason = "the proven set, the refusal text, and the boundary's own conclusion are one indivisible assertion about one canary suite run"
        )]
        fn development_backend_claims_only_canary_proven_controls() {
            let attempt = prepare_walking_skeleton_attempt();
            let mut backend = macos_backend::MacosDedicatedIdentityBackend::development(
                attempt.grant.clone(),
                attempt.policy.clone(),
                &attempt.paths,
                SESSION_ID,
            )
            .expect("compose the development macOS dedicated-identity backend");
            assert!(backend.development_mode());
            assert!(
                backend.enforced_controls().is_empty(),
                "no control may be claimed before a canary has run"
            );

            let refusal = backend
                .active_preflight(&attempt.prepared)
                .expect_err("the development helper cannot prove every mandatory control");
            let refusal = match refusal {
                SupervisorError::Capability(reason) => reason,
                other => panic!("unexpected development refusal: {other:?}"),
            };

            let session = backend.development_session().unwrap_or_else(|| {
                panic!("the development helper published no session; refusal was: {refusal}")
            });
            assert!(
                !session.dedicated_account_pool,
                "an unprivileged session never owns a dedicated execution account"
            );
            assert!(
                session.attestation.install_audit().is_some(),
                "the helper must publish the install audit its local attestation rests on"
            );
            session
                .validate()
                .expect("the published development session satisfies the development contract");
            assert_eq!(
                session.helper_topology,
                crate::macos_dev_helper::available_development_helper_topology(),
                "the session must record which helper hosting shape served it"
            );

            // Whether the helper could apply the profile in process is not a
            // configuration choice: it is decided by whether the helper is a
            // single-threaded launch component, which follows from how it is
            // hosted. A separately built helper binary is its own process and
            // stays single threaded through peer authentication (measured); a
            // helper hosted on a spawned thread of this test image is, by
            // construction, in a process with at least two threads and must
            // never fork. The two facts are asserted against each other so
            // neither can drift into a self-fulfilling claim.
            let applier = backend
                .development_profile_applier()
                .expect("the canary suite recorded how the profile was applied");
            let in_process =
                applier == crate::macos_dev_helper::MacosDevelopmentProfileApplier::InProcessFork;
            match session.helper_topology {
                crate::macos_dev_helper::MacosDevelopmentHelperTopology::SeparateProcess => assert!(
                    in_process,
                    "a separately hosted helper is single threaded and must apply the profile in \
                     process; refusal was {refusal}"
                ),
                crate::macos_dev_helper::MacosDevelopmentHelperTopology::SameImageThread => assert!(
                    !in_process,
                    "a helper hosted on a thread of this image must never fork"
                ),
            }

            let proven = backend.enforced_controls();
            let mut expected_proven = BTreeSet::from([
                contained_boundary::BackendControl::ActiveCanaries,
                contained_boundary::BackendControl::CompleteBoundedOutput,
                contained_boundary::BackendControl::DescriptorWorkingDirectory,
                contained_boundary::BackendControl::ExactArgv,
                contained_boundary::BackendControl::ExternalWallClock,
                contained_boundary::BackendControl::FilesystemPolicy,
                contained_boundary::BackendControl::NetworkPolicy,
                contained_boundary::BackendControl::ReplacedEnvironment,
            ]);
            let mut expected_missing = vec![
                contained_boundary::BackendControl::DescriptorExec,
                contained_boundary::BackendControl::ClosedInheritedDescriptors,
                contained_boundary::BackendControl::DescendantLimit,
                contained_boundary::BackendControl::DescendantDomainKill,
            ];
            let mut expected_fragments = vec![
                "descriptor exec is unavailable on this platform",
                "the configured descendant ceiling is 64",
                "no counted form of process-fork",
                "not an otherwise-unused execution identity",
            ];

            // The fork canary's own numbers, asserted directly rather than
            // inferred from the refusal text. The profile refuses process
            // creation on this host, which is what makes the descendant
            // refusals be about the ceiling's *value* rather than about the
            // absence of any mechanism at all.
            let domain = backend
                .development_descendant_domain()
                .expect("the descendant-domain probe recorded its observation");
            assert_eq!(
                domain.configured_max_processes, 64,
                "the walking-skeleton policy configures a 64-process ceiling: {domain:?}"
            );
            assert!(
                !domain.dedicated_account && !domain.rlimit_nproc_applied,
                "an unprivileged host installs no per-UID ceiling: {domain:?}"
            );
            let fork = domain
                .fork_denial
                .expect("the three-run fork canary completed");
            assert!(
                fork.control_forked,
                "the permissive control must actually create a process, or the probe is vacuous: \
                 {fork:?}"
            );
            assert!(
                fork.restricted_ran_without_forking,
                "the restrictive profile must still run the same program when nothing forks, or a \
                 denial cannot be attributed to process-fork: {fork:?}"
            );
            assert!(
                !fork.restricted_forked,
                "the restrictive profile must refuse process creation: {fork:?}"
            );
            assert!(fork.refuses_process_creation());
            // The exact observation behind the verdict, asserted as numbers
            // rather than inferred from set membership.
            let closure = backend
                .development_descriptor_closure()
                .expect("the descriptor-closure canary recorded its observation");
            assert!(
                closure.target_listing.starts_with(&[0, 1, 2]),
                "the target must itself see the three standard descriptors: {closure:?}"
            );
            if in_process {
                assert_eq!(
                    closure.launcher_threads, 1,
                    "the in-process applier is licensed only by a single-threaded launcher"
                );
                assert_eq!(
                    closure.boundary_table,
                    vec![0, 1, 2],
                    "the forked child's table at its execve boundary must be exactly the \
                     standard three: {closure:?}"
                );
                assert!(
                    closure.launcher_descriptors > 3,
                    "the launcher must have held more than the standard three, or a child table \
                     of exactly three proves nothing: {closure:?}"
                );
                expected_proven
                    .insert(contained_boundary::BackendControl::ClosedInheritedDescriptors);
                expected_missing
                    .retain(|control| {
                        *control != contained_boundary::BackendControl::ClosedInheritedDescriptors
                    });
            } else {
                assert!(
                    closure.launcher_threads > 1,
                    "the separate applier is chosen only when forking would be unsafe: {closure:?}"
                );
                expected_fragments.push("not a single-threaded launch component");
            }
            assert_eq!(
                proven,
                expected_proven,
                "the development helper's proven control set changed; refusal was {refusal}; \
                 measurements were: {:?}",
                backend.development_refusals()
            );

            let required = contained_boundary::required_controls(
                attempt.policy.contract().resource_limits,
            );
            let missing = required.difference(&proven).copied().collect::<Vec<_>>();
            assert_eq!(
                missing, expected_missing,
                "only the host-blocked controls may be missing"
            );
            for fragment in expected_fragments {
                assert!(
                    refusal.contains(fragment),
                    "the refusal must carry the live measurement {fragment:?}: {refusal}"
                );
            }

            // The boundary must reach the same conclusion through its own
            // ordering, and must never mint a permit from a partial set.
            let second = prepare_walking_skeleton_attempt();
            let backend = macos_backend::MacosDedicatedIdentityBackend::development(
                second.grant.clone(),
                second.policy.clone(),
                &second.paths,
                SESSION_ID,
            )
            .expect("recompose the development backend");
            match contained_boundary::execute_classified(
                backend,
                second.prepared,
                &CancellationToken::new(),
            ) {
                ContainedExecutionOutcome::RefusedBeforeLaunch(SupervisorError::Capability(
                    reason,
                )) => assert!(
                    reason.contains("cannot enforce"),
                    "unexpected boundary refusal: {reason}"
                ),
                other => panic!(
                    "the development backend must be refused before launch, observed: {other:?}"
                ),
            }
        }

        /// Compare the same canary suite at process ceilings of 64 and 1. Only the
        /// one-process policy can prove both descendant controls without a dedicated
        /// account. Fork denial and an empty survivor enumeration provide the evidence;
        /// this does not establish support for multi-process build commands.
        #[cfg(target_os = "macos")]
        #[test]
        fn a_single_process_policy_proves_both_descendant_controls_without_root() {
            let bounded = prepare_walking_skeleton_attempt_with(1);
            let mut backend = macos_backend::MacosDedicatedIdentityBackend::development(
                bounded.grant.clone(),
                bounded.policy.clone(),
                &bounded.paths,
                SESSION_ID,
            )
            .expect("compose the development backend for a single-process policy");
            let refusal = backend
                .active_preflight(&bounded.prepared)
                .expect_err("descriptor exec is still unprovable on macOS");
            let refusal = match refusal {
                SupervisorError::Capability(reason) => reason,
                other => panic!("unexpected development refusal: {other:?}"),
            };

            let domain = backend
                .development_descendant_domain()
                .expect("the descendant-domain probe recorded its observation");
            assert_eq!(domain.configured_max_processes, 1);
            assert!(
                !domain.dedicated_account,
                "no unprivileged run may claim a dedicated execution account: {domain:?}"
            );
            assert!(
                !domain.rlimit_nproc_applied,
                "the per-UID ceiling is still unavailable, so the claim below cannot be \
                 borrowing it: {domain:?}"
            );
            assert!(
                domain.real_uid_process_count > 1,
                "the shared UID owns unrelated processes, which is why RLIMIT_NPROC is not a \
                 domain ceiling here: {domain:?}"
            );
            let fork = domain
                .fork_denial
                .expect("the three-run fork canary completed");
            assert!(
                fork.control_forked && fork.restricted_ran_without_forking,
                "both control runs must succeed or the denial is unattributable: {fork:?}"
            );
            assert!(!fork.restricted_forked, "the profile must refuse: {fork:?}");
            let cancellation = domain
                .cancellation
                .as_ref()
                .expect("the cancellation probe recorded its observation");
            assert!(
                cancellation.terminated_by_deadline,
                "the domain-kill claim needs a real termination, not a normal exit: \
                 {cancellation:?}"
            );
            assert!(
                cancellation.leader_session_leader,
                "a leader that is not its own session leader could leave the enumerated group: \
                 {cancellation:?}"
            );
            assert_eq!(
                cancellation.leader_process_group, cancellation.leader_pid,
                "the leader must be its own process-group leader: {cancellation:?}"
            );
            assert!(
                cancellation.survivors.is_empty(),
                "the enumerated domain must be empty after termination: {cancellation:?}"
            );

            let proven = backend.enforced_controls();
            assert!(
                proven.contains(&contained_boundary::BackendControl::DescendantLimit),
                "a ceiling of one is enforced by the profile itself; refusal was {refusal}"
            );
            assert!(
                proven.contains(&contained_boundary::BackendControl::DescendantDomainKill),
                "a domain that cannot create a descendant and cannot leave its group is killed \
                 and proved empty; refusal was {refusal}"
            );

            // The other half of the comparison: the identical suite, with only
            // the configured ceiling changed, claims neither.
            let unbounded = prepare_walking_skeleton_attempt_with(64);
            let mut wide = macos_backend::MacosDedicatedIdentityBackend::development(
                unbounded.grant.clone(),
                unbounded.policy.clone(),
                &unbounded.paths,
                SESSION_ID,
            )
            .expect("compose the development backend for a 64-process policy");
            let _ = wide.active_preflight(&unbounded.prepared);
            let wide_proven = wide.enforced_controls();
            assert!(
                !wide_proven.contains(&contained_boundary::BackendControl::DescendantLimit)
                    && !wide_proven
                        .contains(&contained_boundary::BackendControl::DescendantDomainKill),
                "the same mechanism must not be claimed for a ceiling it cannot express: {:?}",
                wide.development_refusals()
            );
            let wide_domain = wide
                .development_descendant_domain()
                .expect("the wide probe recorded its observation");
            assert_eq!(
                wide_domain.fork_denial, domain.fork_denial,
                "the two runs must differ only in the configured ceiling"
            );
        }

        /// Local code attestation satisfies signing admission, but unprivileged
        /// execution still lacks the assigned account required for terminal evidence.
        /// The refusal must identify that missing host authority.
        #[cfg(target_os = "macos")]
        #[test]
        fn a_development_launch_refuses_to_mint_a_cleanup_proof() {
            assert!(
                macos_backend::MACOS_DEVELOPMENT_CLEANUP_PROOF_UNAVAILABLE
                    .contains("assigned local execution account"),
                "the unprivileged launch refusal must name the execution-account requirement"
            );
            assert!(
                !macos_backend::MACOS_DEVELOPMENT_CLEANUP_PROOF_UNAVAILABLE
                    .contains("production-signed"),
                "the refusal must not re-assert the signing requirement ADR-0012 removed"
            );
            assert_ne!(
                macos_backend::MACOS_DEDICATED_IDENTITY_DEV_BACKEND_ID,
                macos_backend::MACOS_DEDICATED_IDENTITY_BACKEND_ID,
                "development and production backend identities must never collide"
            );
        }

        /// The production constructor is untouched by the development arm.
        #[cfg(target_os = "macos")]
        #[test]
        fn the_production_backend_still_claims_nothing_and_refuses_everything() {
            let attempt = prepare_walking_skeleton_attempt();
            let mut backend = macos_backend::MacosDedicatedIdentityBackend::new(
                attempt.grant.clone(),
                attempt.policy.clone(),
                &attempt.paths,
            )
            .expect("compose the production macOS dedicated-identity backend");
            assert!(!backend.development_mode());
            assert!(backend.enforced_controls().is_empty());
            assert_eq!(
                backend
                    .identity()
                    .expect("production identity")
                    .backend_id(),
                macos_backend::MACOS_DEDICATED_IDENTITY_BACKEND_ID
            );
            match backend.active_preflight(&attempt.prepared) {
                Err(SupervisorError::Capability(reason)) => assert!(
                    reason.contains(
                        macos_backend::MACOS_DEDICATED_IDENTITY_TRANSPORT_UNAVAILABLE
                    ),
                    "unexpected production refusal: {reason}"
                ),
                other => panic!("the production backend must still refuse: {other:?}"),
            }
        }
    }
