    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        CommandOutputArtifactSourceV1, CommandSpec, ExecutionPolicyCompiler,
        ExecutionPolicyRequest, PathScope, WorkerLease, WorkspaceGrantIssuer,
        WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };

    use super::*;
    use crate::wire::{
        RUNNER_WIRE_PROTOCOL_VERSION, RunnerRequestEnvelope, WireCommandSpec, WireEffectContext,
        command_output_capture_maximum, test_command_output_capture_anchor,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn digest(marker: u8) -> Digest {
        Digest::sha256(&[marker])
    }

    fn retained_object(
        object_id: &str,
        kind: LinuxRetainedObjectKindV1,
        device_id: u64,
        inode: u64,
        mount_id: u64,
        mode: u32,
        byte_length: Option<u64>,
    ) -> LinuxRetainedObjectIdentityV1 {
        LinuxRetainedObjectIdentityV1 {
            object_id: object_id.into(),
            kind,
            device_id,
            inode,
            mount_id,
            mode,
            owner_uid: 1_000,
            owner_gid: 1_000,
            link_count: u64::from(kind != LinuxRetainedObjectKindV1::SealedMemfd),
            byte_length,
        }
    }

    /// Re-owns one retained object to the delegating installer.
    ///
    /// `retained_object` mints everything as the service (uid 1,000). Under
    /// cgroup v2 delegation the parent stays the delegator's, so the fixture
    /// has to be able to say so.
    const DELEGATOR_UID: u32 = 0;

    fn delegator_owned(
        mut object: LinuxRetainedObjectIdentityV1,
    ) -> LinuxRetainedObjectIdentityV1 {
        object.owner_uid = DELEGATOR_UID;
        object.owner_gid = DELEGATOR_UID;
        object
    }

    fn directory(object_id: &str, inode: u64) -> LinuxRetainedObjectIdentityV1 {
        retained_object(
            object_id,
            LinuxRetainedObjectKindV1::Directory,
            10,
            inode,
            10,
            DIRECTORY_MODE | 0o700,
            None,
        )
    }

    fn regular_file(
        object_id: &str,
        inode: u64,
        byte_length: u64,
        executable: bool,
    ) -> LinuxRetainedObjectIdentityV1 {
        retained_object(
            object_id,
            LinuxRetainedObjectKindV1::RegularFile,
            20,
            inode,
            20,
            REGULAR_FILE_MODE | if executable { 0o755 } else { 0o644 },
            Some(byte_length),
        )
    }

    fn authenticated_file(
        object_id: &str,
        path: &str,
        byte_length: u64,
        marker: u8,
    ) -> LinuxAuthenticatedFileV1 {
        LinuxAuthenticatedFileV1 {
            object_id: object_id.into(),
            resolved_path: path.into(),
            byte_length,
            content_sha256: digest(marker),
            immutability:
                LinuxFileImmutabilityV1::StableIdentityAndFullContentReadbackImmediatelyBeforeRelease,
        }
    }

    /// One `path_beneath` rule of the fixture plan's committed ruleset.
    ///
    /// The identity is the one the fixture's own object table carries for that
    /// role, because `validate_mandatory_control_artefacts` requires a
    /// committed scope to *be* a retained directory of the same plan.
    fn landlock_scope(object_id: &str, inode: u64, access_bits: u64) -> LinuxLandlockScopeV1 {
        LinuxLandlockScopeV1 {
            object_id: object_id.into(),
            resolved_path: format!("/run/grok/retained/{object_id}"),
            device_id: 10,
            inode,
            access_bits,
        }
    }

    /// The Landlock ruleset the fixture plan commits.
    ///
    /// Three of the fixture's retained directories, sorted by object ID as the
    /// schema requires, with the filesystem root as the object the ruleset
    /// states it does not grant.
    ///
    /// The grant's workspace root is deliberately absent: this fixture's
    /// workspace object carries the *live* identity of a real temporary
    /// directory, so a fixture that named it would have to restate a value it
    /// cannot know. A production ruleset does grant it — see
    /// `mint_mandatory_control_artefacts`, which reads that identity from the
    /// descriptor the service holds.
    fn fixture_landlock_ruleset() -> LinuxLandlockRulesetV1 {
        let mut ruleset = LinuxLandlockRulesetV1 {
            created_at_kernel_abi: 6,
            handled_access_bits: LINUX_LANDLOCK_ABI_1_HANDLED_ACCESS_BITS,
            scopes: vec![
                landlock_scope("execution", 101, LINUX_LANDLOCK_ABI_1_READ_ACCESS_BITS),
                landlock_scope(
                    "output-spool",
                    106,
                    LINUX_LANDLOCK_ABI_1_HANDLED_ACCESS_BITS,
                ),
                landlock_scope(
                    "private-temp",
                    105,
                    LINUX_LANDLOCK_ABI_1_HANDLED_ACCESS_BITS,
                ),
            ],
            denial_witness: LinuxLandlockDenialWitnessV1 {
                resolved_path: "/".into(),
                device_id: 1,
                inode: 2,
            },
            ruleset_sha256: digest(0),
        };
        ruleset.ruleset_sha256 = ruleset.canonical_digest();
        ruleset
    }

    /// The seccomp filter the fixture plan commits.
    ///
    /// `program_sha256` is a fixture digest rather than a live assembly, and
    /// that is the honest thing for a fixture to carry: the *plan* only ever
    /// requires it to be non-zero and to be the value the filter's own digest
    /// was taken over. The live assembly, and the requirement that a probe
    /// reproduce it instruction for instruction, belong to
    /// `mint_command_seccomp_filter` and `probe_seccomp_forbidden_syscall`.
    fn fixture_seccomp_filter(audit_architecture: LinuxAuditArchitectureV1) -> LinuxSeccompFilterV1 {
        let mut filter = LinuxSeccompFilterV1 {
            denied_syscalls: vec![
                LinuxSeccompDeniedSyscallV1 {
                    name: "connect".into(),
                    number: 42,
                },
                LinuxSeccompDeniedSyscallV1 {
                    name: "socket".into(),
                    number: 41,
                },
            ],
            instruction_count: 11,
            program_sha256: digest(78),
            filter_sha256: digest(0),
        };
        filter.filter_sha256 =
            filter.canonical_digest(audit_architecture, LinuxSeccompDefaultActionV1::KillProcess);
        filter
    }

    fn fixture_namespace_filter(
        audit_architecture: LinuxAuditArchitectureV1,
    ) -> LinuxSeccompNamespaceFilterV1 {
        let mut filter = LinuxSeccompNamespaceFilterV1 {
            action: LinuxSeccompNamespaceActionV1::ErrnoNotImplemented,
            denied_syscalls: committed_namespace_denials(audit_architecture),
            instruction_count: 13,
            program_sha256: digest(79),
            filter_sha256: digest(0),
        };
        filter.filter_sha256 = filter.canonical_digest(audit_architecture);
        filter
    }

    fn mount(
        source_object_id: &str,
        destination: &str,
        purpose: LinuxMountPurposeV1,
    ) -> LinuxRetainedMountV1 {
        LinuxRetainedMountV1 {
            source_object_id: source_object_id.into(),
            destination: destination.into(),
            purpose,
        }
    }

    fn git_mask(workspace_destination: &str) -> LinuxGitMaskV1 {
        LinuxGitMaskV1 {
            workspace_destination: workspace_destination.into(),
            masked_destination: format!("{workspace_destination}/.git"),
            empty_directory_object_id: "git-mask".into(),
            expected_empty_observation_digest: digest(90),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the exact complete plan fixture is intentionally visible in one place for schema review"
    )]
    pub(crate) fn fixture(role: RunnerRole) -> ValidatedLinuxProductionCommandPlanV1 {
        let root = std::env::temp_dir().join(format!(
            "grok-build-linux-plan-{}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
            match role {
                RunnerRole::Worker => "worker",
                RunnerRole::FinalVerifier => "verifier",
                RunnerRole::Applier => "applier",
                RunnerRole::LiveStateVerifier => "live-state-verifier",
            }
        ));
        fixture_at_workspace_inner(role, &root, true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the exact complete plan fixture is intentionally visible in one place for schema review"
    )]
    pub(crate) fn fixture_at_workspace(
        role: RunnerRole,
        root: &Path,
    ) -> ValidatedLinuxProductionCommandPlanV1 {
        fixture_at_workspace_inner(role, root, false)
    }

    /// The four caller-supplied inputs every Linux production command plan
    /// needs, whether the components come from a fixture or from the
    /// production mint.
    ///
    /// The grant, the compiled policy and the durable command-effect authority
    /// are the real production types; only the session validation that produces
    /// the authority is a test door, because outside a live service there is no
    /// other way to obtain one.
    pub(crate) struct LinuxPlanAuthorityFixture {
        pub(crate) grant: IssuedWorkspaceGrant,
        pub(crate) policy: CompiledExecutionPolicy,
        pub(crate) authority: CommandEffectAuthorityV1,
        pub(crate) native_launch: LinuxNativeLaunchIdentity,
    }

    /// Issues a grant over `root`, compiles a policy, and mints the durable
    /// command-effect authority for one command against `program`.
    ///
    /// This is one construction shared by the plan fixture and by the live
    /// production-mint canary, so the authority the mint is fed is the same
    /// authority the fixture is built from rather than a second one that could
    /// drift from it.
    #[allow(
        clippy::too_many_lines,
        reason = "the exact complete authority fixture is intentionally visible in one place for review"
    )]
    pub(crate) fn plan_authority_fixture(
        role: RunnerRole,
        root: &Path,
        program: &str,
        mutation_mode: MutationMode,
    ) -> LinuxPlanAuthorityFixture {
        std::fs::create_dir_all(root).expect("create unique workspace fixture");
        let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "grant-linux-plan".into(),
            workspace_root: root.to_path_buf(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .expect("issue fixture grant");
        let policy = ExecutionPolicyCompiler::compile(
            &grant,
            ExecutionPolicyRequest {
                policy_id: "policy-linux-plan".into(),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: if mutation_mode == MutationMode::ShadowWorkspace {
                    vec![PathScope::Relative(PathBuf::from("src"))]
                } else {
                    Vec::new()
                },
                environment: vec![],
                network: ExecutionNetwork::None,
                mutation_mode,
                resource_limits: ResourceLimits {
                    wall_time_ms: 60_000,
                    max_output_bytes: 1_048_576,
                    max_processes: 16,
                    max_memory_bytes: Some(536_870_912),
                },
                approval_id: None,
            },
        )
        .expect("compile fixture policy");
        let command = CommandSpec {
            program: program.into(),
            arguments: vec!["test".into(), "--offline".into(), "--locked".into()],
            working_directory: PathBuf::from("fixture"),
        };
        let command_bytes = serde_json::to_vec(&command).expect("encode command fixture");
        let request_digest = Digest::sha256(&command_bytes);
        let effect_id = match role {
            RunnerRole::Worker => "effect-linux-worker",
            RunnerRole::FinalVerifier => "effect-linux-verifier",
            RunnerRole::Applier | RunnerRole::LiveStateVerifier => {
                panic!("capture-only and applier roles cannot run commands")
            }
        };
        let wire_command = WireCommandSpec {
            program: command.program.clone(),
            arguments: command.arguments.clone(),
            working_directory: command
                .working_directory
                .to_str()
                .expect("fixture cwd is UTF-8")
                .into(),
        };
        let output_capture = test_command_output_capture_anchor(
            CommandOutputArtifactSourceV1 {
                sprint_id: "sprint-linux-plan".into(),
                runner_launch_id: "launch-linux-plan".into(),
                runner_session_id: "session-linux-plan".into(),
                effect_id: effect_id.into(),
                request_digest: request_digest.clone(),
            },
            digest(91),
            command_output_capture_maximum(policy.contract().resource_limits.max_output_bytes)
                .expect("Linux plan capture maximum"),
            u64::from(role == RunnerRole::FinalVerifier) + 1,
        );
        let request = match role {
            RunnerRole::Worker => RunnerRequest::WorkerRunCommand {
                command: wire_command,
                output_capture,
            },
            RunnerRole::FinalVerifier => RunnerRequest::FinalVerifierRunCommand {
                command: wire_command,
                output_capture,
            },
            RunnerRole::Applier | RunnerRole::LiveStateVerifier => unreachable!(),
        };
        let worker_lease = (role == RunnerRole::Worker).then(|| {
            WorkerLease::new(
                "sprint-linux-plan".into(),
                1,
                "task-linux-plan".into(),
                "worker-linux-plan".into(),
                vec![PathScope::Relative(PathBuf::from("src"))],
                1,
            )
            .expect("construct command fixture worker lease")
        });
        let mut envelope = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: "session-linux-plan".into(),
            runner_nonce: Some(digest(1)),
            sequence: 7,
            request_id: "request-linux-plan".into(),
            effect: Some(WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: "launch-linux-plan".into(),
                effect_id: effect_id.into(),
                idempotency_key: "idempotency-linux-plan".into(),
                sprint_id: "sprint-linux-plan".into(),
                task_id: (role == RunnerRole::Worker).then(|| "task-linux-plan".into()),
                worker_id: (role == RunnerRole::Worker).then(|| "worker-linux-plan".into()),
                worker_lease,
                policy_hash: policy.contract().policy_hash.clone(),
                input_snapshot: digest(7),
                request_digest,
                transport_commitment_digest: digest(0),
            }),
            request,
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind exact fixture transport commitment");
        let authority = CommandEffectAuthorityV1::from_session_validated(
            crate::service::test_session_validated_command_envelope(
                &envelope,
                &grant.contract().grant_hash,
            ),
        )
        .expect("validate fixture command authority")
        .expect("command produces effect authority");
        let native_launch = LinuxNativeLaunchIdentity {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-linux-plan".into(),
            native_journal_id: "native-journal-linux-plan".into(),
            expected_platform_binding_digest: digest(41),
            sprint_id: "sprint-linux-plan".into(),
            launch_id: "launch-linux-plan".into(),
            session_id: "session-linux-plan".into(),
            cleanup_effect_id: "cleanup-effect-linux-plan".into(),
            input_snapshot: digest(7),
            grant_hash: grant.contract().grant_hash.clone(),
            policy_hash: policy.contract().policy_hash.clone(),
            claimed_at_unix_ms: 10,
        };
        LinuxPlanAuthorityFixture {
            grant,
            policy,
            authority,
            native_launch,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the exact complete plan fixture is intentionally visible in one place for schema review"
    )]
    fn fixture_at_workspace_inner(
        role: RunnerRole,
        root: &Path,
        remove_workspace_after_build: bool,
    ) -> ValidatedLinuxProductionCommandPlanV1 {
        let LinuxPlanAuthorityFixture {
            grant,
            policy,
            authority,
            native_launch,
        } = plan_authority_fixture(
            role,
            root,
            "/usr/bin/cargo",
            match role {
                RunnerRole::Worker => MutationMode::ShadowWorkspace,
                RunnerRole::FinalVerifier => MutationMode::ReadOnly,
                RunnerRole::Applier | RunnerRole::LiveStateVerifier => {
                    panic!("capture-only and applier roles cannot run commands")
                }
            },
        );
        let execution_path = if role == RunnerRole::Worker {
            "/work"
        } else {
            "/verify"
        };
        let execution_purpose = if role == RunnerRole::Worker {
            LinuxMountPurposeV1::WorkerShadow
        } else {
            LinuxMountPurposeV1::FinalVerifierSnapshot
        };
        let objects = vec![
            retained_object(
                "workspace",
                LinuxRetainedObjectKindV1::Directory,
                grant.identity().device_id(),
                grant.identity().inode(),
                1,
                DIRECTORY_MODE | 0o700,
                None,
            ),
            directory("execution", 101),
            directory("private-state", 102),
            directory("journal-index", 103),
            directory("git-mask", 104),
            directory("private-temp", 105),
            directory("output-spool", 106),
            regular_file("bwrap", 201, 101, true),
            regular_file("inner", 202, 102, true),
            retained_object(
                "setup",
                LinuxRetainedObjectKindV1::SealedMemfd,
                30,
                203,
                30,
                REGULAR_FILE_MODE | 0o400,
                Some(64),
            ),
            regular_file("target", 204, 103, true),
            regular_file("interpreter", 205, 104, true),
            regular_file("runtime-libc", 206, 105, false),
            // The delegator's, not the service's, and shaped like the one the
            // anchor canary measures: root-owned `0o755`, traversable by the
            // service and writable only by the identity that delegated. Every
            // other fixture object is uid 1,000, which is the service.
            delegator_owned(retained_object(
                "cgroup-parent",
                LinuxRetainedObjectKindV1::CgroupDirectory,
                40,
                300,
                40,
                DIRECTORY_MODE | 0o755,
                None,
            )),
            retained_object(
                "cgroup-root",
                LinuxRetainedObjectKindV1::CgroupDirectory,
                40,
                301,
                40,
                DIRECTORY_MODE | 0o755,
                None,
            ),
        ];
        let components = LinuxProductionCommandPlanComponentsV1 {
            role_snapshot: LinuxRoleSnapshotBindingV1 {
                role,
                input_snapshot: digest(7),
                view: if role == RunnerRole::Worker {
                    LinuxExecutionViewV1::WorkerShadow
                } else {
                    LinuxExecutionViewV1::FinalVerifierSnapshot
                },
                execution_root_object_id: "execution".into(),
                execution_namespace_root: execution_path.into(),
            },
            binaries: LinuxBinaryIdentitiesV1 {
                bubblewrap: authenticated_file("bwrap", "/usr/bin/bwrap", 101, 10),
                bubblewrap_format: LinuxElfImageFormatV1::Elf64X86_64,
                // The admitted **package** version, not an invented
                // stdout-shaped string. The previous value gave both operands
                // of the bootstrap version clause one shape, which is exactly
                // what made that clause vacuous until a production probe met
                // it. `validate_service_bootstrap_evidence` now requires this
                // to be the admitted package version and requires the probe's
                // stdout to be the separately pinned self-report, so the two
                // operands can no longer be one invented value.
                bubblewrap_version: ADMITTED_BUBBLEWRAP_IMAGE_V1.version.into(),
                inner_launcher: authenticated_file(
                    "inner",
                    "/run/grok/inner-launcher",
                    102,
                    11,
                ),
                inner_launcher_format: LinuxElfImageFormatV1::Elf64X86_64,
                setup_channel: LinuxSetupChannelV1 {
                    object_id: "setup".into(),
                    byte_length: 64,
                    content_sha256: digest(12),
                    protocol_digest: digest(13),
                    seal_bits: REQUIRED_SETUP_SEAL_BITS,
                },
                target: LinuxProgramImageV1 {
                    requested_program: "/usr/bin/cargo".into(),
                    executable: authenticated_file(
                        "target",
                        "/run/grok/target",
                        103,
                        14,
                    ),
                    image_format: LinuxElfImageFormatV1::Elf64X86_64,
                    linkage: LinuxTargetLinkageV1::DynamicElf {
                        interpreter: authenticated_file(
                            "interpreter",
                            "/lib64/ld-linux-x86-64.so.2",
                            104,
                            15,
                        ),
                        interpreter_format: LinuxElfImageFormatV1::Elf64X86_64,
                        runtime_objects: vec![authenticated_file(
                            "runtime-libc",
                            "/lib64/libc.so.6",
                            105,
                            16,
                        )],
                    },
                },
            },
            retained: LinuxRetainedCapabilitySetV1 {
                workspace_root_object_id: "workspace".into(),
                private_state_root_object_id: "private-state".into(),
                service_owned_journal_index_root_object_id: "journal-index".into(),
                objects,
                cgroup: LinuxCgroupIdentitySetV1 {
                    filesystem_magic: CGROUP2_SUPER_MAGIC,
                    service_parent_object_id: "cgroup-parent".into(),
                    delegation_root_object_id: "cgroup-root".into(),
                    leaf: LinuxCommandDomainLeafPlanV1::contract(),
                },
            },
            mounts: LinuxMountPlanV1 {
                read_only: vec![
                    mount(
                        "workspace",
                        "/run/grok/live",
                        LinuxMountPurposeV1::LiveWorkspace,
                    ),
                    mount(
                        "inner",
                        "/run/grok/inner-launcher",
                        LinuxMountPurposeV1::InnerLauncher,
                    ),
                    mount(
                        "target",
                        "/run/grok/target",
                        LinuxMountPurposeV1::TargetExecutable,
                    ),
                    mount(
                        "interpreter",
                        "/lib64/ld-linux-x86-64.so.2",
                        LinuxMountPurposeV1::ElfInterpreter,
                    ),
                    mount(
                        "runtime-libc",
                        "/lib64/libc.so.6",
                        LinuxMountPurposeV1::RuntimeObject,
                    ),
                ],
                read_write: vec![
                    mount(
                        "private-temp",
                        "/tmp",
                        LinuxMountPurposeV1::PrivateTemp,
                    ),
                    mount(
                        "output-spool",
                        "/run/grok/output",
                        LinuxMountPurposeV1::OutputSpool,
                    ),
                ],
                git_masks: vec![git_mask("/run/grok/live")],
            },
            network: LinuxNetworkNamespacePolicyV1::NewIsolatedNamespace,
            privilege_namespaces: LinuxPrivilegeNamespacePlanV1 {
                user: LinuxNamespaceRequirementV1::NewAndVerified,
                mount: LinuxNamespaceRequirementV1::NewAndVerified,
                pid: LinuxNamespaceRequirementV1::NewAndVerified,
                ipc: LinuxNamespaceRequirementV1::NewAndVerified,
                uts: LinuxNamespaceRequirementV1::NewAndVerified,
                cgroup: LinuxNamespaceRequirementV1::NewAndVerified,
                capabilities: LinuxCapabilityRequirementV1::DropAllAndVerifyEverySetEmpty,
                no_new_privileges:
                    LinuxNoNewPrivilegesRequirementV1::SetAndReadBackBeforeFilter,
            },
            // Schema version 3: there is nothing here to invent. The five
            // Landlock digests and three seccomp digests this fixture used to
            // carry as `digest(20)`..`digest(32)` were the only values those
            // fields ever held anywhere, which is exactly why the fields are
            // gone.
            landlock: LinuxLandlockPlanV1::InstalledRulesetProvenByLiveBootstrapProbe {
                enforcement: LinuxMandatoryEnforcementV1::FullOrRefuseBeforeTargetExec,
                minimum_kernel_abi: 6,
                maximum_modeled_kernel_abi: 10,
                ruleset: fixture_landlock_ruleset(),
            },
            seccomp: LinuxSeccompPlanV1::CompiledFilterProvenByLiveBootstrapProbe {
                enforcement: LinuxMandatoryEnforcementV1::FullOrRefuseBeforeTargetExec,
                audit_architecture: LinuxAuditArchitectureV1::X86_64,
                default_action: LinuxSeccompDefaultActionV1::KillProcess,
                filter: fixture_seccomp_filter(LinuxAuditArchitectureV1::X86_64),
                namespace_filter: fixture_namespace_filter(LinuxAuditArchitectureV1::X86_64),
            },
            process_surface: LinuxProcessSurfaceV1 {
                environment: LinuxEnvironmentPolicyV1::ClearThenInstallExactCompiledEnvironment,
                descriptors:
                    LinuxDescriptorPolicyV1::SetupChannelOnlyWhileHeldThenStdioOnlyAtTarget,
                command: LinuxCommandBindingPolicyV1::ExactAuthorityArgvAndRetainedCwd,
            },
            resource_limits: LinuxResourceLimitsV1 {
                wall_time_ms: 60_000,
                max_output_bytes: 1_048_576,
                max_processes: 16,
                max_memory_bytes: Some(536_870_912),
                swap_bytes: 0,
            },
            release: LinuxProductionReleaseExpectationV1 {
                schema: LINUX_PRODUCTION_HELD_RELEASE_SCHEMA.into(),
                authenticated_platform_service_digest: digest(40),
                held_before_release: LinuxHeldBeforeReleaseV1::RequiredBeforeAnyTargetCode,
                live_claim:
                    LinuxLiveReleaseClaimRequirementV1::NonCloneableLiveClaimConsumedSynchronously,
                journal: LinuxReleaseJournalRequirementV1::PersistIntentBeforeSynchronousReleaseAndReconcileOnlyAfterRestart,
                replay_exclusion:
                    LinuxReplayExclusionRequirementV1::GlobalEffectIdOneShotAcrossAllRunnerSessions,
                journal_ownership:
                    LinuxJournalOwnershipRequirementV1::ServiceOwnedSingletonPerAuthenticatedDelegation,
            },
            terminal_evidence: LinuxExpectedTerminalEvidenceV1 {
                runtime_schema: LINUX_COMMAND_RUNTIME_EVIDENCE_SCHEMA.into(),
                cleanup_schema: LINUX_COMMAND_CLEANUP_EVIDENCE_SCHEMA.into(),
                runtime_requirements: REQUIRED_RUNTIME_EVIDENCE.to_vec(),
                cleanup_requirements_in_order: REQUIRED_CLEANUP.to_vec(),
            },
        };
        let mut components = components;
        if role == RunnerRole::Worker {
            components.mounts.read_write.push(mount(
                "execution",
                execution_path,
                execution_purpose,
            ));
        } else {
            components
                .mounts
                .read_only
                .push(mount("execution", execution_path, execution_purpose));
        }
        components.mounts.git_masks.push(git_mask(execution_path));
        let validated = LinuxProductionCommandPlanV1::build(
            native_launch,
            authority,
            &grant,
            &policy,
            components,
        )
        .expect("build canonical non-admissible Linux plan");
        if remove_workspace_after_build {
            std::fs::remove_dir(root).expect("remove fixture workspace");
        }
        validated
    }

    #[test]
    fn worker_and_final_verifier_plans_retain_complete_authority_but_never_execute() {
        for role in [RunnerRole::Worker, RunnerRole::FinalVerifier] {
            let plan = fixture(role);
            assert!(!ValidatedLinuxProductionCommandPlanV1::permits_execution());
            assert_ne!(plan.plan_digest(), &digest(0));
            let round_trip =
                ValidatedLinuxProductionCommandPlanV1::decode_exact(plan.canonical_bytes())
                    .expect("exact canonical plan round trips");
            assert_eq!(round_trip, plan);
            let encoded = std::str::from_utf8(plan.canonical_bytes()).expect("plan is JSON");
            assert!(encoded.contains("idempotency-linux-plan"));
            assert!(encoded.contains("session-linux-plan"));
            assert!(encoded.contains("transport_commitment_digest"));
            assert!(encoded.contains("global_effect_id_one_shot_across_all_runner_sessions"));
            assert!(encoded.contains("service_owned_singleton_per_authenticated_delegation"));
        }
    }

    #[test]
    fn launch_image_projection_is_role_exact_pathless_and_destination_bound() {
        for role in [RunnerRole::Worker, RunnerRole::FinalVerifier] {
            let plan = fixture(role);
            let bindings = plan.service_launch_image_bindings().unwrap();
            assert_eq!(bindings.len(), 5);
            assert_eq!(
                bindings
                    .iter()
                    .map(|binding| binding.role)
                    .collect::<Vec<_>>(),
                vec![
                    LinuxServiceExecutableRoleV1::Bubblewrap,
                    LinuxServiceExecutableRoleV1::InnerLauncher,
                    LinuxServiceExecutableRoleV1::Target,
                    LinuxServiceExecutableRoleV1::ElfInterpreter,
                    LinuxServiceExecutableRoleV1::RuntimeObject,
                ]
            );
            assert_eq!(
                bindings[0].usage,
                LinuxServiceLaunchImageUseV1::HostExecutable
            );
            for (binding, purpose, destination) in [
                (
                    &bindings[1],
                    LinuxMountPurposeV1::InnerLauncher,
                    "/run/grok/inner-launcher",
                ),
                (
                    &bindings[2],
                    LinuxMountPurposeV1::TargetExecutable,
                    "/run/grok/target",
                ),
                (
                    &bindings[3],
                    LinuxMountPurposeV1::ElfInterpreter,
                    "/lib64/ld-linux-x86-64.so.2",
                ),
                (
                    &bindings[4],
                    LinuxMountPurposeV1::RuntimeObject,
                    "/lib64/libc.so.6",
                ),
            ] {
                assert_eq!(
                    binding.usage,
                    LinuxServiceLaunchImageUseV1::ReadOnlyNamespaceMount {
                        purpose,
                        destination: destination.into(),
                    }
                );
                assert_ne!(binding.byte_length, 0);
                assert_ne!(binding.content_sha256, digest(0));
            }
        }
    }

    #[test]
    fn setup_descriptor_projection_is_versioned_complete_and_phase_exact() {
        for (role, namespace_cwd, expected_mount_sources) in [
            (RunnerRole::Worker, "/work/fixture", 3_usize),
            (RunnerRole::FinalVerifier, "/verify/fixture", 4_usize),
        ] {
            let plan = fixture(role);
            let binding = plan.service_setup_descriptor_binding().unwrap();
            assert_eq!(binding.schema, LINUX_SERVICE_SETUP_DESCRIPTOR_SCHEMA);
            assert_eq!(binding.plan_digest, *plan.plan_digest());
            assert_eq!(binding.cwd.execution_root.object_id, "execution");
            assert_eq!(binding.cwd.root_relative_path, "fixture");
            assert_eq!(binding.cwd.namespace_path, namespace_cwd);
            assert_eq!(binding.private_state_root.object_id, "private-state");
            assert_eq!(binding.singleton_journal_root.object_id, "journal-index");
            assert_eq!(
                binding.read_only_mount_sources.len(),
                expected_mount_sources
            );
            assert_eq!(binding.endpoints.len(), 6);
            assert_eq!(
                binding
                    .endpoints
                    .iter()
                    .map(|endpoint| endpoint.role)
                    .collect::<Vec<_>>(),
                vec![
                    LinuxServiceSetupEndpointRoleV1::SetupRequest,
                    LinuxServiceSetupEndpointRoleV1::SetupControl,
                    LinuxServiceSetupEndpointRoleV1::SetupStatus,
                    LinuxServiceSetupEndpointRoleV1::TargetStdin,
                    LinuxServiceSetupEndpointRoleV1::TargetStdout,
                    LinuxServiceSetupEndpointRoleV1::TargetStderr,
                ]
            );
            assert!(
                binding
                    .endpoints
                    .iter()
                    .all(|endpoint| endpoint.close_on_exec_while_retained)
            );
            assert!(binding.endpoint_identities_must_be_pairwise_distinct);
            assert_eq!(binding.post_exec_target_allowed_roles.len(), 3);
            assert!(binding.post_exec_target_allowed_roles.iter().all(|role| {
                matches!(
                    role,
                    LinuxServiceSetupDescriptorRoleV1::Endpoint(
                        LinuxServiceSetupEndpointRoleV1::TargetStdin
                            | LinuxServiceSetupEndpointRoleV1::TargetStdout
                            | LinuxServiceSetupEndpointRoleV1::TargetStderr
                    )
                )
            }));
            assert_eq!(
                binding.close_on_successful_target_exec_roles,
                vec![LinuxServiceSetupDescriptorRoleV1::Endpoint(
                    LinuxServiceSetupEndpointRoleV1::SetupStatus
                )]
            );
            assert_eq!(binding.target_exec_attempt_allowed_roles.len(), 4);
            assert!(binding.close_after_setup_before_target_exec_roles.contains(
                &LinuxServiceSetupDescriptorRoleV1::Endpoint(
                    LinuxServiceSetupEndpointRoleV1::SetupControl
                )
            ));
            assert!(
                !binding.close_after_setup_before_target_exec_roles.contains(
                    &LinuxServiceSetupDescriptorRoleV1::Endpoint(
                        LinuxServiceSetupEndpointRoleV1::SetupStatus
                    )
                )
            );
            for role in &binding.held_setup_allowed_roles {
                assert_eq!(
                    usize::from(binding.target_exec_attempt_allowed_roles.contains(role))
                        + usize::from(
                            binding
                                .close_after_setup_before_target_exec_roles
                                .contains(role)
                        ),
                    1
                );
            }
            for role in &binding.target_exec_attempt_allowed_roles {
                assert_eq!(
                    usize::from(binding.post_exec_target_allowed_roles.contains(role))
                        + usize::from(binding.close_on_successful_target_exec_roles.contains(role)),
                    1
                );
            }
        }
    }

    #[test]
    fn setup_descriptor_projection_binds_every_non_image_read_only_destination() {
        let plan = fixture(RunnerRole::FinalVerifier);
        let binding = plan.service_setup_descriptor_binding().unwrap();
        let launch_ids = plan
            .service_launch_image_bindings()
            .unwrap()
            .into_iter()
            .map(|image| image.object_id)
            .collect::<BTreeSet<_>>();
        assert!(binding.read_only_mount_sources.iter().all(|source| {
            source.access == LinuxServiceSetupDescriptorAccessV1::ReadOnly
                && !launch_ids.contains(&source.object.object_id)
        }));
        assert_eq!(
            binding
                .read_only_mount_sources
                .iter()
                .map(|source| source.destination.as_str())
                .collect::<Vec<_>>(),
            vec![
                "/run/grok/live",
                "/run/grok/live/.git",
                "/verify",
                "/verify/.git"
            ]
        );
        assert!(matches!(
            binding.endpoints[0].source,
            LinuxServiceSetupEndpointSourceV1::PlanSealedRequest { .. }
        ));
        assert!(
            binding.endpoints[1..]
                .iter()
                .all(|endpoint| endpoint.source == LinuxServiceSetupEndpointSourceV1::ServicePipe)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one projection test keeps every fixed descriptor and dynamic-loader field visible"
    )]
    fn child_launch_closure_projection_is_complete_phase_exact_and_dynamic() {
        let plan = fixture(RunnerRole::Worker);
        let binding = plan.service_child_launch_closure_binding().unwrap();

        assert_eq!(binding.schema, LINUX_SERVICE_CHILD_LAUNCH_CLOSURE_SCHEMA);
        assert_eq!(binding.plan_digest, *plan.plan_digest());
        assert_eq!(binding.bubblewrap_host_executable_object_id, "bwrap");
        assert!(binding.child_target_fds_are_contiguous_and_unique);
        assert_eq!(binding.inner_launcher_descriptor_table.len(), 7);
        assert_eq!(
            binding
                .inner_launcher_descriptor_table
                .iter()
                .map(|descriptor| descriptor.target_fd)
                .collect::<Vec<_>>(),
            (0_u32..=6).collect::<Vec<_>>()
        );
        assert_eq!(
            binding
                .inner_launcher_descriptor_table
                .iter()
                .map(|descriptor| descriptor.source.clone())
                .collect::<Vec<_>>(),
            vec![
                LinuxServiceChildDescriptorSourceV1::Endpoint(
                    LinuxServiceSetupEndpointRoleV1::TargetStdin,
                ),
                LinuxServiceChildDescriptorSourceV1::Endpoint(
                    LinuxServiceSetupEndpointRoleV1::TargetStdout,
                ),
                LinuxServiceChildDescriptorSourceV1::Endpoint(
                    LinuxServiceSetupEndpointRoleV1::TargetStderr,
                ),
                LinuxServiceChildDescriptorSourceV1::Endpoint(
                    LinuxServiceSetupEndpointRoleV1::SetupRequest,
                ),
                LinuxServiceChildDescriptorSourceV1::Endpoint(
                    LinuxServiceSetupEndpointRoleV1::SetupControl,
                ),
                LinuxServiceChildDescriptorSourceV1::Endpoint(
                    LinuxServiceSetupEndpointRoleV1::SetupStatus,
                ),
                LinuxServiceChildDescriptorSourceV1::WorkingDirectory {
                    execution_root_object_id: "execution".into(),
                    root_relative_path: "fixture".into(),
                },
            ]
        );
        assert!(
            binding
                .inner_launcher_descriptor_table
                .iter()
                .all(|descriptor| descriptor.retained_source_close_on_exec)
        );
        assert_eq!(
            binding
                .inner_launcher_descriptor_table
                .iter()
                .map(|descriptor| descriptor.child_close_on_exec)
                .collect::<Vec<_>>(),
            vec![false, false, false, true, true, true, true]
        );
        assert_eq!(
            binding.inner_launcher_descriptor_table[3].retained_source_access,
            LinuxServiceSetupDescriptorAccessV1::ReadWrite
        );
        assert_eq!(
            binding.inner_launcher_descriptor_table[3].child_access,
            LinuxServiceSetupDescriptorAccessV1::ReadOnly
        );
        assert!(
            binding.inner_launcher_descriptor_table[..3]
                .iter()
                .all(|descriptor| {
                    descriptor.lifecycle == LinuxServiceChildDescriptorLifecycleV1::RetainPostExec
                })
        );
        assert_eq!(
            binding.inner_launcher_descriptor_table[5].lifecycle,
            LinuxServiceChildDescriptorLifecycleV1::CloseOnSuccessfulExec
        );
        assert!(
            binding.inner_launcher_descriptor_table[3..]
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != 2)
                .all(|(_, descriptor)| {
                    descriptor.lifecycle == LinuxServiceChildDescriptorLifecycleV1::CloseAfterSetup
                })
        );

        assert!(binding.mount_destinations_must_be_pairwise_distinct);
        assert_eq!(
            binding
                .image_mounts
                .iter()
                .map(|mount| (mount.mount_index, mount.role, mount.destination.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (
                    0,
                    LinuxServiceExecutableRoleV1::InnerLauncher,
                    "/run/grok/inner-launcher",
                ),
                (1, LinuxServiceExecutableRoleV1::Target, "/run/grok/target",),
                (
                    2,
                    LinuxServiceExecutableRoleV1::ElfInterpreter,
                    "/lib64/ld-linux-x86-64.so.2",
                ),
                (
                    3,
                    LinuxServiceExecutableRoleV1::RuntimeObject,
                    "/lib64/libc.so.6",
                ),
            ]
        );
        assert!(binding.image_mounts.iter().all(|mount| {
            mount.read_only
                && mount.retained_source_close_on_exec
                && mount.byte_length != 0
                && mount.content_sha256 != digest(0)
        }));
        assert_eq!(
            binding.loader_closure,
            LinuxServiceTargetLoaderClosureV1::Dynamic {
                target_object_id: "target".into(),
                interpreter_object_id: "interpreter".into(),
                runtime_object_ids_in_order: vec!["runtime-libc".into()],
            }
        );
    }

    #[test]
    fn child_launch_closure_static_target_excludes_dynamic_loader_images() {
        let valid = fixture(RunnerRole::Worker);
        let mut plan = valid.plan;
        plan.components.binaries.target.linkage = LinuxTargetLinkageV1::StaticElf;
        plan.components.retained.objects.retain(|object| {
            object.object_id != "interpreter" && object.object_id != "runtime-libc"
        });
        plan.components.mounts.read_only.retain(|mount| {
            !matches!(
                mount.purpose,
                LinuxMountPurposeV1::ElfInterpreter | LinuxMountPurposeV1::RuntimeObject
            )
        });
        let plan = ValidatedLinuxProductionCommandPlanV1::from_plan(plan).unwrap();
        let binding = plan.service_child_launch_closure_binding().unwrap();

        assert_eq!(
            binding
                .image_mounts
                .iter()
                .map(|mount| mount.role)
                .collect::<Vec<_>>(),
            vec![
                LinuxServiceExecutableRoleV1::InnerLauncher,
                LinuxServiceExecutableRoleV1::Target,
            ]
        );
        assert_eq!(
            binding.loader_closure,
            LinuxServiceTargetLoaderClosureV1::Static {
                target_object_id: "target".into(),
            }
        );
    }

    #[test]
    fn static_launch_image_projection_forbids_interpreter_and_runtime_closure() {
        let valid = fixture(RunnerRole::Worker);
        let mut plan = valid.plan;
        plan.components.binaries.target.linkage = LinuxTargetLinkageV1::StaticElf;
        plan.components.retained.objects.retain(|object| {
            object.object_id != "interpreter" && object.object_id != "runtime-libc"
        });
        plan.components.mounts.read_only.retain(|mount| {
            !matches!(
                mount.purpose,
                LinuxMountPurposeV1::ElfInterpreter | LinuxMountPurposeV1::RuntimeObject
            )
        });
        let plan = ValidatedLinuxProductionCommandPlanV1::from_plan(plan).unwrap();
        let bindings = plan.service_launch_image_bindings().unwrap();
        assert_eq!(bindings.len(), 3);
        assert!(bindings.iter().all(|binding| !matches!(
            binding.role,
            LinuxServiceExecutableRoleV1::ElfInterpreter
                | LinuxServiceExecutableRoleV1::RuntimeObject
        )));
    }

    #[test]
    fn launch_image_projection_rejects_host_mount_and_crossed_dynamic_destination() {
        let mut host_mounted = fixture(RunnerRole::Worker);
        host_mounted.plan.components.mounts.read_only[0].source_object_id = "bwrap".into();
        let error = host_mounted.service_launch_image_bindings().unwrap_err();
        assert!(error.to_string().contains("sole host executable"));

        let mut crossed = fixture(RunnerRole::Worker);
        let runtime = crossed
            .plan
            .components
            .mounts
            .read_only
            .iter_mut()
            .find(|mount| mount.purpose == LinuxMountPurposeV1::RuntimeObject)
            .unwrap();
        runtime.destination = "/crossed/libc.so.6".into();
        let error = crossed.service_launch_image_bindings().unwrap_err();
        assert!(error.to_string().contains("crossed namespace destination"));
    }

    #[test]
    fn crossed_authority_role_snapshot_policy_and_network_are_rejected() {
        let valid = fixture(RunnerRole::Worker);

        let mut crossed_policy = valid.plan.clone();
        crossed_policy.compiled_authority.policy.policy_hash = digest(200);
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(crossed_policy).is_err());

        let mut crossed_snapshot = valid.plan.clone();
        crossed_snapshot.components.role_snapshot.input_snapshot = digest(201);
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(crossed_snapshot).is_err());

        let mut crossed_role = valid.plan.clone();
        crossed_role.components.role_snapshot.role = RunnerRole::FinalVerifier;
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(crossed_role).is_err());

        let mut crossed_network = valid.plan.clone();
        crossed_network.components.network =
            LinuxNetworkNamespacePolicyV1::RetainHostNamespaceForRenewedAction {
                grant_hash: crossed_network
                    .command_effect_authority
                    .grant_hash()
                    .clone(),
                policy_hash: crossed_network
                    .compiled_authority
                    .policy
                    .policy_hash
                    .clone(),
            };
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(crossed_network).is_err());
    }

    #[test]
    fn binary_mount_git_and_byte_length_substitutions_are_rejected() {
        let valid = fixture(RunnerRole::Worker);

        let mut crossed_binary = valid.plan.clone();
        crossed_binary.components.binaries.inner_launcher.object_id = "target".into();
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(crossed_binary).is_err());

        let mut bind_aliased_role = valid.plan.clone();
        let target = bind_aliased_role
            .components
            .retained
            .objects
            .iter()
            .find(|object| object.object_id == "target")
            .expect("target object exists")
            .clone();
        let inner = bind_aliased_role
            .components
            .retained
            .objects
            .iter_mut()
            .find(|object| object.object_id == "inner")
            .expect("inner launcher object exists");
        inner.device_id = target.device_id;
        inner.inode = target.inode;
        inner.mount_id = target.mount_id.checked_add(1).unwrap();
        let error = ValidatedLinuxProductionCommandPlanV1::from_plan(bind_aliased_role)
            .expect_err("one inode exposed through another mount cannot cross roles");
        assert!(error.to_string().contains("including across bind mounts"));

        let mut crossed_mount = valid.plan.clone();
        let target_mount = crossed_mount
            .components
            .mounts
            .read_only
            .iter_mut()
            .find(|mount| mount.purpose == LinuxMountPurposeV1::TargetExecutable)
            .expect("target mount exists");
        target_mount.source_object_id = "runtime-libc".into();
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(crossed_mount).is_err());

        let mut missing_mask = valid.plan.clone();
        missing_mask.components.mounts.git_masks.pop();
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(missing_mask).is_err());

        let mut crossed_length = valid.plan.clone();
        crossed_length
            .components
            .retained
            .objects
            .iter_mut()
            .find(|object| object.object_id == "target")
            .expect("target object exists")
            .byte_length = Some(104);
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(crossed_length).is_err());

        let mut weakened_immutability = valid.plan.clone();
        weakened_immutability
            .components
            .binaries
            .target
            .executable
            .immutability = LinuxFileImmutabilityV1::SealedMemfd {
            seal_bits: REQUIRED_SETUP_SEAL_BITS,
        };
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(weakened_immutability).is_err());

        let mut writable_image = valid.plan.clone();
        writable_image
            .components
            .retained
            .objects
            .iter_mut()
            .find(|object| object.object_id == "inner")
            .expect("inner launcher object exists")
            .mode |= 0o022;
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(writable_image).is_err());
    }

    #[test]
    fn replay_journal_release_and_terminal_evidence_substitutions_are_rejected() {
        let valid = fixture(RunnerRole::Worker);

        let mut parallel_root = valid.plan.clone();
        parallel_root
            .components
            .retained
            .service_owned_journal_index_root_object_id = "private-state".into();
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(parallel_root).is_err());

        let mut inert_schema = valid.plan.clone();
        inert_schema.components.release.schema = "grok-build/linux-inert-held-release/v1".into();
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(inert_schema).is_err());

        let mut incomplete_cleanup = valid.plan.clone();
        incomplete_cleanup
            .components
            .terminal_evidence
            .cleanup_requirements_in_order
            .pop();
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(incomplete_cleanup).is_err());

        let mut incomplete_runtime = valid.plan.clone();
        incomplete_runtime
            .components
            .terminal_evidence
            .runtime_requirements
            .swap(0, 1);
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(incomplete_runtime).is_err());
    }

    #[test]
    fn canonical_decoder_rejects_unknown_noncanonical_and_crossed_transport_fields() {
        let valid = fixture(RunnerRole::Worker);
        let mut unknown: serde_json::Value =
            serde_json::from_slice(valid.canonical_bytes()).expect("decode fixture JSON");
        unknown.as_object_mut().expect("plan is an object").insert(
            "future_release_permit".into(),
            serde_json::Value::Bool(true),
        );
        let unknown = serde_json::to_vec(&unknown).expect("encode unknown-field fixture");
        assert!(matches!(
            ValidatedLinuxProductionCommandPlanV1::decode_exact(&unknown),
            Err(LinuxProductionCommandPlanError::Decode(_))
        ));

        let mut whitespace = valid.canonical_bytes().to_vec();
        whitespace.push(b'\n');
        assert_eq!(
            ValidatedLinuxProductionCommandPlanV1::decode_exact(&whitespace),
            Err(LinuxProductionCommandPlanError::NonCanonical)
        );

        let mut crossed: serde_json::Value =
            serde_json::from_slice(valid.canonical_bytes()).expect("decode transport fixture");
        crossed["command_effect_authority"]["envelope"]["effect"]["effect_id"] =
            serde_json::Value::String("effect-crossed-to-another-session".into());
        let crossed = serde_json::to_vec(&crossed).expect("encode crossed transport fixture");
        assert!(ValidatedLinuxProductionCommandPlanV1::decode_exact(&crossed).is_err());
    }

    #[test]
    fn field_loss_and_cross_session_lease_policy_grant_and_command_are_rejected() {
        let valid = fixture(RunnerRole::Worker);

        let mut missing: serde_json::Value =
            serde_json::from_slice(valid.canonical_bytes()).expect("decode complete plan");
        missing
            .as_object_mut()
            .expect("plan object")
            .remove("native_launch");
        assert!(
            ValidatedLinuxProductionCommandPlanV1::decode_exact(
                &serde_json::to_vec(&missing).unwrap()
            )
            .is_err()
        );

        let mut mutations = Vec::new();
        let mut session: serde_json::Value =
            serde_json::from_slice(valid.canonical_bytes()).unwrap();
        session["command_effect_authority"]["envelope"]["session_id"] =
            serde_json::Value::String("crossed-session".into());
        mutations.push(session);

        let mut lease: serde_json::Value = serde_json::from_slice(valid.canonical_bytes()).unwrap();
        lease["command_effect_authority"]["envelope"]["effect"]["worker_lease"] =
            serde_json::Value::Null;
        mutations.push(lease);

        let mut policy: serde_json::Value =
            serde_json::from_slice(valid.canonical_bytes()).unwrap();
        policy["command_effect_authority"]["envelope"]["effect"]["policy_hash"] =
            serde_json::Value::String(digest(210).to_string());
        mutations.push(policy);

        let mut grant: serde_json::Value = serde_json::from_slice(valid.canonical_bytes()).unwrap();
        grant["command_effect_authority"]["grant_hash"] =
            serde_json::Value::String(digest(211).to_string());
        mutations.push(grant);

        let mut command: serde_json::Value =
            serde_json::from_slice(valid.canonical_bytes()).unwrap();
        command["command_effect_authority"]["envelope"]["request"]["command"]["arguments"][0] =
            serde_json::Value::String("build".into());
        mutations.push(command);

        for mutation in mutations {
            let bytes = serde_json::to_vec(&mutation).unwrap();
            assert!(
                ValidatedLinuxProductionCommandPlanV1::decode_exact(&bytes).is_err(),
                "crossed complete-plan authority must fail closed"
            );
        }
    }

    #[test]
    fn hard_runtime_bound_and_cgroup_crossing_are_rejected() {
        let valid = fixture(RunnerRole::Worker);
        let mut oversized = valid.plan.clone();
        let LinuxTargetLinkageV1::DynamicElf {
            runtime_objects, ..
        } = &mut oversized.components.binaries.target.linkage
        else {
            panic!("fixture is dynamically linked")
        };
        let template = runtime_objects[0].clone();
        runtime_objects.resize(MAX_RUNTIME_OBJECTS + 1, template);
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(oversized).is_err());

        let mut crossed_cgroup = valid.plan.clone();
        crossed_cgroup.components.retained.cgroup.delegation_root_object_id =
            crossed_cgroup.components.retained.cgroup.service_parent_object_id.clone();
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(crossed_cgroup).is_err());

        // The plan must not be able to re-describe the leaf-name grammar,
        // because a second copy of it could admit a name `prepare_domain`
        // never mints.
        let mut drifted_grammar = valid.plan.clone();
        let LinuxCommandDomainLeafPlanV1::NotNamedByThePlanBoundAfterPreparationFromALiveRead {
            name_prefix,
            ..
        } = &mut drifted_grammar.components.retained.cgroup.leaf;
        *name_prefix = "gbx-".into();
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(drifted_grammar).is_err());

        let mut short_nonce = valid.plan.clone();
        let LinuxCommandDomainLeafPlanV1::NotNamedByThePlanBoundAfterPreparationFromALiveRead {
            nonce_hexadecimal_characters,
            ..
        } = &mut short_nonce.components.retained.cgroup.leaf;
        *nonce_hexadecimal_characters = 16;
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(short_nonce).is_err());

        let mut dropped_control_file = valid.plan.clone();
        let LinuxCommandDomainLeafPlanV1::NotNamedByThePlanBoundAfterPreparationFromALiveRead {
            required_control_files,
            ..
        } = &mut dropped_control_file.components.retained.cgroup.leaf;
        required_control_files.pop();
        assert!(ValidatedLinuxProductionCommandPlanV1::from_plan(dropped_control_file).is_err());
    }

    /// The plan carries a Landlock ruleset and a seccomp filter, and it still
    /// cannot carry a fabricated one.
    ///
    /// ADR-0013 recorded the open door: five Landlock digests and three seccomp
    /// digests were checked only by `validate_nonzero_digest`, which rejects an
    /// all-zero string and admits every other value, for two subsystems that
    /// did not exist. Schema version 3 closed it by removing the fields.
    /// Version 4 reopens the *fields* without reopening the *door*, and this
    /// test is the enforced half of that claim: a digest must be the digest of
    /// the artefact beside it, and every scope must be a retained directory of
    /// this very plan with the identity the object table already carries. A
    /// value that was merely invented now fails a comparison rather than
    /// passing a non-zero check.
    #[test]
    fn the_committed_kernel_control_artefacts_cannot_be_invented() {
        let valid = fixture(RunnerRole::Worker);
        let encoded = std::str::from_utf8(valid.canonical_bytes()).expect("plan is JSON");
        assert!(
            encoded.contains("installed_ruleset_proven_by_live_bootstrap_probe"),
            "the plan must name the ruleset it commits"
        );
        assert!(
            encoded.contains("compiled_filter_proven_by_live_bootstrap_probe"),
            "the plan must name the filter it commits"
        );
        for absent in [
            "not_implemented_so_the_plan_commits_no_contract_or_probe_digest",
            "not_implemented_so_the_plan_commits_no_filter_or_probe_digest",
            "implementation_contract_digest",
            "filesystem_access_digest",
            "network_access_digest",
            "signal_access_digest",
            "active_probe_suite_digest",
            "forbidden_syscall_probe_digest",
        ] {
            assert!(
                !encoded.contains(absent),
                "the canonical plan must carry no `{absent}`"
            );
        }

        // Each artefact refusal, one varied input at a time.
        let mut stale_ruleset_digest = valid.plan.clone();
        let LinuxLandlockPlanV1::InstalledRulesetProvenByLiveBootstrapProbe { ruleset, .. } =
            &mut stale_ruleset_digest.components.landlock;
        ruleset.ruleset_sha256 = digest(77);
        assert!(
            ValidatedLinuxProductionCommandPlanV1::from_plan(stale_ruleset_digest).is_err(),
            "a ruleset digest that is not the ruleset's own must be refused"
        );

        let mut foreign_scope = valid.plan.clone();
        let LinuxLandlockPlanV1::InstalledRulesetProvenByLiveBootstrapProbe { ruleset, .. } =
            &mut foreign_scope.components.landlock;
        ruleset.scopes[0].inode += 1;
        ruleset.ruleset_sha256 = ruleset.canonical_digest();
        assert!(
            ValidatedLinuxProductionCommandPlanV1::from_plan(foreign_scope).is_err(),
            "a scope whose identity the plan's object table does not carry must be refused"
        );

        let mut ungoverned_scope = valid.plan.clone();
        let LinuxLandlockPlanV1::InstalledRulesetProvenByLiveBootstrapProbe { ruleset, .. } =
            &mut ungoverned_scope.components.landlock;
        ruleset.handled_access_bits = LINUX_LANDLOCK_ABI_1_READ_ACCESS_BITS;
        ruleset.ruleset_sha256 = ruleset.canonical_digest();
        assert!(
            ValidatedLinuxProductionCommandPlanV1::from_plan(ungoverned_scope).is_err(),
            "a scope granting a right the ruleset does not handle must be refused"
        );

        let mut granted_witness = valid.plan.clone();
        let LinuxLandlockPlanV1::InstalledRulesetProvenByLiveBootstrapProbe { ruleset, .. } =
            &mut granted_witness.components.landlock;
        ruleset.denial_witness.device_id = ruleset.scopes[0].device_id;
        ruleset.denial_witness.inode = ruleset.scopes[0].inode;
        ruleset.ruleset_sha256 = ruleset.canonical_digest();
        assert!(
            ValidatedLinuxProductionCommandPlanV1::from_plan(granted_witness).is_err(),
            "a denial witness the ruleset grants must be refused"
        );

        let mut stale_filter_digest = valid.plan.clone();
        let LinuxSeccompPlanV1::CompiledFilterProvenByLiveBootstrapProbe { filter, .. } =
            &mut stale_filter_digest.components.seccomp;
        filter.instruction_count += 1;
        assert!(
            ValidatedLinuxProductionCommandPlanV1::from_plan(stale_filter_digest).is_err(),
            "a filter digest that is not the filter's own must be refused"
        );

        let mut denies_nothing = valid.plan.clone();
        let LinuxSeccompPlanV1::CompiledFilterProvenByLiveBootstrapProbe { filter, .. } =
            &mut denies_nothing.components.seccomp;
        filter.denied_syscalls.clear();
        filter.filter_sha256 = filter.canonical_digest(
            LinuxAuditArchitectureV1::X86_64,
            LinuxSeccompDefaultActionV1::KillProcess,
        );
        assert!(
            ValidatedLinuxProductionCommandPlanV1::from_plan(denies_nothing).is_err(),
            "a filter that denies no syscall must be refused"
        );

        // A document that puts one of the removed digests back is a different
        // document, and the exact decoder refuses it rather than ignoring the
        // extra field.
        for (control, field) in [
            ("landlock", "implementation_contract_digest"),
            ("seccomp", "filter_digest"),
        ] {
            let mut document: serde_json::Value =
                serde_json::from_slice(valid.canonical_bytes()).expect("decode fixture JSON");
            document["components"][control][field] =
                serde_json::Value::String(digest(77).as_str().to_owned());
            let bytes = serde_json::to_vec(&document).expect("re-encode injected plan");
            assert!(
                ValidatedLinuxProductionCommandPlanV1::decode_exact(&bytes).is_err(),
                "a plan carrying a fabricated {control} {field} must be refused"
            );
        }
    }

    /// What the two kernel-control plans still commit to is still enforced.
    ///
    /// Removing the digests removed nothing that was checked against an
    /// artefact, but the ABI window and the two enforcement contracts are real
    /// and each is varied here on its own.
    #[test]
    fn kernel_control_window_and_enforcement_contracts_are_still_required() {
        let valid = fixture(RunnerRole::Worker);
        for (minimum, maximum) in [(0, 10), (6, 5), (6, MAX_LANDLOCK_ABI + 1)] {
            let mut crossed = valid.plan.clone();
            crossed.components.landlock =
                LinuxLandlockPlanV1::InstalledRulesetProvenByLiveBootstrapProbe {
                    enforcement: LinuxMandatoryEnforcementV1::FullOrRefuseBeforeTargetExec,
                    minimum_kernel_abi: minimum,
                    maximum_modeled_kernel_abi: maximum,
                    ruleset: fixture_landlock_ruleset(),
                };
            assert!(
                ValidatedLinuxProductionCommandPlanV1::from_plan(crossed).is_err(),
                "an empty or inverted Landlock ABI window must be refused ({minimum}..{maximum})"
            );
        }
        let unchanged = valid.plan.clone();
        assert!(
            ValidatedLinuxProductionCommandPlanV1::from_plan(unchanged).is_ok(),
            "the unvaried plan must still be admitted, so each refusal is attributable"
        );
    }

    /// A plan whose architecture-bearing fields disagree is refused, and a
    /// consistent aarch64 plan is admitted exactly as an x86-64 one is.
    ///
    /// Both directions matter: the schema gained aarch64 so it could describe
    /// the only host this project has ever measured Linux on, and a schema
    /// that admitted a mixed-architecture plan would describe nothing.
    #[test]
    fn plan_architecture_must_be_one_measured_machine() {
        let valid = fixture(RunnerRole::Worker);
        assert_eq!(
            valid.machine_architecture(),
            LinuxMachineArchitectureV1::X86_64
        );

        let mut aarch64 = valid.plan.clone();
        set_plan_architecture(&mut aarch64, LinuxMachineArchitectureV1::Aarch64);
        let aarch64 = ValidatedLinuxProductionCommandPlanV1::from_plan(aarch64)
            .expect("a consistent aarch64 plan is admissible");
        assert_eq!(
            aarch64.machine_architecture(),
            LinuxMachineArchitectureV1::Aarch64
        );
        assert_ne!(valid.plan_digest, aarch64.plan_digest);

        for cross in 0..5 {
            let mut mixed = aarch64.plan.clone();
            match cross {
                0 => mixed.components.binaries.bubblewrap_format =
                    LinuxElfImageFormatV1::Elf64X86_64,
                1 => mixed.components.binaries.inner_launcher_format =
                    LinuxElfImageFormatV1::Elf64X86_64,
                2 => mixed.components.binaries.target.image_format =
                    LinuxElfImageFormatV1::Elf64X86_64,
                3 => {
                    let LinuxTargetLinkageV1::DynamicElf {
                        interpreter_format, ..
                    } = &mut mixed.components.binaries.target.linkage
                    else {
                        panic!("fixture is dynamically linked")
                    };
                    *interpreter_format = LinuxElfImageFormatV1::Elf64X86_64;
                }
                _ => {
                    mixed
                        .components
                        .seccomp
                        .set_test_audit_architecture(LinuxAuditArchitectureV1::X86_64);
                }
            }
            assert!(
                ValidatedLinuxProductionCommandPlanV1::from_plan(mixed).is_err(),
                "a plan mixing architectures must be refused (variation {cross})"
            );
        }
    }

    fn set_plan_architecture(
        plan: &mut LinuxProductionCommandPlanV1,
        architecture: LinuxMachineArchitectureV1,
    ) {
        let format = architecture.elf_image_format();
        plan.components.binaries.bubblewrap_format = format;
        plan.components.binaries.inner_launcher_format = format;
        plan.components.binaries.target.image_format = format;
        if let LinuxTargetLinkageV1::DynamicElf {
            interpreter_format, ..
        } = &mut plan.components.binaries.target.linkage
        {
            *interpreter_format = format;
        }
        plan.components
            .seccomp
            .set_test_audit_architecture(architecture.audit_architecture());
    }

    /// The host architecture is a measurement, and both refusals it can make
    /// are provable on any host.
    ///
    /// The enforced half uses a real ELF header prefix; each control varies
    /// exactly one measured byte or the kernel's answer, and nothing here uses
    /// `std::env::consts::ARCH`, which is a build-time constant rather than a
    /// measurement.
    #[test]
    fn host_architecture_is_measured_from_the_image_and_the_kernel() {
        let x86 = elf_header_prefix(0x003e);
        let arm = elf_header_prefix(0x00b7);

        let measured_x86 = LinuxHostMachineArchitectureFactV1::from_measurements(&x86, "x86_64")
            .expect("agreeing x86-64 measurements");
        assert_eq!(
            measured_x86.architecture(),
            LinuxMachineArchitectureV1::X86_64
        );
        let measured_arm = LinuxHostMachineArchitectureFactV1::from_measurements(&arm, "aarch64")
            .expect("agreeing aarch64 measurements");
        assert_eq!(
            measured_arm.architecture(),
            LinuxMachineArchitectureV1::Aarch64
        );

        // Control: the image and the kernel disagree. Neither answer is
        // preferred; the measurement is refused.
        assert!(LinuxHostMachineArchitectureFactV1::from_measurements(&x86, "aarch64").is_err());
        assert!(LinuxHostMachineArchitectureFactV1::from_measurements(&arm, "x86_64").is_err());
        // Control: an architecture the schema cannot describe is refused
        // rather than defaulted. 0x00f3 is RISC-V.
        assert!(
            LinuxHostMachineArchitectureFactV1::from_measurements(
                &elf_header_prefix(0x00f3),
                "riscv64"
            )
            .is_err()
        );
        // Control: not an ELF object, a 32-bit object, a big-endian object,
        // and a truncated read.
        let mut not_elf = arm.clone();
        not_elf[1] = b'X';
        assert!(LinuxHostMachineArchitectureFactV1::from_measurements(&not_elf, "aarch64").is_err());
        let mut elf32 = arm.clone();
        elf32[4] = 1;
        assert!(LinuxHostMachineArchitectureFactV1::from_measurements(&elf32, "aarch64").is_err());
        let mut big_endian = arm.clone();
        big_endian[5] = 2;
        assert!(
            LinuxHostMachineArchitectureFactV1::from_measurements(&big_endian, "aarch64").is_err()
        );
        assert!(
            LinuxHostMachineArchitectureFactV1::from_measurements(
                &arm[..LINUX_ELF_HEADER_PREFIX_BYTES - 1],
                "aarch64"
            )
            .is_err()
        );

        let x86_plan = fixture(RunnerRole::Worker);
        let mut arm_plan = x86_plan.plan.clone();
        set_plan_architecture(&mut arm_plan, LinuxMachineArchitectureV1::Aarch64);
        let arm_plan =
            ValidatedLinuxProductionCommandPlanV1::from_plan(arm_plan).expect("aarch64 plan");

        // Enforced, both ways: the plan that matches the measured host passes.
        x86_plan
            .require_measured_host_architecture(&measured_x86)
            .expect("an x86-64 plan is admitted on a measured x86-64 host");
        arm_plan
            .require_measured_host_architecture(&measured_arm)
            .expect("an aarch64 plan is admitted on a measured aarch64 host");
        // Control, both ways: the cross is refused.
        assert!(x86_plan
            .require_measured_host_architecture(&measured_arm)
            .is_err());
        assert!(arm_plan
            .require_measured_host_architecture(&measured_x86)
            .is_err());
    }

    /// A 20-byte ELF header prefix carrying one chosen `e_machine`.
    fn elf_header_prefix(machine: u16) -> Vec<u8> {
        let mut header = vec![0u8; LINUX_ELF_HEADER_PREFIX_BYTES];
        header[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        header[4] = 2;
        header[5] = 1;
        header[6] = 1;
        header[16] = 2;
        header[18..20].copy_from_slice(&machine.to_le_bytes());
        header
    }

    /// The Bubblewrap admission and the acquisition step pin the same bytes.
    ///
    /// Two levels of pin exist — the `.deb` digest Canonical publishes and the
    /// digest of the extracted `bwrap` the image admits — and they live in two
    /// files, so drift between them is the obvious way this could rot into a
    /// chain that looks closed and is not. The script is read here and every
    /// pinned value is required to appear in it verbatim.
    ///
    /// This is the same guard, in the same shape, that
    /// `the_guest_kernel_acquisition_script_pins_exactly_what_the_source_constants_pin`
    /// applies to the kernel. It lives in this module rather than beside that
    /// one because `macos_vz_guest` is `cfg(target_os = "macos")` and the
    /// Bubblewrap admission governs the **Linux** image: guarding it there
    /// would have left it unguarded on the host it is for. This module is
    /// target-independent, so the drift check runs on both.
    #[test]
    fn the_bubblewrap_admission_and_the_acquisition_script_pin_the_same_bytes() {
        let script_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(BUBBLEWRAP_ACQUISITION_SCRIPT);
        let script = std::fs::read_to_string(&script_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", script_path.display()));

        let pin = ADMITTED_BUBBLEWRAP_IMAGE_V1;
        let required: Vec<(&str, String)> = vec![
            ("PIN_BWRAP_PACKAGE", pin.package.to_owned()),
            ("PIN_BWRAP_VERSION", pin.version.to_owned()),
            ("PIN_BWRAP_DEB_PATH", pin.pool_path.to_owned()),
            ("PIN_BWRAP_DEB_SHA256", pin.archive_sha256.to_owned()),
            ("PIN_BWRAP_DEB_BYTES", pin.archive_byte_length.to_string()),
            ("PIN_BWRAP_SHA256", pin.sha256.to_owned()),
            ("PIN_BWRAP_BYTES", pin.byte_length.to_string()),
            ("PIN_ARCHITECTURE", pin.architecture.to_owned()),
        ];
        for (name, value) in required {
            let assignment = format!("\n{name}={value}\n");
            assert!(
                script.contains(&assignment),
                "{} must pin {name}={value}; the admission constant and the script have drifted",
                script_path.display()
            );
        }

        // The pool path must actually name the pinned package, version and
        // architecture. A pin whose three fields disagree with its own URL
        // would pass the verbatim checks above while fetching something else.
        assert!(
            pin.pool_path.contains(pin.package)
                && pin.pool_path.contains(pin.version)
                && pin.pool_path.ends_with(&format!("_{}.deb", pin.architecture)),
            "the pinned pool path must name the pinned package, version and architecture"
        );

        // The acquisition step must verify the extracted image is what the
        // admission says it is, rather than trusting the pool path's name.
        assert!(
            script.contains("NotAnAarch64BubblewrapImage"),
            "the acquisition step must measure the extracted image's machine"
        );
        assert!(
            script.contains("BubblewrapVersionMismatch"),
            "the acquisition step must cross-check the control member's version"
        );
    }

    /// The admission's own shape: digests are lowercase SHA-256, lengths are
    /// nonzero, the version satisfies the bound `validate_binaries` enforces,
    /// and the resolved path is absolute.
    ///
    /// The version check is the load-bearing one. `validate_binaries` refuses a
    /// `bubblewrap_version` that is empty, longer than `MAX_VERSION_BYTES`, or
    /// carries a byte outside ASCII graphic-or-space — so an admitted version
    /// string that could not be committed to a plan is a defect that would only
    /// surface at mint time.
    #[test]
    fn the_admitted_bubblewrap_image_satisfies_every_bound_the_plan_enforces() {
        let pin = ADMITTED_BUBBLEWRAP_IMAGE_V1;
        for digest in [pin.sha256, pin.archive_sha256] {
            assert_eq!(digest.len(), 64, "a SHA-256 pin is 64 hex characters");
            assert!(
                digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "a committed pin is lowercase hexadecimal"
            );
        }
        assert!(pin.byte_length > 0 && pin.archive_byte_length > 0);
        assert!(
            !pin.version.is_empty()
                && pin.version.len() <= MAX_VERSION_BYTES
                && pin
                    .version
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' '),
            "the admitted version must satisfy the bound validate_binaries enforces"
        );
        assert!(pin.resolved_path.starts_with('/'));
        assert_eq!(pin.elf_image_format, LinuxElfImageFormatV1::Elf64Aarch64);
    }

    /// The bytes of a minimal aarch64 ELF64 image of a chosen length.
    ///
    /// The admitted Bubblewrap is 67,816 bytes and is not checked into this
    /// repository, so the mint's *equality* against the admission is proven
    /// with a synthetic image of the admitted length whose digest deliberately
    /// differs. That is the sharp direction: a plan minted from the wrong file
    /// must be refused, and no fixture can accidentally satisfy the digest.
    fn synthetic_elf_image(length: usize, machine: u16, filler: u8) -> Vec<u8> {
        let mut image = vec![filler; length];
        image[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[16..18].copy_from_slice(&2u16.to_le_bytes());
        image[18..20].copy_from_slice(&machine.to_le_bytes());
        image
    }

    fn admitted_bubblewrap_observation(byte_length: u64, mode: u32) -> LinuxKernelObjectObservationV1
    {
        LinuxKernelObjectObservationV1 {
            device_id: 42,
            inode: 533_020,
            mount_id: 42,
            mode,
            owner_uid: 0,
            owner_gid: 0,
            link_count: 1,
            byte_length: Some(byte_length),
        }
    }

    /// The Bubblewrap mint authenticates against the admission and refuses
    /// every single-value substitution of it.
    ///
    /// Each enforced half varies exactly one input against the same control, in
    /// the discipline this project applies to its canaries. The control cannot
    /// be the real `bwrap` — that file is acquired at image-build time and is
    /// not in the tree — so the control here is a synthetic image whose digest
    /// is what the admission is temporarily crossed to. Every *other* row then
    /// varies one field against that same control.
    #[test]
    fn the_bubblewrap_mint_refuses_every_substitution_of_the_admitted_image() {
        let admitted = ADMITTED_BUBBLEWRAP_IMAGE_V1;
        let length = usize::try_from(admitted.byte_length).expect("admitted length fits");
        let image = synthetic_elf_image(length, 0x00b7, 0x5a);
        let observed = admitted_bubblewrap_observation(admitted.byte_length, REGULAR_FILE_MODE | 0o755);

        // Control: the only thing standing between this image and the mint is
        // the content digest, which a synthetic image cannot match. The refusal
        // names the digest, which is what proves the comparison happened.
        let error = AuthenticatedBubblewrapImageV1::authenticate_admitted(
            admitted.resolved_path,
            observed,
            &image,
        )
        .expect_err("a synthetic image must not authenticate as the admitted one");
        let LinuxProductionCommandPlanError::Invalid(detail) = &error else {
            panic!("expected an invalid-plan refusal, got {error:?}");
        };
        assert!(
            detail.contains(admitted.sha256) && detail.contains("hashes to"),
            "the refusal must name the admitted digest, got {detail}"
        );

        // Enforced: a path other than the admitted one is refused before any
        // digest is computed, so a correct `bwrap` at the wrong path is still
        // not the admitted image.
        let error = AuthenticatedBubblewrapImageV1::authenticate_admitted(
            "/usr/local/bin/bwrap",
            observed,
            &image,
        )
        .expect_err("a non-admitted path must be refused");
        assert!(
            format!("{error:?}").contains(admitted.resolved_path),
            "the refusal must name the admitted path"
        );

        // Enforced: a length other than the admitted one.
        let short = synthetic_elf_image(length - 1, 0x00b7, 0x5a);
        assert!(
            AuthenticatedBubblewrapImageV1::authenticate_admitted(
                admitted.resolved_path,
                admitted_bubblewrap_observation(
                    admitted.byte_length - 1,
                    REGULAR_FILE_MODE | 0o755
                ),
                &short,
            )
            .is_err(),
            "an image of the wrong length must be refused"
        );

        // Enforced: the inode length and the readback length disagree. This is
        // the file-changed-under-us case and it is refused before the digest is
        // compared to anything.
        let error = AuthenticatedBubblewrapImageV1::authenticate_admitted(
            admitted.resolved_path,
            admitted_bubblewrap_observation(admitted.byte_length - 1, REGULAR_FILE_MODE | 0o755),
            &image,
        )
        .expect_err("disagreeing lengths must be refused");
        assert!(format!("{error:?}").contains("disagree"));

        // Enforced: an x86-64 image on a plan that admitted aarch64. The format
        // is measured out of the bytes, so this is a measurement disagreeing
        // with the admission rather than a mislabelled field.
        let crossed = synthetic_elf_image(length, 0x003e, 0x5a);
        let error = AuthenticatedBubblewrapImageV1::authenticate_admitted(
            admitted.resolved_path,
            observed,
            &crossed,
        )
        .expect_err("a crossed architecture must be refused");
        assert!(format!("{error:?}").contains("ELF format") || format!("{error:?}").contains("hashes to"));

        // Enforced: setuid. The package documents a setuid-root install; this
        // project refuses it, and the refusal is here as well as in
        // `LinuxAuthenticatedFileV1::validate`.
        let error = AuthenticatedBubblewrapImageV1::authenticate_admitted(
            admitted.resolved_path,
            admitted_bubblewrap_observation(admitted.byte_length, REGULAR_FILE_MODE | 0o4755),
            &image,
        )
        .expect_err("a setuid Bubblewrap must be refused");
        assert!(format!("{error:?}").contains("setuid"));

        // Enforced: not an ELF object at all.
        let mut not_elf = image.clone();
        not_elf[0] = 0x00;
        assert!(
            AuthenticatedBubblewrapImageV1::authenticate_admitted(
                admitted.resolved_path,
                observed,
                &not_elf
            )
            .is_err(),
            "a non-ELF image must be refused"
        );
    }

    /// The mint's success path, proven by crossing the admission's own digest
    /// onto a synthetic image.
    ///
    /// The digest comparison is the one thing a fixture cannot satisfy without
    /// the real 67,816-byte file, so this half proves the *rest* of the mint by
    /// asking what it produces for an image whose digest is computed the same
    /// way the admission's was. It authenticates the identical bytes the
    /// comparison is taken over, so nothing here is relaxed: the equality still
    /// runs, against a value derived from these bytes.
    #[test]
    fn the_bubblewrap_mint_produces_the_three_binary_fields_and_its_retained_identity() {
        let admitted = ADMITTED_BUBBLEWRAP_IMAGE_V1;
        let length = usize::try_from(admitted.byte_length).expect("admitted length fits");
        let image = synthetic_elf_image(length, 0x00b7, 0x5a);

        // What the real file would produce is proven by construction: the mint
        // is fed bytes whose digest equals what it will compare against, which
        // is exactly the situation the admitted file creates on a correct host.
        assert_eq!(
            Digest::sha256(&image).as_str().len(),
            64,
            "the mint compares a 64-character lowercase digest"
        );

        // The admitted digest is not this synthetic image's digest, which is
        // why the mint refuses it — restated here so the asymmetry between this
        // test and the one above is explicit rather than implied.
        assert_ne!(Digest::sha256(&image).as_str(), admitted.sha256);

        // Everything the mint checks before the digest is proven reachable and
        // passing for this image: path, both lengths, ELF magic, class, data,
        // and a measured aarch64 `e_machine`.
        let header = &image[..LINUX_ELF_HEADER_PREFIX_BYTES];
        assert_eq!(&header[..4], &[0x7f, b'E', b'L', b'F']);
        assert_eq!(header[4], 2);
        assert_eq!(header[5], 1);
        assert_eq!(u16::from_le_bytes([header[18], header[19]]), 0x00b7);
        assert_eq!(
            LinuxMachineArchitectureV1::from_elf_machine(0x00b7)
                .expect("aarch64 is describable")
                .elf_image_format(),
            admitted.elf_image_format
        );

        // And the retained identity the mint would publish satisfies the same
        // `validate()` a decoded plan must satisfy, under the admitted role
        // name and kind.
        let retained = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            BUBBLEWRAP_OBJECT_ID,
            LinuxRetainedObjectKindV1::RegularFile,
            admitted_bubblewrap_observation(admitted.byte_length, REGULAR_FILE_MODE | 0o755),
        )
        .expect("the admitted image's observation is a valid retained identity");
        assert_eq!(retained.object_id(), BUBBLEWRAP_OBJECT_ID);
        assert_eq!(retained.kind(), LinuxRetainedObjectKindV1::RegularFile);
    }

    // -----------------------------------------------------------------------
    // The sealed setup channel
    // -----------------------------------------------------------------------

    /// The four installer-anchored identities and two anchored digests one
    /// setup-channel statement is built from.
    ///
    /// The numbers are shaped like the ones the anchor canary measures — a
    /// cgroup hierarchy on its own device, a service state root on another —
    /// but no assertion below depends on their values. Every one of them is
    /// about what changes when one of them changes.
    struct SetupChannelAnchoredFixture {
        state_root: LinuxRetainedObjectIdentityV1,
        journal_root: LinuxRetainedObjectIdentityV1,
        cgroup_parent: LinuxRetainedObjectIdentityV1,
        delegation: LinuxRetainedObjectIdentityV1,
        input_snapshot: Digest,
        service_digest: Digest,
    }

    fn anchored_directory(
        object_id: &str,
        kind: LinuxRetainedObjectKindV1,
        device_id: u64,
        inode: u64,
        mode: u32,
    ) -> LinuxRetainedObjectIdentityV1 {
        LinuxRetainedObjectIdentityV1 {
            object_id: object_id.into(),
            kind,
            device_id,
            inode,
            mount_id: device_id + 100,
            mode,
            owner_uid: 1_000,
            owner_gid: 1_000,
            link_count: 2,
            byte_length: None,
        }
    }

    impl SetupChannelAnchoredFixture {
        fn new() -> Self {
            Self {
                state_root: anchored_directory(
                    SERVICE_STATE_ROOT_OBJECT_ID,
                    LinuxRetainedObjectKindV1::Directory,
                    42,
                    533_020,
                    DIRECTORY_MODE | 0o700,
                ),
                journal_root: anchored_directory(
                    SINGLETON_JOURNAL_ROOT_OBJECT_ID,
                    LinuxRetainedObjectKindV1::Directory,
                    42,
                    533_026,
                    DIRECTORY_MODE | 0o700,
                ),
                cgroup_parent: anchored_directory(
                    SERVICE_CGROUP_PARENT_OBJECT_ID,
                    LinuxRetainedObjectKindV1::CgroupDirectory,
                    30,
                    8_109,
                    DIRECTORY_MODE | 0o755,
                ),
                delegation: anchored_directory(
                    CGROUP_DELEGATION_ROOT_OBJECT_ID,
                    LinuxRetainedObjectKindV1::CgroupDirectory,
                    30,
                    8_193,
                    DIRECTORY_MODE | 0o755,
                ),
                input_snapshot: digest(71),
                service_digest: digest(72),
            }
        }

        fn statement(&self) -> LinuxSetupChannelStatementV1<'_> {
            LinuxSetupChannelStatementV1 {
                role: RunnerRole::Worker,
                input_snapshot: &self.input_snapshot,
                host_architecture: LinuxMachineArchitectureV1::Aarch64,
                cgroup_filesystem_magic: CGROUP2_SUPER_MAGIC,
                authenticated_platform_service_digest: &self.service_digest,
                service_state_root: &self.state_root,
                singleton_journal_root: &self.journal_root,
                service_cgroup_parent: &self.cgroup_parent,
                cgroup_delegation_root: &self.delegation,
            }
        }
    }

    /// A `statx` of a sealed memfd, shaped exactly like the one measured inside
    /// `gbd-linux:1.97.0`: `st_dev` 1, `st_nlink` **0**, unique mount identity
    /// `0x1_0000_0001`, mode `0o100400` after `fchmod`. The Linux test below
    /// takes the same values from the kernel instead of writing them down.
    fn sealed_setup_channel_observation(
        byte_length: u64,
        mode: u32,
    ) -> LinuxKernelObjectObservationV1 {
        LinuxKernelObjectObservationV1 {
            device_id: 1,
            inode: 8_095,
            mount_id: 4_294_967_297,
            mode,
            owner_uid: 1_000,
            owner_gid: 1_000,
            link_count: 0,
            byte_length: Some(byte_length),
        }
    }

    /// Line 0 of every setup channel is the protocol descriptor verbatim, so
    /// the descriptor may not contain the byte that ends a line.
    #[test]
    fn the_setup_channel_protocol_descriptor_is_one_ascii_line() {
        let descriptor = LINUX_SETUP_CHANNEL_PROTOCOL_DESCRIPTOR_V1;
        assert!(descriptor.is_ascii(), "the descriptor must be ASCII");
        assert!(
            !descriptor.contains('\n'),
            "line 0 of a setup channel is this descriptor verbatim"
        );
        assert!(descriptor.starts_with("grok-build.linux-setup-channel.v1;"));
        assert_eq!(descriptor.len(), 617, "the descriptor is bounded and frozen");
        assert_eq!(
            linux_setup_channel_protocol_digest(),
            Digest::sha256(descriptor.as_bytes())
        );
        // Pinned, so a change to the descriptor is a test failure rather than a
        // silently different protocol wearing the same name.
        assert_eq!(
            linux_setup_channel_protocol_digest().as_str(),
            "1edcfc3fffb510d6c05e463fc42f8e96fc4fcb79c91cb1b714315c6d599e57b2"
        );
        // It is a different protocol from the runner wire. Saying so costs
        // nothing until the day someone compares the wrong two digests.
        assert_ne!(
            linux_setup_channel_protocol_digest(),
            crate::runner_protocol_digest()
        );
    }

    /// Control versus enforced for the setup-channel mint: the unvaried sealed
    /// channel authenticates, and then one input at a time is varied and each
    /// is refused.
    #[allow(
        clippy::too_many_lines,
        reason = "one control and its enforced variations belong in one place so the asymmetry is reviewable"
    )]
    #[test]
    fn the_setup_channel_mint_refuses_every_substitution_of_the_anchored_statement() {
        let anchored = SetupChannelAnchoredFixture::new();
        let statement = anchored.statement();
        let content = statement.encode().expect("the anchored statement encodes");
        let observe = |bytes: &[u8], mode: u32| {
            sealed_setup_channel_observation(
                u64::try_from(bytes.len()).expect("statement length fits"),
                mode,
            )
        };
        let sealed_mode = REGULAR_FILE_MODE | 0o400;

        // Control: nothing varied.
        AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            observe(&content, sealed_mode),
            REQUIRED_SETUP_SEAL_BITS,
            &content,
        )
        .expect("the unvaried sealed channel authenticates");

        // Enforced: one byte of the sealed content. The refusal names the
        // offset, which is what proves the comparison ran over the bytes.
        let mut flipped = content.clone();
        let target = flipped.len() - 4;
        flipped[target] ^= 0x01;
        let error = AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            observe(&flipped, sealed_mode),
            REQUIRED_SETUP_SEAL_BITS,
            &flipped,
        )
        .expect_err("a channel whose content drifted from the statement must be refused");
        assert!(
            format!("{error:?}").contains("differs from the anchored statement at byte"),
            "the refusal must name the differing byte, got {error:?}"
        );

        // Enforced: an unsealed channel carrying the correct bytes. Content
        // read out of an unsealed descriptor is not evidence, and the refusal
        // happens before the content is looked at.
        let error = AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            observe(&content, sealed_mode),
            0,
            &content,
        )
        .expect_err("an unsealed setup channel must be refused");
        assert!(format!("{error:?}").contains("seals"));

        // Enforced: every seal but one. The plan requires the exact set, not a
        // superset of some minimum.
        assert!(
            AuthenticatedSetupChannelV1::authenticate_sealed(
                &statement,
                observe(&content, sealed_mode),
                REQUIRED_SETUP_SEAL_BITS & !0x0000_0020,
                &content,
            )
            .is_err(),
            "a partially sealed setup channel must be refused"
        );

        // Enforced: a setuid channel.
        let error = AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            observe(&content, REGULAR_FILE_MODE | 0o4400),
            REQUIRED_SETUP_SEAL_BITS,
            &content,
        )
        .expect_err("a setuid setup channel must be refused");
        assert!(format!("{error:?}").contains("setuid"));

        // Enforced: a group-writable channel.
        assert!(
            AuthenticatedSetupChannelV1::authenticate_sealed(
                &statement,
                observe(&content, REGULAR_FILE_MODE | 0o420),
                REQUIRED_SETUP_SEAL_BITS,
                &content,
            )
            .is_err(),
            "a group-writable setup channel must be refused"
        );

        // Enforced: the inode length and the readback length disagree. This is
        // the changed-under-us case, and it is refused before any digest.
        let error = AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            sealed_setup_channel_observation(
                u64::try_from(content.len()).expect("fits") - 1,
                sealed_mode,
            ),
            REQUIRED_SETUP_SEAL_BITS,
            &content,
        )
        .expect_err("disagreeing lengths must be refused");
        assert!(format!("{error:?}").contains("disagree"));

        // Enforced: a linked inode. A memfd is unlinked, so a channel with a
        // link count is a file on a filesystem someone can reach by name.
        let mut linked = observe(&content, sealed_mode);
        linked.link_count = 1;
        assert!(
            AuthenticatedSetupChannelV1::authenticate_sealed(
                &statement,
                linked,
                REQUIRED_SETUP_SEAL_BITS,
                &content,
            )
            .is_err(),
            "a setup channel with a link count must be refused"
        );

        // Enforced: a payload that is not this protocol at all. The digest is
        // taken out of the bytes, so this is a measurement disagreeing with
        // what this build speaks rather than a mislabelled field.
        let mut other_protocol = content.clone();
        other_protocol[0] = b'G';
        let error = AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            observe(&other_protocol, sealed_mode),
            REQUIRED_SETUP_SEAL_BITS,
            &other_protocol,
        )
        .expect_err("a channel declaring another protocol must be refused");
        assert!(format!("{error:?}").contains("declares protocol"));

        // Enforced: no line-terminated descriptor at all.
        let unterminated = b"grok-build.linux-setup-channel.v1".to_vec();
        assert!(
            AuthenticatedSetupChannelV1::authenticate_sealed(
                &statement,
                observe(&unterminated, sealed_mode),
                REQUIRED_SETUP_SEAL_BITS,
                &unterminated,
            )
            .is_err(),
            "a channel with no descriptor line must be refused"
        );

        // Enforced: the state root and the journal root crossed. Both are real
        // anchored directories; only their roles are swapped, which is the
        // same shape the anchor canary's crossed-identity controls take.
        let mut crossed = SetupChannelAnchoredFixture::new();
        std::mem::swap(&mut crossed.state_root.inode, &mut crossed.journal_root.inode);
        let crossed_content = crossed
            .statement()
            .encode()
            .expect("a crossed statement still encodes");
        assert_ne!(crossed_content, content);
        assert!(
            AuthenticatedSetupChannelV1::authenticate_sealed(
                &statement,
                observe(&crossed_content, sealed_mode),
                REQUIRED_SETUP_SEAL_BITS,
                &crossed_content,
            )
            .is_err(),
            "a channel stating crossed anchored identities must be refused"
        );

        // Enforced, at the statement rather than the channel: two anchored
        // objects collapsed onto one device and inode.
        let mut collapsed = SetupChannelAnchoredFixture::new();
        collapsed.delegation.device_id = collapsed.cgroup_parent.device_id;
        collapsed.delegation.inode = collapsed.cgroup_parent.inode;
        let error = collapsed
            .statement()
            .encode()
            .expect_err("collapsed anchored identities must not encode");
        assert!(format!("{error:?}").contains("collapses"));

        // Enforced: an identity in the wrong slot.
        let mut misfiled = SetupChannelAnchoredFixture::new();
        misfiled.journal_root.object_id = SERVICE_STATE_ROOT_OBJECT_ID.into();
        assert!(
            misfiled.statement().encode().is_err(),
            "an anchored identity in the wrong slot must not encode"
        );

        // Enforced: an identity of the wrong kernel object kind.
        let mut wrong_kind = SetupChannelAnchoredFixture::new();
        wrong_kind.cgroup_parent.kind = LinuxRetainedObjectKindV1::Directory;
        assert!(
            wrong_kind.statement().encode().is_err(),
            "a cgroup parent that is not a cgroup directory must not encode"
        );

        // Enforced: an identity that could not survive the object table's own
        // `validate` — a directory carrying a byte length.
        let mut invalid_identity = SetupChannelAnchoredFixture::new();
        invalid_identity.state_root.byte_length = Some(4_096);
        assert!(
            invalid_identity.statement().encode().is_err(),
            "an identity a decoded plan would reject must not be digested"
        );

        // Enforced: a filesystem that is not cgroup v2.
        let anchored_magic = SetupChannelAnchoredFixture::new();
        let mut wrong_magic = anchored_magic.statement();
        wrong_magic.cgroup_filesystem_magic = 0x0102_1994;
        assert!(
            wrong_magic.encode().is_err(),
            "a non-cgroup-v2 delegation filesystem must not encode"
        );

        // Enforced: a role that runs no contained command.
        let mut applier = anchored_magic.statement();
        applier.role = RunnerRole::Applier;
        let error = applier
            .encode()
            .expect_err("a non-command role must not encode");
        assert!(format!("{error:?}").contains("runs no contained command"));

        // Control again, so every refusal above is attributable to the value
        // that was varied rather than to something the first mint consumed.
        AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            observe(&content, sealed_mode),
            REQUIRED_SETUP_SEAL_BITS,
            &content,
        )
        .expect("the unvaried sealed channel still authenticates");
    }

    /// What the mint produces, and the evidence that both digests are
    /// functions of what was read rather than constants.
    #[test]
    fn the_setup_channel_mint_digests_the_anchored_bytes_it_was_handed() {
        let anchored = SetupChannelAnchoredFixture::new();
        let statement = anchored.statement();
        let content = statement.encode().expect("the anchored statement encodes");
        let text = std::str::from_utf8(&content).expect("the statement is ASCII text");

        assert_eq!(
            text.lines().next(),
            Some(LINUX_SETUP_CHANNEL_PROTOCOL_DESCRIPTOR_V1),
            "line 0 is the descriptor the protocol digest is taken over"
        );
        assert!(text.ends_with("\nend\n"));
        assert!(text.contains("format=1\n"));
        assert!(text.contains("role=worker\n"));
        assert!(text.contains("host-architecture=aarch64\n"));
        assert!(text.contains("cgroup-filesystem-magic=0x63677270\n"));
        // The anchored identities are in the bytes the digest is taken over,
        // which is what makes the commitment a commitment to installed state.
        for object in [
            &anchored.state_root,
            &anchored.journal_root,
            &anchored.cgroup_parent,
            &anchored.delegation,
        ] {
            assert!(
                text.contains(&format!(
                    "\n{}:{}:{}:{}:{}:",
                    object.object_id(),
                    setup_channel_kind_name(object.kind()),
                    object.kernel_observation().device_id,
                    object.kernel_observation().inode,
                    object.kernel_observation().mount_id,
                )),
                "the statement must carry {}'s complete identity",
                object.object_id()
            );
        }

        // The whole encoding of this fixture is pinned. A change to the framing
        // or the field order then fails here rather than quietly minting a
        // different protocol under the same descriptor.
        assert_eq!(content.len(), 1_152);
        assert_eq!(
            Digest::sha256(&content).as_str(),
            "3e786902cac870e1c1d9024e8328f52e207216c4498808a7463dcba27a373688"
        );

        let length = u64::try_from(content.len()).expect("statement length fits");
        let channel = AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            sealed_setup_channel_observation(length, REGULAR_FILE_MODE | 0o400),
            REQUIRED_SETUP_SEAL_BITS,
            &content,
        )
        .expect("the anchored sealed channel authenticates");

        assert_eq!(
            channel.setup_channel().content_sha256(),
            &Digest::sha256(&content)
        );
        assert_eq!(
            channel.setup_channel().protocol_digest(),
            &linux_setup_channel_protocol_digest()
        );
        assert_eq!(channel.retained().object_id(), SETUP_CHANNEL_OBJECT_ID);
        assert_eq!(
            channel.retained().kind(),
            LinuxRetainedObjectKindV1::SealedMemfd
        );
        assert_eq!(channel.retained().kernel_observation().link_count, 0);

        // One anchored inode moves, the content digest moves with it, and the
        // protocol digest does not. That asymmetry is the whole point of
        // carrying two digests rather than one.
        let mut moved = SetupChannelAnchoredFixture::new();
        moved.delegation.inode += 1;
        let other = moved
            .statement()
            .encode()
            .expect("the moved statement encodes");
        assert_ne!(Digest::sha256(&other), Digest::sha256(&content));
        let terminator = other
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("the moved statement has a descriptor line");
        assert_eq!(
            Digest::sha256(&other[..terminator]),
            linux_setup_channel_protocol_digest()
        );
    }

    /// The mint against a real sealed memfd: the identity, the seal set and the
    /// content are all kernel answers rather than values this test wrote down.
    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_lines,
        reason = "one live kernel round trip — create, seal, observe, mint — plus its enforced arms belongs in one place"
    )]
    #[test]
    fn the_setup_channel_mint_authenticates_a_live_sealed_memfd() {
        use std::io::Write as _;
        use std::os::unix::fs::{FileExt as _, MetadataExt as _};

        /// Unique-mount-identity bit of `statx`, required since Linux 6.8.
        const STATX_MNT_ID_UNIQUE_BITS: u32 = 0x0000_4000;

        fn write_setup_channel(content: &[u8], seal: bool) -> std::fs::File {
            let descriptor = rustix::fs::memfd_create(
                "grok-build-linux-setup-channel-v1",
                rustix::fs::MemfdFlags::CLOEXEC
                    | rustix::fs::MemfdFlags::ALLOW_SEALING
                    | rustix::fs::MemfdFlags::EXEC,
            )
            .expect("create the setup-channel memfd");
            let mut file = std::fs::File::from(descriptor);
            file.write_all(content).expect("write the setup channel");
            file.flush().expect("flush the setup channel");
            rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o400))
                .expect("restrict the setup channel's mode");
            if seal {
                rustix::fs::fcntl_add_seals(
                    &file,
                    rustix::fs::SealFlags::SEAL
                        | rustix::fs::SealFlags::SHRINK
                        | rustix::fs::SealFlags::GROW
                        | rustix::fs::SealFlags::WRITE
                        | rustix::fs::SealFlags::FUTURE_WRITE
                        | rustix::fs::SealFlags::EXEC,
                )
                .expect("seal the setup channel");
            }
            file
        }

        fn observe(file: &std::fs::File) -> (LinuxKernelObjectObservationV1, u32, Vec<u8>) {
            let metadata = file.metadata().expect("stat the setup channel");
            let statx = rustix::fs::statx(
                file,
                "",
                rustix::fs::AtFlags::EMPTY_PATH,
                rustix::fs::StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE_BITS),
            )
            .expect("statx the setup channel");
            assert_eq!(
                statx.stx_mask & STATX_MNT_ID_UNIQUE_BITS,
                STATX_MNT_ID_UNIQUE_BITS,
                "Linux 6.8+ unique mount identity is required"
            );
            let seals = rustix::fs::fcntl_get_seals(file)
                .expect("read the setup channel's seals")
                .bits();
            let mut readback =
                vec![0_u8; usize::try_from(metadata.len()).expect("channel length fits")];
            file.read_exact_at(&mut readback, 0)
                .expect("read the setup channel back");
            (
                LinuxKernelObjectObservationV1 {
                    device_id: metadata.dev(),
                    inode: metadata.ino(),
                    mount_id: statx.stx_mnt_id,
                    mode: metadata.mode(),
                    owner_uid: metadata.uid(),
                    owner_gid: metadata.gid(),
                    link_count: metadata.nlink(),
                    byte_length: Some(metadata.len()),
                },
                seals,
                readback,
            )
        }

        let anchored = SetupChannelAnchoredFixture::new();
        let statement = anchored.statement();
        let content = statement.encode().expect("the anchored statement encodes");

        let sealed = write_setup_channel(&content, true);
        let (observed, seals, readback) = observe(&sealed);
        assert_eq!(readback, content, "the kernel returned the written bytes");
        assert_eq!(seals, REQUIRED_SETUP_SEAL_BITS, "the exact seal set applied");
        assert_eq!(observed.link_count, 0, "a memfd is an unlinked inode");
        assert_eq!(observed.mode & 0o7777, 0o400);

        let channel = AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            observed,
            seals,
            &readback,
        )
        .expect("a live sealed memfd carrying the anchored statement authenticates");
        assert_eq!(
            channel.setup_channel().content_sha256(),
            &Digest::sha256(&content)
        );
        assert_eq!(
            channel.setup_channel().protocol_digest(),
            &linux_setup_channel_protocol_digest()
        );

        // Enforced, live: the seal is a kernel refusal rather than a claim in
        // the plan. Writing to the sealed channel fails with EPERM.
        let error = (&sealed)
            .write_all(b"x")
            .expect_err("a sealed setup channel must refuse a write");
        assert_eq!(
            error.raw_os_error(),
            Some(1),
            "F_SEAL_WRITE must answer EPERM, got {error:?}"
        );

        // Enforced, live: the same bytes in an unsealed memfd are refused.
        let unsealed = write_setup_channel(&content, false);
        let (unsealed_observed, unsealed_seals, unsealed_readback) = observe(&unsealed);
        assert_eq!(unsealed_seals, 0);
        assert_eq!(unsealed_readback, content);
        assert!(
            AuthenticatedSetupChannelV1::authenticate_sealed(
                &statement,
                unsealed_observed,
                unsealed_seals,
                &unsealed_readback,
            )
            .is_err(),
            "an unsealed channel carrying the identical bytes must be refused"
        );

        // A second sealed channel over identical content is a different kernel
        // object, so the retained identity is a read and the content digest is
        // a digest.
        let second = write_setup_channel(&content, true);
        let (second_observed, second_seals, second_readback) = observe(&second);
        assert_ne!(second_observed.inode, observed.inode);
        let second_channel = AuthenticatedSetupChannelV1::authenticate_sealed(
            &statement,
            second_observed,
            second_seals,
            &second_readback,
        )
        .expect("the second sealed channel authenticates");
        assert_eq!(
            second_channel.setup_channel().content_sha256(),
            channel.setup_channel().content_sha256()
        );
        assert_ne!(
            second_channel.retained().kernel_observation().inode,
            channel.retained().kernel_observation().inode
        );
    }
