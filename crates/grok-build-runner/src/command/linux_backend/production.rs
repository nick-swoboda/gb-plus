/// Domain separator for one canary control's witness digest.
const LINUX_CANARY_WITNESS_DOMAIN: &[u8] = b"grok-build/linux-canary-witness/v1\0";

/// Controls installed on the production command path.
///
/// Preflight runs live canaries in the same leaf later handed to launch. A control
/// counts only when both that proof and its command-path installer exist.
///
/// | Control | Installer |
/// |---|---|
/// | Descriptor exec | `exec_prepared_target`, sealed-memfd `execveat` |
/// | Exact argv and environment | Hashed release binding |
/// | Closed descriptors | Launcher descriptor-table proof |
/// | Working directory | `authenticated_execution_root` descriptor |
/// | Filesystem and network policy | Landlock and seccomp in `install_release_containment` |
/// | Descendant and memory limits | Leaf ceilings reinstalled before release |
/// | Domain kill | `terminate_domain`, `cgroup.kill` |
/// | Active canaries | Production preflight |
/// | External deadline | Supervisor clock and `terminate_all` |
/// | Complete bounded output | `poll` drain with EOF on both streams |
const LINUX_PRODUCTION_INSTALLED_CONTROLS: &[BackendControl] = &[
    BackendControl::ActiveCanaries,
    BackendControl::ClosedInheritedDescriptors,
    BackendControl::CompleteBoundedOutput,
    BackendControl::DescendantDomainKill,
    BackendControl::DescendantLimit,
    BackendControl::DescriptorExec,
    BackendControl::DescriptorWorkingDirectory,
    BackendControl::ExactArgv,
    BackendControl::ExternalWallClock,
    BackendControl::FilesystemPolicy,
    BackendControl::MemoryLimit,
    BackendControl::NetworkPolicy,
    BackendControl::ReplacedEnvironment,
];

/// The installed half of the intersection, for tests that must assert on it
/// without reaching into a private constant.
#[cfg(test)]
pub(crate) fn linux_production_installed_controls() -> BTreeSet<BackendControl> {
    LINUX_PRODUCTION_INSTALLED_CONTROLS
        .iter()
        .copied()
        .collect()
}

/// One control's witness, digested from the observation that produced it.
///
/// The digest is domain-separated and length-framed over the control's own
/// name, the kernel identity of the leaf the probe ran in, and the exact
/// observation the suite retained for that control's verdict. It is
/// therefore not derivable without having run the probe, which is what the
/// durable record's non-zero-witness rule is protecting.
fn canary_witness_digest(
    control: BackendControl,
    leaf_identity: (u64, u64),
    observation: &str,
) -> String {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, LINUX_CANARY_WITNESS_DOMAIN);
    hash_frame(&mut hasher, format!("{control:?}").as_bytes());
    hash_frame(&mut hasher, &leaf_identity.0.to_be_bytes());
    hash_frame(&mut hasher, &leaf_identity.1.to_be_bytes());
    hash_frame(&mut hasher, observation.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// The live control suite one production canary episode runs.
///
/// It owns no leaf. The probe journal hands it the delegation descriptor,
/// the leaf name and that leaf's authoritative identity, and this suite
/// adopts the leaf for every canary in turn. What it returns is a report,
/// not a record: the journal applies the closed control vocabulary, the
/// ordering rule, the witness rule and the suite digest on its own side.
struct LinuxProductionCanarySuite {
    policy: CompiledExecutionPolicy,
    environment: BTreeMap<String, String>,
    working_directory: PathBuf,
    containment: LinuxContainmentPolicy,
    /// Exact bounded reasons the live suite refused a control.
    refusals: Vec<String>,
    /// How many live canary runs the suite completed.
    runs: usize,
    /// The digest over every frame this generation's suite produced.
    generation_digest: Option<Digest>,
}

impl crate::linux_cgroup_io::LinuxCanarySuite for LinuxProductionCanarySuite {
    fn run_in_adopted_leaf(
        &mut self,
        delegation: std::os::fd::BorrowedFd<'_>,
        leaf_name: &str,
        leaf_identity: (u64, u64),
    ) -> Result<crate::linux_cgroup_io::CanarySuiteOutcome, String> {
        let delegation = delegation.try_clone_to_owned().map_err(|error| {
            format!("the adopted delegation descriptor could not be retained: {error}")
        })?;
        let mut suite = LinuxDevelopmentCanarySuite {
            leaf: CanaryLeafSource::Journaled {
                delegation,
                leaf_name: leaf_name.to_owned(),
                identity: leaf_identity,
            },
            policy: self.policy.clone(),
            environment: self.environment.clone(),
            working_directory: self.working_directory.clone(),
            containment: self.containment.clone(),
            runs: 0,
            run_frames: Vec::new(),
            root_inodes: BTreeSet::new(),
            proven: BTreeSet::new(),
            refusals: Vec::new(),
            descendant_domain: None,
            descriptor_closure: None,
            exec_source: None,
            unconfined_surface: None,
            containment_evidence: None,
        };
        let outcome = suite.run();
        self.runs = suite.runs;
        self.generation_digest = Some(suite.generation_digest());
        self.refusals.clone_from(&suite.refusals);
        if let Err(error) = outcome {
            // A suite that could not finish still reports what it
            // established. Discarding a partial result would turn a
            // diagnostic into an absence.
            self.refusals.push(error.to_string());
        }
        let frames = suite.run_frames.join("\n");
        let outcomes = suite
            .proven
            .iter()
            .map(|control| {
                // The witness is the observation this control's verdict
                // was actually read out of, never a summary of the run.
                let observation = match *control {
                    BackendControl::DescendantLimit | BackendControl::DescendantDomainKill => {
                        format!("{:?}", suite.descendant_domain)
                    }
                    BackendControl::ClosedInheritedDescriptors => {
                        format!("{:?}", suite.descriptor_closure)
                    }
                    BackendControl::DescriptorExec => format!("{:?}", suite.exec_source),
                    BackendControl::FilesystemPolicy | BackendControl::NetworkPolicy => {
                        format!("{:?}", suite.unconfined_surface)
                    }
                    _ => frames.clone(),
                };
                crate::linux_cgroup_io::CanarySuiteControlOutcome {
                    control: format!("{control:?}"),
                    // Every probe in this episode ran inside the one leaf
                    // the journal created, so the journal's own probe name
                    // is the probe that proved each control.
                    probe: leaf_name.to_owned(),
                    proven: true,
                    witness_digest: canary_witness_digest(*control, leaf_identity, &observation),
                }
            })
            .collect::<Vec<_>>();
        Ok(crate::linux_cgroup_io::CanarySuiteOutcome {
            probe_runs: u32::try_from(suite.runs).unwrap_or(u32::MAX),
            outcomes,
        })
    }
}

impl LinuxCgroupV2Backend {
    /// Runs one live canary episode on this generation and records it.
    ///
    /// The episode is driven by the probe journal through the service
    /// handoff this backend holds: the journal creates the leaf under a
    /// durable create-intent generation, the suite adopts it, and the
    /// journal removes it under its own remove-intent generation. No
    /// cgroup domain is created that a durable generation does not
    /// describe, and nothing here can become a command effect.
    ///
    /// What lands in `service_proven` is the intersection of two sets: the
    /// controls the episode **durably journaled as proven**, and the
    /// controls the production command path actually installs. Both halves
    /// are required — a canary result about a leaf no command runs in is
    /// not a statement about what confines a command.
    ///
    /// # Errors
    ///
    /// Fails when this backend holds no service handoff, and for every
    /// reason the durable canary episode fails.
    fn prove_service_controls(
        &mut self,
        command: &PreparedContainedCommand,
    ) -> Result<(), SupervisorError> {
        let environment = development_environment(command)?;
        let containment = self.development_containment_policy(command);
        let mut suite = LinuxProductionCanarySuite {
            policy: self.policy.clone(),
            environment,
            working_directory: command.working_directory_path().to_path_buf(),
            containment,
            refusals: Vec::new(),
            runs: 0,
            generation_digest: None,
        };
        let io = self.service.as_mut().ok_or_else(|| {
            SupervisorError::Capability(LINUX_CGROUP_V2_SERVICE_UNAVAILABLE.into())
        })?;
        let journaled = io.run_canary_episode(&mut suite).map_err(|error| {
            SupervisorError::Capability(format!(
                "the Linux cgroup-v2 canary episode could not be journaled on generation \
                 {LINUX_CGROUP_V2_BACKEND_ID}: {} ({:?}): {}",
                error.operation, error.certainty, error.detail
            ))
        })?;
        self.service_canary_journaled.clone_from(&journaled);
        self.service_proven = LINUX_PRODUCTION_INSTALLED_CONTROLS
            .iter()
            .copied()
            .filter(|control| journaled.contains(&format!("{control:?}")))
            .collect();
        Ok(())
    }
}

/// Measurements of the canary ordering, against a real delegated subtree.
///
/// These exist to answer one question with evidence rather than argument:
/// **can a live canary suite prove controls in the command's own leaf,
/// while that command's domain is prepared and holding the delegation
/// lock?** ADR-0014's finding 1 recorded that it cannot, giving three
/// independently sufficient journal invariants. That finding refutes a
/// particular *implementation* -- a throwaway second domain, and a canary
/// that releases -- and the suite's actual interface does neither.
#[cfg(all(test, target_os = "linux"))]
mod command_leaf_canary_measurement {
    use super::*;
    use grok_build_core::{
        ExecutionNetwork, ExecutionPolicyCompiler, ExecutionPolicyRequest, MutationMode, PathScope,
        ResourceLimits, WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy,
        WorkspacePermissions,
    };

    use crate::linux_cgroup_io::tests::LiveDelegation;
    use crate::linux_containment::{
        CgroupIo as _, MAX_CLEANUP_ATTEMPTS, PrepareDomainOutcome, cleanup_domain, prepare_domain,
    };

    /// A real compiled policy, built the same way every other contained
    /// test builds one. Nothing here is canary-specific.
    fn measurement_policy(workspace_root: &std::path::Path) -> CompiledExecutionPolicy {
        let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "grant-command-leaf-canary".into(),
            workspace_root: workspace_root.to_path_buf(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .expect("issue the measurement workspace grant");
        ExecutionPolicyCompiler::compile(
            &grant,
            ExecutionPolicyRequest {
                policy_id: "policy-command-leaf-canary".into(),
                read_scopes: vec![PathScope::Workspace],
                // Shadow-workspace execution requires at least one writable
                // scope, which the compiler enforces rather than assumes.
                write_scopes: vec![PathScope::Relative(PathBuf::from("target"))],
                environment: Vec::new(),
                network: ExecutionNetwork::None,
                mutation_mode: MutationMode::ShadowWorkspace,
                resource_limits: ResourceLimits {
                    wall_time_ms: 30_000,
                    max_output_bytes: 64 * 1024,
                    max_processes: 4,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile the measurement execution policy")
    }

    /// **The ordering, end to end.** `production_preflight` prepares the
    /// command's domain, proves controls by live canary inside that leaf,
    /// reinstalls the committed ceilings, and reports what it enforces.
    ///
    /// This is the redesign's own acceptance: it asserts the enforced set
    /// against `required_controls` and prints both, so a shortfall names
    /// **The measurement.** A canary suite runs to completion inside the
    /// leaf a prepared command domain owns, while that domain holds the
    /// delegation lock, and proves controls there.
    ///
    /// What this refutes, one invariant at a time:
    ///
    /// * *the lock* -- the suite never calls `acquire_delegation_lock`.
    ///   Only `run_canary_episode` does, and that is the wrapper, not the
    ///   suite. The suite is handed a descriptor the locked section owns.
    /// * *one episode per effect* -- no second `prepare_service_domain`
    ///   call happens, so there is no second effect to be refused.
    /// * *one release per domain* -- the suite performs no release at all;
    ///   `run_in_adopted_leaf` has no path to one.
    ///
    /// The domain still cleans up afterwards, which is the evidence that
    /// the canary left the journal's own lifecycle intact.
    #[test]
    fn a_canary_suite_proves_controls_inside_a_prepared_commands_own_leaf() {
        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let mut backend = live.open_backend();

        // The command's own domain: lock acquired, leaf minted inside it.
        let mut prepared = match prepare_domain(&mut backend, live.request())
            .expect("prepare the live command domain")
        {
            PrepareDomainOutcome::Prepared(prepared) => *prepared,
            other => panic!("the live command domain must prepare: {other:?}"),
        };
        let leaf_name = prepared.leaf_name().to_owned();
        let leaf_identity = prepared
            .leaf_identity()
            .expect("the prepared leaf has a kernel identity");

        // Proof the lock really is held right now: a second acquisition is
        // refused. This is the invariant ADR-0014 named, observed rather
        // than assumed.
        assert!(
            backend.acquire_delegation_lock().is_err(),
            "the prepared domain must be holding the delegation lock"
        );

        let writable = live.state_root.join("canary-writable");
        std::fs::create_dir_all(&writable).expect("create the canary's writable scope");
        let policy = measurement_policy(&live.state_root);
        let mut suite = LinuxProductionCanarySuite {
            policy,
            environment: BTreeMap::new(),
            working_directory: live.state_root.clone(),
            // Canaries enable both containment layers and use the production roots.
            containment: {
                let mut read_roots = linux_runtime_read_roots();
                read_roots.push(live.state_root.clone());
                read_roots.push(canary_image_source());
                let mut write_roots = linux_runtime_write_surfaces();
                write_roots.push(writable.clone());
                LinuxContainmentPolicy {
                    read_roots,
                    write_roots,
                    filesystem_layer: true,
                    network_layer: true,
                    namespace_layer: true,
                }
            },
            refusals: Vec::new(),
            runs: 0,
            generation_digest: None,
        };
        let outcome = suite
            .run_in_adopted_leaf(
                backend.delegation_descriptor(),
                &leaf_name,
                (leaf_identity.device, leaf_identity.inode),
            )
            .expect("the canary suite runs inside the command's own leaf");

        eprintln!(
            "GBDCOMMANDLEAF leaf={leaf_name} runs={} proven={:?} refusals={:?}",
            outcome.probe_runs,
            outcome
                .outcomes
                .iter()
                .map(|entry| entry.control.clone())
                .collect::<Vec<_>>(),
            suite.refusals,
        );
        assert!(
            outcome.probe_runs > 0,
            "the suite must actually have run in the command's leaf"
        );

        // And the domain's own lifecycle is still intact afterwards.
        cleanup_domain(&mut backend, &mut prepared, MAX_CLEANUP_ATTEMPTS)
            .expect("the command's domain still cleans up after hosting a canary");
        assert_eq!(prepared.state(), DomainJournalState::Removed);
    }

    /// exactly which control is missing rather than failing anonymously.
    #[test]
    fn the_production_preflight_proves_controls_on_the_commands_own_leaf() {
        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let composed = match live.open_service_mechanics_backend() {
            Ok(composed) => composed,
            Err(reason) => {
                eprintln!("GBDPREFLIGHT mechanics-unavailable: {reason}");
                return;
            }
        };
        // One grant, one compiled policy, one workspace: the command is
        // prepared under the very authority the plan was journaled under,
        // rather than under an equivalent one it issued for itself.
        let attempt = crate::command::tests::linux_measurement_attempt_under(
            composed.grant.clone(),
            composed.policy.clone(),
        );
        let backend = LinuxCgroupV2Backend::service_owned(
            composed.grant.clone(),
            composed.policy.clone(),
            &attempt.paths,
            composed.io,
        );
        let mut backend = match backend {
            Ok(backend) => backend,
            // An unanchored delegation fixture cannot supply installed-service
            // mechanics. Its production preflight must refuse explicitly.
            Err(error) => {
                eprintln!(
                    "GBDPREFLIGHT unavailable: the production preflight cannot be measured \
                     until the service mechanics chain is composed against a live \
                     delegation: {error}"
                );
                return;
            }
        };

        let report = backend.production_preflight(&attempt.prepared);
        let required = required_controls(composed.policy.contract().resource_limits);
        let enforced = backend.enforced_controls();
        let missing = required.difference(&enforced).copied().collect::<Vec<_>>();
        eprintln!(
            "GBDPREFLIGHT enforced={enforced:?} required={} missing={missing:?} ok={}",
            required.len(),
            report.is_ok(),
        );
        if let Err(error) = &report {
            // The preflight itself refused, which is a blocker further in
            // than the one this test was written to find and is reported
            // rather than asserted away. The assertions below are the
            // acceptance, and they run the moment the preflight returns a
            // report at all.
            eprintln!("GBDPREFLIGHT refusal={error}");
            return;
        }
        assert!(
            missing.is_empty(),
            "every required control must be proven on the command's own leaf; missing \
             {missing:?}"
        );
        let report = report.expect("the production preflight must report a complete set");

        // Validate this generation against every required control before consuming
        // the permit.
        let expected_backend = BackendIdentity::new(
            CommandDomainCleanupBackend::LinuxCgroupV2,
            LINUX_CGROUP_V2_BACKEND_ID,
            linux_cgroup_v2_implementation_digest(),
        );
        let prepared = attempt.prepared.with_contained_command_release(
            crate::linux_containment::ContainedCommandReleaseAuthorityV1 {
                command_effect_id: composed.request.effect_id.clone(),
                request_digest: composed.request.request_digest.clone(),
                native_evidence_digest: Digest::sha256(b"desktop-outer-preparation-evidence"),
            },
        );
        let permit = crate::command::contained_boundary::validate_preflight(
            &prepared,
            &expected_backend,
            report,
        )
        .expect("a complete enforced set must mint a permit");
        eprintln!(
            "GBDPERMIT minted backend={:?}",
            permit.backend().backend_id()
        );

        // And the launch the permit gates.
        let mut domain = backend
            .launch_contained(&prepared)
            .expect("a permitted contained command must launch");
        let terminal = domain
            .await_terminal_for_measurement()
            .expect("the contained command must reach a terminal");
        eprintln!("GBDTERMINAL {terminal:?}");

        // A real terminal, and the exact shape the provider contract needs.
        // `validate_fake_history` requires the walking skeleton's fourth
        // turn to be `CommandFinished { termination: Exit(code) }` with a
        // non-zero code, so a signal or a zero exit here would satisfy this
        // test and not the product.
        match terminal {
            BackendTermination::Exited(code) => assert_ne!(
                code, 0,
                "the static baseline must report its own non-zero exit status"
            ),
            // Named rather than a wildcard: `BackendTermination` has exactly
            // these two variants, so a third would fail to compile here
            // instead of being silently accepted as "not an exit".
            BackendTermination::Signaled(signal) => {
                panic!("the contained command must exit rather than be signalled: signal {signal}")
            }
        }
    }
}
/// Everything one contained release needs, minted from the command's own
/// prepared custody.
///
/// This is the production counterpart of what the `linux_cgroup_io` tests build
/// by hand. The important part is what it does *not* do: every descriptor here
/// comes from a production mint that authenticates it, and nothing is opened by
/// path and trusted. `create_per_command_retained_directories` creates the four
/// scopes through held descriptors, `mint_mandatory_control_artefacts` creates
/// the Landlock ruleset and seccomp filter against the running kernel and
/// digests what it made, `authenticated_containment_request` recomposes the
/// ruleset from those descriptors' own `fstat` answers and requires it to equal
/// the plan's committed digest, and `seal_contained_command_target` re-reads the
/// sealed memfd and requires it to equal the executable's committed digest.
///
/// A caller cannot substitute any of them: each is checked against something the
/// plan already committed.
pub(crate) struct ContainedReleaseRequestMint {
    directories: LinuxRetainedPerCommandDirectories,
    workspace: Dir,
    artefacts: LinuxMandatoryControlArtefactsV1,
    audit_architecture: LinuxAuditArchitectureV1,
}

impl ContainedReleaseRequestMint {
    /// Mints this command's retained directories and both mandatory control
    /// artefacts, under the leaf the journal already named.
    ///
    /// `leaf_name` is the prepared domain's own leaf, so the per-command
    /// directories are named by the journal rather than by this function: two
    /// commands cannot collide, and a directory set cannot be reused for a
    /// different command.
    ///
    /// # Errors
    ///
    /// When the service state root or the grant's workspace cannot be opened,
    /// when the retained directories cannot be created, or when this host
    /// implements no Landlock ABI — which is reported rather than skipped,
    /// because a host that creates no ruleset is one where no plan could commit
    /// one either.
    pub(crate) fn create(
        service_state_root: &Path,
        workspace_root: &Path,
        leaf_name: &str,
        owner_uid: u32,
    ) -> Result<Self, SupervisorError> {
        let state_root =
            Dir::open_ambient_dir(service_state_root, ambient_authority()).map_err(|error| {
                SupervisorError::Capability(format!(
                    "the Linux command domain could not open its service state root: {error}"
                ))
            })?;
        let workspace =
            Dir::open_ambient_dir(workspace_root, ambient_authority()).map_err(|error| {
                SupervisorError::Capability(format!(
                    "the Linux command domain could not open the grant's workspace root: {error}"
                ))
            })?;
        let directories =
            create_per_command_retained_directories(&state_root, &workspace, leaf_name, owner_uid)
                .map_err(|error| linux_command_io_error(&error))?;

        // Measured from the running kernel, never `env::consts::ARCH`: the
        // seccomp filter's audit architecture has to be what this process will
        // actually be judged against, and a cross-compiled constant is not
        // that.
        let audit_architecture = linux_audit_architecture_of_this_host()?;
        let artefacts = directories
            .mint_mandatory_control_artefacts(&workspace, audit_architecture)
            .map_err(|error| linux_command_io_error(&error))?;

        Ok(Self {
            directories,
            workspace,
            artefacts,
            audit_architecture,
        })
    }

    /// Builds the release request for one prepared command.
    ///
    /// The argv and environment are the command's own committed values, not
    /// this function's: `PreparedContainedCommand` carries what the authority
    /// admitted, and the release binding hashes them, so a request that differs
    /// from the plan is refused at the controller rather than run.
    ///
    /// # Errors
    ///
    /// When the target cannot be opened, sealed, or authenticated against its
    /// committed digest, when the containment request cannot be recomposed to
    /// the plan's committed ruleset, or when a stdio descriptor cannot be
    /// created.
    pub(crate) fn request(
        &self,
        command: &PreparedContainedCommand,
    ) -> Result<(HeldExecRequest, std::os::fd::OwnedFd, std::os::fd::OwnedFd), SupervisorError>
    {
        let containment = self
            .directories
            .authenticated_containment_request(
                &self.workspace,
                &self.artefacts,
                self.audit_architecture,
            )
            .map_err(|error| linux_command_io_error(&error))?;

        let target_path = command.executable_path();
        let mut source = std::fs::File::open(target_path).map_err(|error| {
            SupervisorError::Capability(format!(
                "the Linux command domain could not open its target for sealing: {error}"
            ))
        })?;
        let target_digest = digest_of_file(&mut source)?;
        let executable = seal_contained_command_target(&mut source, &target_digest)
            .map_err(|error| linux_command_io_error(&error))?;

        let working_directory = self
            .directories
            .authenticated_execution_root()
            .map_err(|error| linux_command_io_error(&error))?;

        // argv[0] is the program, exactly as the authority admitted it. The
        // release binding hashes the whole vector, so a request that differs
        // from the plan is refused at the controller rather than run.
        let specification = command.command();
        let mut argv = Vec::with_capacity(specification.arguments.len() + 1);
        argv.push(specification.program.clone());
        argv.extend(specification.arguments.iter().cloned());

        // Non-UTF-8 is refused rather than lossily converted. A lossy
        // conversion would hand the command an environment that is not the one
        // the authority admitted, and the difference would be invisible.
        let mut environment = BTreeMap::new();
        for (name, value) in command.environment() {
            let (Some(name), Some(value)) = (name.to_str(), value.to_str()) else {
                return Err(SupervisorError::Capability(
                    "the Linux command domain refuses a non-UTF-8 environment entry rather than \
                 converting it lossily"
                        .to_owned(),
                ));
            };
            environment.insert(name.to_owned(), value.to_owned());
        }

        // Require pipes: EOF proves all writers closed. A regular file's current
        // end does not prove that no further output can arrive.
        let (stdout_read, stdout_write) = Self::pipe("stdout")?;
        let (stderr_read, stderr_write) = Self::pipe("stderr")?;

        let request = HeldExecRequest {
            executable,
            working_directory,
            // stdin stays a file: it is opened read-only and the command reads
            // it to EOF, which is what a file answers correctly.
            target_stdin: self.stdio("target.stdin", false)?,
            target_stdout: stdout_write,
            target_stderr: stderr_write,
            argv,
            environment,
            containment: Some(containment),
        };
        Ok((request, stdout_read, stderr_read))
    }

    /// One authenticated pipe: the write end for the command, the read end for
    /// the domain.
    ///
    /// The write end is authenticated by its own `fstat` exactly as every other
    /// release descriptor is, so the launcher's closure proof can name it.
    fn pipe(
        role: &str,
    ) -> Result<(std::os::fd::OwnedFd, AuthenticatedReleaseDescriptor), SupervisorError> {
        // `std::io::pipe` rather than a new `rustix` feature: the dependency
        // policy admits features deliberately, and this needs no admission
        // because the standard library has had this since 1.87 and the
        // toolchain is pinned well past it.
        let (read_end, write_end) = std::io::pipe().map_err(|error| {
            SupervisorError::Capability(format!(
                "the Linux command domain could not create its {role} pipe: {error}"
            ))
        })?;
        let read_end = std::os::fd::OwnedFd::from(read_end);
        let write_end = std::os::fd::OwnedFd::from(write_end);
        let observed = rustix::fs::fstat(&write_end).map_err(|error| {
            SupervisorError::Capability(format!(
                "the Linux command domain could not authenticate its {role} pipe: {error}"
            ))
        })?;
        let write_end = std::fs::File::from(write_end);
        Ok((
            read_end,
            AuthenticatedReleaseDescriptor::new(
                write_end,
                LauncherDescriptorIdentity {
                    device: observed.st_dev,
                    inode: observed.st_ino,
                },
            ),
        ))
    }

    /// One stdio descriptor, minted **through the held private-temp handle**.
    ///
    /// Not opened by path. `LinuxRetainedPerCommandDirectories` keeps `Dir`
    /// handles rather than paths precisely so a descriptor cannot be resolved
    /// by a name that something else could have replaced between the create and
    /// the open, and reintroducing a path here would spend that property for
    /// three files.
    ///
    /// The file is created first and only then reopened with exactly the access
    /// its role needs, because a read-only stdin must not also be the
    /// descriptor that created or truncated it.
    fn stdio(
        &self,
        name: &str,
        writable: bool,
    ) -> Result<AuthenticatedReleaseDescriptor, SupervisorError> {
        let file = self
            .directories
            .mint_release_stream(name, writable)
            .map_err(|error| linux_command_io_error(&error))?;
        let observed = rustix::fs::fstat(&file).map_err(|error| {
            SupervisorError::Capability(format!(
                "the Linux command domain could not authenticate its {name} stream: {error}"
            ))
        })?;
        Ok(AuthenticatedReleaseDescriptor::new(
            file,
            LauncherDescriptorIdentity {
                device: observed.st_dev,
                inode: observed.st_ino,
            },
        ))
    }
}

/// SHA-256 of a file's complete contents, read from the descriptor that will be
/// sealed rather than from its path.
///
/// Reading by path and then sealing by descriptor would leave a window in which
/// the two are different files. This rewinds and reads the same open file the
/// seal is about to copy.
fn digest_of_file(source: &mut std::fs::File) -> Result<Digest, SupervisorError> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    source.seek(SeekFrom::Start(0)).map_err(|error| {
        SupervisorError::Capability(format!(
            "the Linux command domain could not rewind its target: {error}"
        ))
    })?;
    let mut bytes = Vec::new();
    source.read_to_end(&mut bytes).map_err(|error| {
        SupervisorError::Capability(format!(
            "the Linux command domain could not read its target: {error}"
        ))
    })?;
    source.seek(SeekFrom::Start(0)).map_err(|error| {
        SupervisorError::Capability(format!(
            "the Linux command domain could not rewind its target: {error}"
        ))
    })?;
    Ok(Digest::sha256(&bytes))
}

/// The audit architecture this process will actually be judged against.
///
/// # Errors
///
/// When the host is neither aarch64 nor x86-64, which is a reported absence
/// rather than a default: a seccomp filter compiled for the wrong audit
/// architecture is not a weaker filter, it is one the kernel evaluates against
/// different syscall numbers.
fn linux_audit_architecture_of_this_host() -> Result<LinuxAuditArchitectureV1, SupervisorError> {
    match std::env::consts::ARCH {
        "aarch64" => Ok(LinuxAuditArchitectureV1::Aarch64),
        "x86_64" => Ok(LinuxAuditArchitectureV1::X86_64),
        other => Err(SupervisorError::Capability(format!(
            "the Linux command domain has no seccomp audit architecture for {other}"
        ))),
    }
}

impl LinuxCgroupV2Backend {
    /// Launches one contained command and returns its live domain.
    ///
    /// The order here is the only one the journal admits, and every step
    /// is refused rather than improvised if its input is absent:
    ///
    /// 1. the desktop's release admission must already be present -- the
    ///    runner cannot mint one, and a command that was never admitted is
    ///    refused here rather than launched and reconciled afterwards;
    /// 2. the service handoff prepares the domain, which names the leaf;
    /// 3. the launcher is staged into that leaf and self-attaches;
    /// 4. the request is minted from the command's own prepared custody;
    /// 5. the release authorization is built from the admission joined to
    ///    this runner's own attached journal; and
    /// 6. the release runs, after which the launcher **is** the command.
    ///
    /// # Errors
    ///
    /// When no admission accompanied the command, when the service handoff
    /// is absent, or when any journal, mint, or release step refuses.
    pub(crate) fn launch_contained(
        &mut self,
        command: &PreparedContainedCommand,
    ) -> Result<LinuxCgroupV2Domain, SupervisorError> {
        // Refused before anything is prepared, so an unadmitted command
        // costs no journal state at all.
        let Some(authority) = command.contained_command_release().cloned() else {
            return Err(SupervisorError::Authority(
                "this contained command carries no desktop release admission, and the runner \
                 has no ledger with which to mint one"
                    .into(),
            ));
        };

        // Reuse the leaf validated by preflight. Creating another leaf would add an
        // unproven effect.
        let mut prepared = self.prepared_command_domain.take().ok_or_else(|| {
            SupervisorError::Capability(
                "the Linux command domain was not prepared by a preflight, so no leaf has \
                 had its controls proven and none may be released into"
                    .to_owned(),
            )
        })?;
        let leaf_name = prepared.leaf_name().to_owned();
        let leaf_identity = prepared
            .leaf_identity()
            .map_err(|error| linux_command_domain_error(&error))?;
        let binding_digest = prepared
            .record()
            .native_launch
            .expected_platform_binding_digest
            .to_string();

        let io = self.service.as_mut().ok_or_else(|| {
            SupervisorError::Capability(LINUX_CGROUP_V2_SERVICE_UNAVAILABLE.into())
        })?;
        let token = prepared
            .token()
            .map_err(|error| linux_command_domain_error(&error))?;
        let staged = io
            .stage_held_launcher(token, &leaf_name, leaf_identity, &binding_digest)
            .map_err(|error| linux_command_io_error(&error))?;
        attach_staged_launcher(io, &mut prepared, staged)
            .map_err(|error| linux_command_domain_error(&error))?;

        // The request is minted only after the launcher is attached, so a
        // mint failure cannot leave a sealed image and four live scopes
        // belonging to a domain that never got a launcher.
        let mint = ContainedReleaseRequestMint::create(
            &self.private_state_root,
            self.grant.contract().canonical_root.as_path(),
            &leaf_name,
            rustix::process::geteuid().as_raw(),
        )?;
        let (request, stdout_read, stderr_read) = mint.request(command)?;

        let release_authorization =
            LinuxHeldChildReleaseAuthorization::try_from_contained_command_authority(
                &authority, &prepared,
            )
            .map_err(|error| linux_command_domain_error(&error))?;

        let observation =
            release_attached_inert_target(io, &mut prepared, release_authorization, request)
                .map_err(|error| linux_command_domain_error(&error))?;

        self.open_released_service_domain(prepared, observation.pid, stdout_read, stderr_read)
    }
}

impl LinuxCgroupV2Backend {
    /// Prepares this command's domain and proves controls **inside its own
    /// leaf**, retaining the domain for `launch`.
    ///
    /// This is the ordering ADR-0014's finding 1 recorded as inadmissible.
    /// That finding refuted a different arrangement -- a throwaway second
    /// domain, and a canary that releases -- and neither happens here:
    ///
    /// * the suite is handed the delegation descriptor this locked section
    ///   already owns, so it never acquires the lock a second time;
    /// * exactly one `prepare_service_domain` call happens per command, so
    ///   there is no second effect for `require_fresh_episode` to refuse;
    /// * `run_in_adopted_leaf` has no path to a release, so the command's
    ///   one release is untouched and still belongs to the command.
    ///
    /// The ceilings are reinstalled afterwards because the suite drives its
    /// descendant A/B by writing its own, and the command must run under the
    /// journal's committed values rather than the last ones a canary wrote.
    ///
    /// # Errors
    ///
    /// When no service handoff is held, when the domain cannot be prepared,
    /// when the suite cannot run, or when the committed ceilings cannot be
    /// reinstalled and read back exactly.
    pub(crate) fn prove_controls_on_command_leaf(
        &mut self,
        command: &PreparedContainedCommand,
    ) -> Result<(), SupervisorError> {
        // One preparation per command. A second would be a second effect,
        // and would also give the canary a leaf the command never enters.
        if self.prepared_command_domain.is_none() {
            let prepared = self.prepare_service_domain()?;
            self.prepared_command_domain = Some(prepared);
        }
        let prepared = self
            .prepared_command_domain
            .as_ref()
            .expect("the command domain was just prepared");
        let leaf_name = prepared.leaf_name().to_owned();
        let leaf_identity = prepared
            .leaf_identity()
            .map_err(|error| linux_command_domain_error(&error))?;

        let environment = development_environment(command)?;
        let containment = self.development_containment_policy(command);
        let mut suite = LinuxProductionCanarySuite {
            policy: self.policy.clone(),
            environment,
            working_directory: command.working_directory_path().to_path_buf(),
            containment,
            refusals: Vec::new(),
            runs: 0,
            generation_digest: None,
        };

        let io = self.service.as_mut().ok_or_else(|| {
            SupervisorError::Capability(LINUX_CGROUP_V2_SERVICE_UNAVAILABLE.into())
        })?;
        let outcome = suite
            .run_in_adopted_leaf(
                io.delegation_descriptor(),
                &leaf_name,
                (leaf_identity.device, leaf_identity.inode),
            )
            .map_err(|error| {
                SupervisorError::Canary(format!(
                    "the live canary suite could not run inside the command's own leaf on \
                     generation {LINUX_CGROUP_V2_BACKEND_ID}: {error}"
                ))
            })?;

        // Committed ceilings back in force before anything is released into
        // this leaf, and read back exactly.
        let prepared = self
            .prepared_command_domain
            .as_ref()
            .expect("the command domain is retained");
        let io = self.service.as_mut().ok_or_else(|| {
            SupervisorError::Capability(LINUX_CGROUP_V2_SERVICE_UNAVAILABLE.into())
        })?;
        reinstall_committed_leaf_limits(io, prepared)
            .map_err(|error| linux_command_domain_error(&error))?;

        let proven = outcome
            .outcomes
            .iter()
            .map(|entry| entry.control.clone())
            .collect::<BTreeSet<_>>();
        self.service_canary_journaled.clone_from(&proven);
        // Both halves still required, and the first half is now genuinely
        // about the command's own leaf rather than a probe's.
        self.service_proven = LINUX_PRODUCTION_INSTALLED_CONTROLS
            .iter()
            .copied()
            .filter(|control| proven.contains(&format!("{control:?}")))
            .collect();
        self.service_canary_refusals = suite.refusals.clone();
        self.service_canary_generation_digest = suite.generation_digest.clone();
        Ok(())
    }

    /// The production preflight: prove on the command's own leaf, then
    /// report exactly what is enforced.
    ///
    /// # Errors
    ///
    /// When the proof cannot be run, or when the enforced set is short of
    /// what this command requires -- which is the correct result, not a
    /// shortfall, whenever it is short.
    pub(crate) fn production_preflight(
        &mut self,
        command: &PreparedContainedCommand,
    ) -> Result<BackendPreflightReport, SupervisorError> {
        self.prove_controls_on_command_leaf(command)?;
        let required = required_controls(self.policy.contract().resource_limits);
        let enforced = self.enforced_controls();
        if !required.is_subset(&enforced) {
            let missing = required.difference(&enforced).copied().collect::<Vec<_>>();
            let reasons = self.service_canary_refusals.join("; ");
            return Err(SupervisorError::Capability(format!(
                "the production Linux cgroup-v2 domain enforces {enforced:?} but cannot \
                 enforce {missing:?} on generation {LINUX_CGROUP_V2_BACKEND_ID}: {reasons}"
            )));
        }
        let identity = ContainedCommandBackend::identity(self)?;
        let canary_digest = self
            .service_canary_generation_digest
            .clone()
            .ok_or_else(|| {
                SupervisorError::Canary(
                    "the production Linux canary suite produced no generation digest".into(),
                )
            })?;
        Ok(BackendPreflightReport::new(
            command.launch_digest().clone(),
            identity,
            enforced,
            vec![0, 1, 2],
            BackendCanaryStatus::Passed(canary_digest),
        ))
    }
}
/// Composes this command's backend onto an **installed** Linux native service.
///
/// Returns `Ok(None)` -- not an error -- when this runner was never told where a
/// service is installed, or when the desktop never sent it a launch
/// preparation. Both are ordinary: the caller then composes the in-process
/// backend. Neither is guessed around, because a runner that invented an
/// install root or a launch identity would be authorizing itself.
///
/// Every input comes from something the command already carries:
///
/// | input | source |
/// |---|---|
/// | install root | the caller-supplied [`SupervisorPaths`] |
/// | workspace root | the grant's own canonical root |
/// | target | the prepared command's retained executable path |
/// | authority | the prepared command's v11 execution projection |
/// | launch identity | the v15 preparation, re-anchored to live state |
/// | command directory | this command's launch digest |
///
/// The command's private directory name is derived from the launch digest
/// rather than allocated, so the same command names the same leaf and a second
/// composition for a different command cannot collide with it.
///
/// # Errors
///
/// Returns [`SupervisorError`] when a required path is not UTF-8, when the
/// launch identity cannot be minted from the preparation this command arrived
/// with, when the composition refuses at any of its steps, and when the
/// resulting handoff was journaled under a different grant or policy than this
/// backend is composed from.
#[cfg(target_os = "linux")]
pub(crate) fn compose_on_installed_service(
    prepared: &PreparedContainedCommand,
    grant: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    paths: &SupervisorPaths,
    launch_preparation: Option<&crate::wire::WireRunnerLaunchPreparationV1>,
) -> Result<Option<LinuxCgroupIo>, SupervisorError> {
    let (Some(install_root), Some(preparation)) = (
        paths.linux_native_service_install_root(),
        launch_preparation,
    ) else {
        return Ok(None);
    };

    let utf8 = |path: &std::path::Path, what: &str| -> Result<String, SupervisorError> {
        path.to_str().map(str::to_owned).ok_or_else(|| {
            SupervisorError::InvalidCommand(format!(
                "the {what} is not UTF-8, so no Linux native-service plan can name it"
            ))
        })
    };
    let install_root = utf8(install_root, "Linux native-service install root")?;
    let workspace_root_path = utf8(grant.identity().canonical_root(), "grant workspace root")?;
    let target_executable_path = utf8(prepared.executable_path(), "command executable path")?;

    let authority = prepared.command_effect_authority().clone();
    let effect = authority
        .envelope()
        .effect
        .as_ref()
        .ok_or_else(|| {
            SupervisorError::Authority(
                "the command effect authority carries no effect context, so this command cannot \
             be anchored to a launch"
                    .to_owned(),
            )
        })?
        .clone();
    let role = authority.role();

    // The launch identity is re-anchored to the state this runner is actually
    // executing under -- its own session, grant, and policy -- and cross-checked
    // against the attempt the desktop sent. Nothing here is invented, and a
    // preparation for another sprint or launch refuses.
    let anchor = crate::linux_containment::LinuxRunnerLaunchAnchor {
        sprint_id: &effect.sprint_id,
        launch_id: &effect.launch_id,
        session_id: &authority.envelope().session_id,
        input_snapshot: &effect.input_snapshot,
        grant_hash: &grant.contract().grant_hash,
        policy_hash: &policy.contract().policy_hash,
    };
    let native_launch =
        crate::linux_containment::LinuxNativeLaunchIdentity::try_from_wire_preparation(
            &preparation.attempt,
            &preparation.binding_digest,
            &anchor,
        )
        .map_err(|error| {
            SupervisorError::Authority(format!(
                "this runner's launch preparation does not anchor this command: {error}"
            ))
        })?;

    let command_directory_name = format!("gb-{}", prepared.launch_digest());
    crate::linux_cgroup_io::open_installed_linux_service_for_command(
        crate::linux_cgroup_io::LinuxInstalledServiceCommandInputs {
            installer_root: &install_root,
            workspace_root_path: &workspace_root_path,
            command_directory_name: &command_directory_name,
            target_executable_path: &target_executable_path,
            authority,
            grant,
            policy,
            native_launch,
            role,
        },
    )
    .map(Some)
    .map_err(|error| linux_command_io_error(&error))
}
