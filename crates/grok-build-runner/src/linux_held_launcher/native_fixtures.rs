    #[cfg(test)]
    mod native_tests {
        use std::fs::{self, OpenOptions};
        use std::io::{Seek as _, SeekFrom as StdSeekFrom};
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, Ordering};

        use rustix::fs::{MemfdFlags, SealFlags};

        use super::*;

        static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
        static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

        /// Serializes tests that spawn a held launcher and restores dumpability.
        ///
        /// Recovering a poisoned lock keeps later tests from becoming
        /// `PoisonError`. Re-setting dumpable makes `/proc/<pid>` opens
        /// independent of whether another test already installed core-dump
        /// suppression.
        fn native_test_guard() -> std::sync::MutexGuard<'static, ()> {
            let guard = NATIVE_TEST_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable)
                .expect("restore this process's dumpable behavior for a native test");
            guard
        }

        /// Test-only: restore `PR_SET_DUMPABLE`. Production never does this.
        struct DumpableRestorer {
            previous: rustix::process::DumpableBehavior,
        }

        impl DumpableRestorer {
            fn capture() -> Self {
                Self {
                    previous: rustix::process::dumpable_behavior()
                        .expect("read this process's dumpable behavior"),
                }
            }
        }

        impl Drop for DumpableRestorer {
            fn drop(&mut self) {
                rustix::process::set_dumpable_behavior(self.previous)
                    .expect("restore this process's dumpable behavior");
            }
        }

        struct TestRoot {
            path: PathBuf,
        }

        impl TestRoot {
            fn new() -> Self {
                let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "grok-build-held-launcher-{}-{sequence}",
                    std::process::id()
                ));
                fs::create_dir(&path).unwrap();
                Self { path }
            }
        }

        impl Drop for TestRoot {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }

        struct StagedTestSession {
            root: TestRoot,
            registry: HeldLauncherRegistry,
            procfs: LinuxProcfs,
            expectation: HeldLauncherExpectation<'static>,
            cgroup_path: PathBuf,
        }

        impl StagedTestSession {
            fn stage() -> Self {
                let root = TestRoot::new();
                let cgroup_path = root.path.join("cgroup.procs");
                fs::write(&cgroup_path, b"").unwrap();
                let cgroup_procs = OpenOptions::new().write(true).open(&cgroup_path).unwrap();
                let cgroup_membership = OpenOptions::new().read(true).open(&cgroup_path).unwrap();
                let cgroup_identity = descriptor_identity(&cgroup_procs).unwrap();
                let leaf = File::open(&root.path).unwrap();
                let leaf_identity = descriptor_identity(&leaf).unwrap();
                let procfs = LinuxProcfs::open_authenticated().unwrap();
                let mut registry = HeldLauncherRegistry::default();
                let launch_request_hash: &'static str = "linux-inert-release-test";
                let helper_image = File::open(runner_binary()).unwrap();
                let (pid, process_start_time_ticks) = registry
                    .stage_with_test_helper_image(
                        &procfs,
                        cgroup_procs,
                        cgroup_membership,
                        leaf_identity,
                        cgroup_identity,
                        launch_request_hash,
                        "01".repeat(32),
                        helper_image,
                    )
                    .unwrap();
                let expectation = HeldLauncherExpectation {
                    pid,
                    process_start_time_ticks,
                    launch_request_hash,
                    leaf_identity,
                    cgroup_procs_identity: cgroup_identity,
                };
                Self {
                    root,
                    registry,
                    procfs,
                    expectation,
                    cgroup_path,
                }
            }

            fn attach_and_publish_membership(&mut self) {
                self.registry
                    .self_attach(&self.procfs, self.expectation, b"0\n")
                    .unwrap();
                fs::write(&self.cgroup_path, format!("{}\n", self.expectation.pid)).unwrap();
            }

            // Taken by value so the helper's close point is this call, which
            // the descriptor-reuse tests observe.
            #[expect(
                clippy::needless_pass_by_value,
                reason = "taking custody of the image descriptor fixes its close point, which these descriptor-reuse tests depend on"
            )]
            fn request_for_image(
                &self,
                image: File,
                image_digest: String,
                token: &str,
            ) -> HeldExecRequest {
                let cwd = File::open(&self.root.path).unwrap();
                let cwd_identity = descriptor_identity(&cwd).unwrap();
                let stdin_path = self.root.path.join("target.stdin");
                let stdout_path = self.root.path.join("target.stdout");
                let stderr_path = self.root.path.join("target.stderr");
                fs::write(&stdin_path, INERT_TARGET_STDIN).unwrap();
                fs::write(&stdout_path, b"").unwrap();
                fs::write(&stderr_path, b"").unwrap();
                let target_stdin = OpenOptions::new().read(true).open(stdin_path).unwrap();
                let target_stdout = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(stdout_path)
                    .unwrap();
                let target_stderr = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(stderr_path)
                    .unwrap();
                HeldExecRequest {
                    executable: AuthenticatedExecutableDescriptor::new(
                        image.try_clone().unwrap(),
                        descriptor_identity(&image).unwrap(),
                        image_digest,
                    ),
                    working_directory: AuthenticatedReleaseDescriptor::new(cwd, cwd_identity),
                    target_stdin: authenticated_descriptor(target_stdin),
                    target_stdout: authenticated_descriptor(target_stdout),
                    target_stderr: authenticated_descriptor(target_stderr),
                    argv: vec![
                        "grok-build-inert-target".into(),
                        super::super::INERT_TARGET_ARGUMENT.into(),
                        token.into(),
                        cwd_identity.device.to_string(),
                        cwd_identity.inode.to_string(),
                    ],
                    environment: BTreeMap::from([
                        (
                            "GROK_BUILD_INERT_CWD_DEVICE".into(),
                            cwd_identity.device.to_string(),
                        ),
                        (
                            "GROK_BUILD_INERT_CWD_INODE".into(),
                            cwd_identity.inode.to_string(),
                        ),
                        ("GROK_BUILD_INERT_TOKEN".into(), token.into()),
                    ]),
                    containment: None,
                }
            }

            /// The same release, moved to the contained-command target kind
            /// and carrying a real containment artefact.
            ///
            /// The scope is the release's **own working directory**, passed as
            /// the descriptor this session already holds, and the witness is
            /// `/`: a real object outside every granted scope and outside the
            /// compiled runtime allowlist, so the kernel's answer for it is
            /// the ruleset's other half. The syscall table is the production
            /// network-endpoint table this architecture compiles.
            fn contain(&self, mut request: HeldExecRequest, witness_path: &str) -> HeldExecRequest {
                let scope_directory = File::open(&self.root.path).unwrap();
                let scope_identity = descriptor_identity(&scope_directory).unwrap();
                let witness = File::open(witness_path).unwrap();
                let witness_identity = descriptor_identity(&witness).unwrap();
                let observed = crate::linux_dev_domain::observed_landlock_abi();
                let handled = {
                    use landlock::Access as _;
                    landlock::AccessFs::from_all(observed)
                };
                let mut containment = AuthenticatedContainmentRequest {
                    created_at_kernel_abi: u32::from(crate::linux_dev_domain::abi_level(observed)),
                    handled_access_bits: handled.bits(),
                    scopes: vec![AuthenticatedLandlockScope {
                        object_id: "command-execution-root".to_owned(),
                        resolved_path: self.root.path.display().to_string(),
                        access_bits: handled.bits(),
                        descriptor: AuthenticatedReleaseDescriptor::new(
                            scope_directory,
                            scope_identity,
                        ),
                    }],
                    denial_witness_path: witness_path.to_owned(),
                    denial_witness_identity: witness_identity,
                    committed_ruleset_sha256: String::new(),
                    audit_architecture: audit_architecture_tag(),
                    // The plan commits denied syscalls bytewise sorted by
                    // NAME (`validate_mandatory_kernel_controls`), while
                    // `LINUX_NETWORK_SYSCALLS` is written in number order. A
                    // release that kept the table's order could never carry a
                    // plan-minted `filter_sha256`.
                    denied_syscalls: {
                        let mut denied = crate::linux_dev_domain::LINUX_NETWORK_SYSCALLS
                            .iter()
                            .map(|(name, number)| ((*name).to_owned(), *number))
                            .collect::<Vec<_>>();
                        denied.sort_by(|left, right| left.0.cmp(&right.0));
                        denied
                    },
                    committed_filter_sha256: String::new(),
                    namespace_denied_syscalls:
                        crate::linux_command_plan::committed_namespace_denials(
                            crate::linux_command_plan::HOST_AUDIT_ARCHITECTURE,
                        ),
                    committed_namespace_filter_sha256: String::new(),
                };
                seal_committed_digests(&mut containment);
                request.containment = Some(containment);
                request
            }
        }

        /// This architecture's canonical audit tag, as the plan spells it.
        fn audit_architecture_tag() -> String {
            match crate::linux_dev_domain::LINUX_SECCOMP_TARGET_ARCH {
                seccompiler::TargetArch::aarch64 => "audit-arch-aarch64".to_owned(),
                seccompiler::TargetArch::x86_64 => "audit-arch-x86-64".to_owned(),
                seccompiler::TargetArch::riscv64 => "audit-arch-unmodeled".to_owned(),
            }
        }

        /// Computes the two committed digests the plan would have committed.
        ///
        /// A test that *wrote* them would be writing exactly the fabricated
        /// digest this protocol refuses, so they are produced by the same
        /// canonical functions the launcher checks against, over live
        /// identities and a locally assembled program.
        fn seal_committed_digests(request: &mut AuthenticatedContainmentRequest) {
            let scopes = request
                .scopes
                .iter()
                .map(|scope| ReleaseLandlockScope {
                    object_id: scope.object_id.clone(),
                    resolved_path: scope.resolved_path.clone(),
                    identity: scope.descriptor.expected_identity,
                    access_bits: scope.access_bits,
                })
                .collect();
            let ruleset = ReleaseLandlockRuleset {
                created_at_kernel_abi: request.created_at_kernel_abi,
                handled_access_bits: request.handled_access_bits,
                scopes,
                denial_witness: ReleaseLandlockWitness {
                    resolved_path: request.denial_witness_path.clone(),
                    identity: request.denial_witness_identity,
                },
                ruleset_sha256: String::new(),
            };
            request.committed_ruleset_sha256 = ruleset.canonical_digest();
            let denied = request
                .denied_syscalls
                .iter()
                .map(|(name, number)| ReleaseSeccompSyscall {
                    name: name.clone(),
                    number: *number,
                })
                .collect::<Vec<_>>();
            let program =
                assemble_release_seccomp_program(&denied, &request.audit_architecture).unwrap();
            let filter = ReleaseSeccompFilter {
                audit_architecture: request.audit_architecture.clone(),
                default_action: "kill-process".to_owned(),
                denied_syscalls: denied,
                instruction_count: u64::try_from(program.len()).unwrap(),
                program_sha256: seccomp_program_digest(&program),
                filter_sha256: String::new(),
            };
            request.committed_filter_sha256 = filter.canonical_digest();

            let namespace_program = assemble_release_namespace_program(
                &request.namespace_denied_syscalls,
                &request.audit_architecture,
            )
            .unwrap();
            let namespace_filter = ReleaseSeccompNamespaceFilter {
                audit_architecture: request.audit_architecture.clone(),
                action: "errno-not-implemented".to_owned(),
                denied_syscalls: request.namespace_denied_syscalls.clone(),
                instruction_count: u64::try_from(namespace_program.len()).unwrap(),
                program_sha256: seccomp_program_digest(&namespace_program),
                filter_sha256: String::new(),
            };
            request.committed_namespace_filter_sha256 = namespace_filter.canonical_digest();
        }

        fn authenticated_descriptor(file: File) -> AuthenticatedReleaseDescriptor {
            let identity = descriptor_identity(&file).unwrap();
            AuthenticatedReleaseDescriptor::new(file, identity)
        }

        fn clone_request(request: &HeldExecRequest) -> HeldExecRequest {
            HeldExecRequest {
                executable: AuthenticatedExecutableDescriptor::new(
                    request.executable.file.try_clone().unwrap(),
                    request.executable.expected_identity,
                    request.executable.expected_content_sha256.clone(),
                ),
                working_directory: AuthenticatedReleaseDescriptor::new(
                    request.working_directory.file.try_clone().unwrap(),
                    request.working_directory.expected_identity,
                ),
                target_stdin: AuthenticatedReleaseDescriptor::new(
                    request.target_stdin.file.try_clone().unwrap(),
                    request.target_stdin.expected_identity,
                ),
                target_stdout: AuthenticatedReleaseDescriptor::new(
                    request.target_stdout.file.try_clone().unwrap(),
                    request.target_stdout.expected_identity,
                ),
                target_stderr: AuthenticatedReleaseDescriptor::new(
                    request.target_stderr.file.try_clone().unwrap(),
                    request.target_stderr.expected_identity,
                ),
                argv: request.argv.clone(),
                environment: request.environment.clone(),
                containment: None,
            }
        }

        /// A real static ELF that runs and exits without cooperating.
        ///
        /// The inert fixture `kill(getpid(), SIGSTOP)`s itself unconditionally,
        /// which is the whole contract of `InertInternalTest`. A
        /// `ContainedCommand` release must not depend on that, under strategy
        /// A the controller never sends `CONT` for this kind, so a
        /// contained-command test needs a target that behaves like a real
        /// command: start, run, exit.
        fn non_cooperating_static_target(root: &std::path::Path) -> PathBuf {
            let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("fixtures")
                .join("walking-skeleton-baseline")
                .join("baseline_exit.rs")
                .canonicalize()
                .expect("canonicalize the walking-skeleton baseline source");
            let artefact = root.join("contained-static-target");
            let output = Command::new("rustc")
                .args([
                    "--edition",
                    "2021",
                    "--crate-name",
                    "contained_target",
                    "-O",
                ])
                .args(["-C", "target-feature=+crt-static"])
                .args(["-C", "relocation-model=static"])
                .arg("-o")
                .arg(&artefact)
                .arg(source)
                .output()
                .expect("run rustc to build the non-cooperating static target");
            assert!(
                output.status.success(),
                "building the static target must succeed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            artefact
        }

        fn sealed_image_from_reader(source: File) -> (File, String) {
            sealed_image_from_reader_with_seals(
                source,
                SealFlags::SEAL
                    | SealFlags::SHRINK
                    | SealFlags::GROW
                    | SealFlags::WRITE
                    | SealFlags::FUTURE_WRITE
                    | SealFlags::EXEC,
            )
        }

        fn sealed_image_from_reader_with_seals(
            mut source: File,
            seals: SealFlags,
        ) -> (File, String) {
            let descriptor = rustix::fs::memfd_create(
                "grok-build-inert-image",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::EXEC,
            )
            .unwrap();
            let mut image = File::from(descriptor);
            std::io::copy(&mut source, &mut image).unwrap();
            image.flush().unwrap();
            rustix::fs::fchmod(&image, Mode::from_raw_mode(0o500)).unwrap();
            rustix::fs::fcntl_add_seals(&image, seals).unwrap();
            assert_eq!(rustix::fs::fcntl_get_seals(&image).unwrap(), seals);
            image.seek(StdSeekFrom::Start(0)).unwrap();
            let length = u64::try_from(fstat(&image).unwrap().st_size).unwrap();
            let digest = hash_file_exact(&image, length).unwrap();
            (image, digest)
        }

        fn replace_source_after_open(root: &TestRoot) -> File {
            let source_path = root.path.join("source-runner");
            fs::copy(runner_binary(), &source_path).unwrap();
            fs::set_permissions(&source_path, fs::Permissions::from_mode(0o500)).unwrap();
            let source = File::open(&source_path).unwrap();
            let retained_path = root.path.join("source-runner-retained");
            fs::rename(&source_path, retained_path).unwrap();
            fs::write(&source_path, b"source-path-was-replaced").unwrap();
            source
        }

        fn runner_binary() -> PathBuf {
            if let Some(path) = option_env!("CARGO_BIN_EXE_grok-build-runner") {
                return PathBuf::from(path);
            }
            if let Some(path) = std::env::var_os("CARGO_BIN_EXE_grok-build-runner") {
                return PathBuf::from(path);
            }
            let current = std::env::current_exe().unwrap();
            let profile = current
                .parent()
                .and_then(std::path::Path::parent)
                .expect("unit test executable must be under target/<profile>/deps");
            let candidate = profile.join("grok-build-runner");
            assert!(
                candidate.is_file(),
                "native held-launcher tests require the regular runner binary; use cargo test --all-targets"
            );
            candidate
        }

        #[test]
        fn sealed_descriptor_exec_survives_source_replacement_and_closes_all_fds() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            let source = replace_source_after_open(&staged.root);
            let (image, digest) = sealed_image_from_reader(source);
            let request = staged.request_for_image(image, digest, "source-replaced");
            let observation = staged
                .registry
                .release_inert_target(&staged.procfs, staged.expectation, request)
                .unwrap();
            assert!(observation.same_pid_exec_observed);
            assert!(observation.cgroup_membership_revalidated);
            assert!(observation.target_continued);
            assert!(
                staged
                    .registry
                    .reap_released(observation.pid, HELPER_TIMEOUT)
                    .unwrap()
                    .is_some()
            );
            let stdout = fs::read(staged.root.path.join("target.stdout")).unwrap();
            assert!(
                stdout
                    .windows(b"inert-target-ok:source-replaced\n".len())
                    .any(|window| window == b"inert-target-ok:source-replaced\n")
            );
            let stderr = fs::read(staged.root.path.join("target.stderr")).unwrap();
            assert!(
                stderr
                    .windows(INERT_TARGET_STDERR.len())
                    .any(|window| window == INERT_TARGET_STDERR)
            );
        }

        /// Verifies both control layers and a successful target exec together.
        /// Landlock must report `FullyEnforced` with `no_new_privs`, and the `/` denial
        /// witness must return `EACCES`. The installed filter must match the committed
        /// digest. The target must still execute through `/proc/self/fd/<n>` and produce
        /// its expected output using the fixed runtime read allowlist.
        #[test]
        fn a_contained_command_release_installs_both_layers_and_still_execs_its_sealed_image() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            // A non-cooperating target, because that is what this kind is for.
            // The inert fixture self-stops and would wait forever for a `CONT`
            // the contained-command path deliberately never sends.
            let target = non_cooperating_static_target(&staged.root.path);
            let (image, digest) = sealed_image_from_reader(File::open(&target).unwrap());
            let request = staged.request_for_image(image, digest, "contained-command");
            let request = staged.contain(request, "/");
            {
                let containment = request.containment.as_ref().unwrap();
                println!(
                    "GBDRELEASE contained protocol_version={} abi={} handled_access_bits={:#x} \
                     scopes={} witness={} ruleset={} denied_syscalls={} filter={} \
                     runtime_read={:?} runtime_write={:?}",
                    HELD_LAUNCHER_PROTOCOL_VERSION,
                    containment.created_at_kernel_abi,
                    containment.handled_access_bits,
                    containment.scopes.len(),
                    containment.denial_witness_path,
                    containment.committed_ruleset_sha256,
                    containment.denied_syscalls.len(),
                    containment.committed_filter_sha256,
                    LINUX_LAUNCHER_RUNTIME_READ_SURFACES,
                    LINUX_LAUNCHER_RUNTIME_WRITE_SURFACES,
                );
            }
            let observation = staged
                .registry
                .release_inert_target(&staged.procfs, staged.expectation, request)
                .unwrap();
            assert!(observation.same_pid_exec_observed);
            assert!(observation.cgroup_membership_revalidated);
            assert!(observation.target_continued);
            // Retain the exact exit status for CommandFinished.
            let terminal = staged
                .registry
                .reap_released(observation.pid, HELPER_TIMEOUT)
                .unwrap()
                .expect("the contained command must be reaped within the helper timeout");
            let code = terminal
                .code()
                .expect("the contained command exited rather than being signaled");
            eprintln!("GBDRELEASE contained terminal=Exit({code})");
            assert_ne!(
                code, 0,
                "the static target must report its own non-zero exit status"
            );
            // Release and status-pipe closure establish exec without requiring the
            // target to print a cooperative marker; refusal and exec failure use
            // sequence-3 frames.
        }

        /// The runtime allowlist is closed, and a plan cannot un-grant it.
        ///
        /// This is the control run for the test above, varying exactly one
        /// input: the committed denial witness moves from `/` to `/proc`. If
        /// the runtime surfaces were an open plan field, a plan could simply
        /// decline to grant `/proc` and this release would install and run
        /// (and then fail its own `execve`). Because the allowlist is a
        /// compiled constant the plan cannot reach, `/proc` **is** granted, the
        /// witness therefore opens, and `install_release_containment` refuses
        /// the release by name rather than releasing a target whose policy it
        /// could not honour.
        #[test]
        fn a_release_cannot_witness_a_surface_the_compiled_runtime_allowlist_grants() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            let (image, digest) = sealed_image_from_reader(File::open(runner_binary()).unwrap());
            let request = staged.request_for_image(image, digest, "proc-is-granted");
            let request = staged.contain(request, "/proc");
            let failure = staged
                .registry
                .release_inert_target(&staged.procfs, staged.expectation, request)
                .expect_err("a witness the compiled allowlist grants must refuse the release");
            assert!(
                failure.detail.contains("was not denied by the kernel"),
                "the release was refused for the wrong reason: {}",
                failure.detail
            );
        }

        /// A substituted scope is refused before any layer is installed.
        ///
        /// The committed digest is left exactly as the plan sealed it and only
        /// the descriptor behind one scope is replaced by a second, equally
        /// real directory. The ruleset the controller recomposes from live
        /// `fstat` identities is then not the ruleset the plan committed, and
        /// the release stops at the controller, the helper is never told
        /// anything, so nothing is half-installed.
        #[test]
        fn a_substituted_containment_scope_is_refused_before_any_layer_is_installed() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            let (image, digest) = sealed_image_from_reader(File::open(runner_binary()).unwrap());
            let request = staged.request_for_image(image, digest, "substituted-scope");
            let mut request = staged.contain(request, "/");
            let substitute = staged.root.path.join("second-real-directory");
            fs::create_dir(&substitute).unwrap();
            let substitute = File::open(&substitute).unwrap();
            let substitute_identity = descriptor_identity(&substitute).unwrap();
            {
                let containment = request.containment.as_mut().unwrap();
                containment.scopes[0].descriptor =
                    AuthenticatedReleaseDescriptor::new(substitute, substitute_identity);
            }
            let failure = staged
                .registry
                .release_inert_target(&staged.procfs, staged.expectation, request)
                .expect_err("a substituted scope descriptor must refuse the release");
            assert!(
                failure
                    .detail
                    .contains("is not the ruleset the plan committed"),
                "the release was refused for the wrong reason: {}",
                failure.detail
            );
        }

        /// A filter digest no assembly produces is refused, on both sides.
        ///
        /// The syscall table is edited after the plan sealed its digest, which
        /// is the shape a fabricated artefact takes: the committed
        /// `filter_sha256` covers the table, so an assembly of the edited table
        /// cannot reproduce it.
        #[test]
        fn an_edited_namespace_table_cannot_reproduce_the_committed_filter_digest() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            let (image, digest) = sealed_image_from_reader(File::open(runner_binary()).unwrap());
            let request = staged.request_for_image(image, digest, "edited-namespace");
            let mut request = staged.contain(request, "/");
            {
                let containment = request.containment.as_mut().unwrap();
                containment.namespace_denied_syscalls.pop();
            }
            let failure = staged
                .registry
                .release_inert_target(&staged.procfs, staged.expectation, request)
                .expect_err("an edited namespace table must refuse the release");
            assert!(
                failure
                    .detail
                    .contains("is not the filter the plan committed"),
                "the release was refused for the wrong reason: {}",
                failure.detail
            );
        }

        /// A filter digest no assembly produces is refused, on both sides.
        ///
        /// The syscall table is edited after the plan sealed its digest, which
        /// is the shape a fabricated artefact takes: the committed
        /// `filter_sha256` covers the table, so an assembly of the edited table
        /// cannot reproduce it.
        #[test]
        fn an_edited_syscall_table_cannot_reproduce_the_committed_filter_digest() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            let (image, digest) = sealed_image_from_reader(File::open(runner_binary()).unwrap());
            let request = staged.request_for_image(image, digest, "edited-filter");
            let mut request = staged.contain(request, "/");
            {
                let containment = request.containment.as_mut().unwrap();
                containment.denied_syscalls.pop();
            }
            let failure = staged
                .registry
                .release_inert_target(&staged.procfs, staged.expectation, request)
                .expect_err("an edited syscall table must refuse the release");
            assert!(
                failure
                    .detail
                    .contains("is not the filter the plan committed"),
                "the release was refused for the wrong reason: {}",
                failure.detail
            );
        }

        /// Release must work with a non-dumpable runner. Descriptors are transferred
        /// through `SCM_RIGHTS` because the child cannot reopen the parent's procfs FDs.
        #[test]
        fn sealed_release_survives_the_non_dumpable_runner_profile() {
            let _guard = native_test_guard();
            // Restore dumpability if this test unwinds. Production remains
            // nondumpable throughout the held-launch lifecycle.
            let _dumpable_restorer = DumpableRestorer::capture();
            let suppression = crate::sensitive_output::enforce_core_dump_suppression_v1()
                .expect("core-dump suppression must install and read back");
            assert_eq!(suppression.core_limit_current, 0);
            assert_eq!(suppression.core_limit_maximum, 0);
            assert_eq!(suppression.linux_dumpable_disabled, Some(true));

            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            let source = replace_source_after_open(&staged.root);
            let (image, digest) = sealed_image_from_reader(source);
            let sent_identity = descriptor_identity(&image).unwrap();
            let sent_seals = rustix::fs::fcntl_get_seals(&image).unwrap();
            assert_eq!(sent_seals.bits(), REQUIRED_EXECUTABLE_SEAL_BITS);
            let sent_length = u64::try_from(fstat(&image).unwrap().st_size).unwrap();
            let request = staged.request_for_image(image, digest.clone(), "non-dumpable");

            let observation = staged
                .registry
                .release_inert_target(&staged.procfs, staged.expectation, request)
                .unwrap();
            assert_eq!(observation.executable_identity, sent_identity);
            assert!(observation.same_pid_exec_observed);
            assert!(observation.cgroup_membership_revalidated);
            assert!(observation.target_continued);
            assert!(
                staged
                    .registry
                    .reap_released(observation.pid, HELPER_TIMEOUT)
                    .unwrap()
                    .is_some()
            );
            let stdout = fs::read(staged.root.path.join("target.stdout")).unwrap();
            assert!(
                stdout
                    .windows(b"inert-target-ok:non-dumpable\n".len())
                    .any(|window| window == b"inert-target-ok:non-dumpable\n")
            );

            // The suppression profile is still exactly what was admitted, so
            // nothing in the handoff relaxed it to get the descriptors across.
            let after = crate::sensitive_output::read_core_dump_suppression_v1()
                .expect("core-dump suppression must still read back after the release");
            assert_eq!(after, suppression);
            assert!(sent_length > 0);
            assert_eq!(digest.len(), 64);
        }

        #[test]
        fn invalid_sealed_image_reports_exact_pre_target_exec_failure() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            let invalid_path = staged.root.path.join("invalid-image");
            fs::write(&invalid_path, b"not-an-executable").unwrap();
            let (image, digest) = sealed_image_from_reader(File::open(&invalid_path).unwrap());
            let request = staged.request_for_image(image, digest, "exec-failure");
            let failure = staged
                .registry
                .release_inert_target(&staged.procfs, staged.expectation, request)
                .unwrap_err();
            assert_eq!(failure.certainty, HeldExecCertainty::ExecFailedBeforeTarget);
        }

        /// An invalid sealed image must return the kernel's `ENOEXEC` without starting
        /// a shell. Require pre-target certainty and empty output streams to catch an
        /// `execvp`-style interpreter fallback.
        #[test]
        fn non_executable_sealed_image_runs_no_interpreter_in_the_target_context() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            let invalid_path = staged.root.path.join("invalid-image");
            fs::write(&invalid_path, b"not-an-executable").unwrap();
            let (image, digest) = sealed_image_from_reader(File::open(&invalid_path).unwrap());
            let request = staged.request_for_image(image, digest, "no-interpreter");
            let failure = staged
                .registry
                .release_inert_target(&staged.procfs, staged.expectation, request)
                .unwrap_err();

            // Check output first so an unexpected interpreter is reported directly.
            for stream in ["target.stdout", "target.stderr"] {
                let bytes = fs::read(staged.root.path.join(stream)).unwrap();
                assert!(
                    bytes.is_empty(),
                    "{stream} carried {}; something ran in the target context",
                    String::from_utf8_lossy(&bytes)
                );
            }
            assert_eq!(failure.certainty, HeldExecCertainty::ExecFailedBeforeTarget);
            assert!(
                failure.detail.contains("execve") && failure.detail.contains("os error 8"),
                "release did not fail with the kernel's own ENOEXEC: {}",
                failure.detail
            );
            assert_eq!(
                staged
                    .procfs
                    .recovery_observation(
                        staged.expectation.pid,
                        staged.expectation.process_start_time_ticks,
                    )
                    .unwrap(),
                ProcessRecoveryObservation::Absent
            );
        }

        #[test]
        fn executable_memfd_without_exec_seal_is_rejected_before_release() {
            let _guard = native_test_guard();
            let root = TestRoot::new();
            let source = replace_source_after_open(&root);
            let (image, digest) = sealed_image_from_reader_with_seals(
                source,
                SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
            );
            let descriptor = AuthenticatedExecutableDescriptor::new(
                image.try_clone().unwrap(),
                descriptor_identity(&image).unwrap(),
                digest,
            );

            let failure = executable_binding(&descriptor).unwrap_err();
            assert!(failure.detail.contains("exec"));
        }

        #[test]
        fn pidfd_cancellation_reaps_the_exact_held_process() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            assert!(staged.registry.cancel(staged.expectation).unwrap());
            assert_eq!(
                staged
                    .procfs
                    .recovery_observation(
                        staged.expectation.pid,
                        staged.expectation.process_start_time_ticks,
                    )
                    .unwrap(),
                ProcessRecoveryObservation::Absent
            );
        }

        #[test]
        fn unexpected_resume_without_a_release_frame_exits_and_is_reaped() {
            let _guard = native_test_guard();
            let mut staged = StagedTestSession::stage();
            staged.attach_and_publish_membership();
            let session = staged
                .registry
                .sessions
                .get_mut(&staged.expectation.pid)
                .unwrap();
            pidfd_send_signal(&session.pidfd, Signal::CONT).unwrap();
            // The reap bound must exceed the helper's own timeout.
            assert!(bounded_reap(&mut session.child, HELPER_TIMEOUT * 4).is_some());
            assert_eq!(
                staged
                    .procfs
                    .recovery_observation(
                        staged.expectation.pid,
                        staged.expectation.process_start_time_ticks,
                    )
                    .unwrap(),
                ProcessRecoveryObservation::Absent
            );
        }

        #[test]
        fn close_reuse_substitution_is_rejected_for_executable_cwd_and_stdout() {
            let _guard = native_test_guard();
            let staged = StagedTestSession::stage();
            let source = replace_source_after_open(&staged.root);
            let (image, digest) = sealed_image_from_reader(source);
            let request = staged.request_for_image(image, digest, "fd-reuse");
            let membership = OpenOptions::new()
                .read(true)
                .open(&staged.cgroup_path)
                .unwrap();
            let expected_cgroup = descriptor_identity(&membership).unwrap();
            let specification = request.build_spec(&membership, expected_cgroup).unwrap();

            let other_directory = staged.root.path.join("other-cwd");
            fs::create_dir(&other_directory).unwrap();
            let mut replaced_cwd = clone_request(&request);
            reuse_exact_number(
                &mut replaced_cwd.working_directory.file,
                &File::open(other_directory).unwrap(),
            );
            assert!(
                replaced_cwd
                    .revalidate_against_spec(&membership, expected_cgroup, &specification)
                    .is_err()
            );

            let replacement_stdout = staged.root.path.join("other-stdout");
            fs::write(&replacement_stdout, b"").unwrap();
            let replacement_stdout = OpenOptions::new()
                .read(true)
                .write(true)
                .open(replacement_stdout)
                .unwrap();
            let mut replaced_stdout = clone_request(&request);
            reuse_exact_number(&mut replaced_stdout.target_stdout.file, &replacement_stdout);
            assert!(
                replaced_stdout
                    .revalidate_against_spec(&membership, expected_cgroup, &specification)
                    .is_err()
            );

            let invalid = staged.root.path.join("replacement-image");
            fs::write(&invalid, b"replacement").unwrap();
            let (replacement_image, _) = sealed_image_from_reader(File::open(invalid).unwrap());
            let mut replaced_executable = clone_request(&request);
            reuse_exact_number(&mut replaced_executable.executable.file, &replacement_image);
            assert!(
                replaced_executable
                    .revalidate_against_spec(&membership, expected_cgroup, &specification)
                    .is_err()
            );
        }

        fn reuse_exact_number(slot: &mut File, replacement: &File) {
            let old_number = slot.as_raw_fd();
            let temporary = replacement.try_clone().unwrap();
            let old = std::mem::replace(slot, temporary);
            assert_eq!(old.as_raw_fd(), old_number);
            drop(old);
            let reused = rustix::io::fcntl_dupfd_cloexec(replacement, old_number).unwrap();
            assert_eq!(reused.as_raw_fd(), old_number);
            *slot = File::from(reused);
        }
    }
