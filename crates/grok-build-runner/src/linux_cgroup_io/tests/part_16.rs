    // Increment 1 of the "a command can run contained" path.
    //
    // These drive the production containment and target mints into the real
    // journaled release, `plan_held_release`, `prepare_held_release`,
    // `commit_held_release` on `LinuxCgroupIo`, against a genuine delegated
    // cgroup-v2 leaf, and let a real static ELF execute under the plan's own
    // Landlock ruleset and seccomp filter.
    //
    // What this proves: a command **can** run contained. What it deliberately
    // does not do: name a control, mint a permit, or advance the spine.
    // `enforced_controls()` still answers `{ActiveCanaries}` and all eighteen
    // `permits_execution` constants are still `false`, because nothing here
    // runs on the command's own preflight path.

    #[cfg(target_os = "linux")]
    use crate::linux_containment::{
        LinuxHeldChildReleaseAuthorization, attach_staged_launcher, release_attached_inert_target,
    };

    /// The real runner image, which is the held launcher's own executable.
    ///
    /// Under `cargo test` this process is the harness binary, whose `main` never
    /// dispatches `HELD_LAUNCHER_ARGUMENT`, so the helper must be told which
    /// image to run. Production re-executes `/proc/self/exe` and needs none of
    /// this.
    #[cfg(target_os = "linux")]
    fn contained_release_runner_binary() -> PathBuf {
        if let Some(path) = option_env!("CARGO_BIN_EXE_grok-build-runner") {
            return PathBuf::from(path);
        }
        if let Some(path) = std::env::var_os("CARGO_BIN_EXE_grok-build-runner") {
            return PathBuf::from(path);
        }
        let current = std::env::current_exe().expect("locate this test executable");
        let profile = current
            .parent()
            .and_then(Path::parent)
            .expect("unit test executable must live under target/<profile>/deps");
        let candidate = profile.join("grok-build-runner");
        assert!(
            candidate.exists(),
            "the runner image must be built before this test can stage a helper: {}",
            candidate.display()
        );
        candidate
    }

    /// Everything one contained-command release needs, built from real objects.
    ///
    /// This is the increment's whole point: the scopes are the descriptors the
    /// service already holds on directories it created, the digests are the
    /// plan's own committed artefacts, and the target is a static ELF sealed
    /// into an `MFD_EXEC` memfd. Nothing is opened by path at release time.
    #[cfg(target_os = "linux")]
    struct ContainedReleaseInputs {
        directories: LinuxRetainedPerCommandDirectories,
        workspace: Dir,
        artefacts: LinuxMandatoryControlArtefactsV1,
        audit_architecture: LinuxAuditArchitectureV1,
        root: PathBuf,
        target: PathBuf,
        target_digest: Digest,
    }

    #[cfg(target_os = "linux")]
    impl ContainedReleaseInputs {
        /// Creates this command's retained directories and mints the plan's two
        /// mandatory control artefacts against the running kernel.
        ///
        /// Returns `None` when this host implements no Landlock ABI, which is a
        /// reported absence rather than a skipped assertion: no ruleset can be
        /// created, so no plan could commit one either.
        fn build(state_root: &Path, command_directory: &str, owner_uid: u32) -> Option<Self> {
            let root = state_root.join("contained-release-scratch");
            fs::create_dir_all(&root).expect("create the contained-release scratch root");
            let workspace_path = root.join("workspace");
            fs::create_dir_all(&workspace_path).expect("create the release workspace root");

            let state_root_dir =
                Dir::open_ambient_dir(state_root, ambient_authority()).expect("open state root");
            let workspace = Dir::open_ambient_dir(&workspace_path, ambient_authority())
                .expect("open the release workspace root");
            let directories = create_per_command_retained_directories(
                &state_root_dir,
                &workspace,
                command_directory,
                owner_uid,
            )
            .expect("create this command's retained directories");

            let audit_architecture = match std::env::consts::ARCH {
                "aarch64" => LinuxAuditArchitectureV1::Aarch64,
                _ => LinuxAuditArchitectureV1::X86_64,
            };
            let artefacts =
                match directories.mint_mandatory_control_artefacts(&workspace, audit_architecture) {
                    Ok(artefacts) => artefacts,
                    Err(error) => {
                        println!(
                            "GBDCONTAINED mandatory-controls-unavailable detail={:?} \
                             (this host creates no ruleset, so no release can install one)",
                            error.detail
                        );
                        return None;
                    }
                };

            let target = build_static_target_image(&root);
            let target_digest = Digest::sha256(&fs::read(&target).expect("read the static target"));
            Some(Self {
                directories,
                workspace,
                artefacts,
                audit_architecture,
                root,
                target,
                target_digest,
            })
        }

        /// The release request, with every descriptor minted by production code.
        fn request(&self, argv0: &str) -> HeldExecRequest {
            let containment = self
                .directories
                .authenticated_containment_request(
                    &self.workspace,
                    &self.artefacts,
                    self.audit_architecture,
                )
                .expect("mint the containment request from the retained descriptors");
            let mut source =
                fs::File::open(&self.target).expect("open the static target for sealing");
            let executable = seal_contained_command_target(&mut source, &self.target_digest)
                .expect("seal the static command target into an MFD_EXEC memfd");
            HeldExecRequest {
                executable,
                working_directory: self
                    .directories
                    .authenticated_execution_root()
                    .expect("duplicate the execution root for the release"),
                target_stdin: self.stdio("target.stdin", false),
                target_stdout: self.stdio("target.stdout", true),
                target_stderr: self.stdio("target.stderr", true),
                argv: vec![argv0.to_owned()],
                environment: BTreeMap::new(),
                containment: Some(containment),
            }
        }

        fn stdio(&self, name: &str, writable: bool) -> AuthenticatedReleaseDescriptor {
            let path = self.root.join(name);
            // The file is created first and only then reopened with the access
            // the role needs: a read-only stdin cannot also be the descriptor
            // that creates or truncates it.
            fs::write(&path, b"").expect("create a release stdio file");
            let file = fs::OpenOptions::new()
                .read(true)
                .write(writable)
                .open(&path)
                .expect("open a release stdio file");
            let observed = rustix::fs::fstat(&file).expect("stat a release stdio file");
            AuthenticatedReleaseDescriptor::new(
                file,
                LauncherDescriptorIdentity {
                    device: observed.st_dev,
                    inode: observed.st_ino,
                },
            )
        }
    }

    /// The enforced arm: a real static binary executes under the plan's own
    /// Landlock ruleset and seccomp filter, through the journaled release.
    ///
    /// Four independent things have to hold at once for this to pass, and each
    /// one is worthless without the others:
    ///
    /// * the containment request is built by **production** code from the four
    ///   retained directory descriptors, not opened by path in this test;
    /// * `build_containment_artefact` recomposed the ruleset from those
    ///   descriptors' own `fstat` answers and required it to digest to the
    ///   **plan's** committed `ruleset_sha256`, so the release installs what the
    ///   plan described or nothing at all;
    /// * the target is a sealed `MFD_EXEC` memfd whose bytes were re-read after
    ///   sealing and required to equal the plan's committed digest; and
    /// * the journal reached `Released` through `plan`, `prepare` and `commit`
    ///   on a genuine delegated leaf.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_static_binary_executes_under_the_plans_own_ruleset_and_filter() {
        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let mut backend = live.open_backend();
        let mut domain = live_prepared(
            prepare_domain(&mut backend, live.request()).expect("prepare the live command domain"),
        );
        let leaf_name = domain.leaf_name().to_owned();

        let Some(inputs) = ContainedReleaseInputs::build(
            &live.state_root,
            &leaf_name,
            rustix::process::geteuid().as_raw(),
        ) else {
            let _ = cleanup_domain(&mut backend, &mut domain, MAX_CLEANUP_ATTEMPTS);
            return;
        };

        let request = inputs.request("gbd-contained-static-target");
        {
            let containment = request.containment.as_ref().expect("the release is contained");
            eprintln!(
                "GBDCONTAINED minted leaf={leaf_name} abi={} handled_access_bits={:#x} \
                 scopes={} roles={:?} witness={} ruleset={} denied_syscalls={} filter={}",
                containment.created_at_kernel_abi,
                containment.handled_access_bits,
                containment.scopes.len(),
                containment
                    .scopes
                    .iter()
                    .map(|scope| scope.object_id.as_str())
                    .collect::<Vec<_>>(),
                containment.denial_witness_path,
                containment.committed_ruleset_sha256,
                containment.denied_syscalls.len(),
                containment.committed_filter_sha256,
            );
        }

        // The journal requires the staged launcher's request hash to be this
        // domain's own expected platform binding digest -- a label of the
        // test's choosing is refused by name.
        let binding_digest = domain
            .test_record()
            .native_launch
            .expected_platform_binding_digest
            .as_str()
            .to_owned();
        let identity = domain.leaf_identity().expect("the prepared leaf has an identity");
        let staged = backend
            .stage_held_launcher_with_test_helper_image(
                domain.test_token().expect("the prepared domain holds its token"),
                &leaf_name,
                identity,
                &binding_digest,
                fs::File::open(contained_release_runner_binary()).expect("open the runner image as the helper"),
            )
            .expect("stage the held launcher in the live leaf");
        attach_staged_launcher(&mut backend, &mut domain, staged)
            .expect("attach the staged launcher");

        let authorization = LinuxHeldChildReleaseAuthorization::test_for_record(domain.test_record());
        let observation = release_attached_inert_target(
            &mut backend,
            &mut domain,
            authorization,
            request,
        )
        .expect("release the contained static target through the journaled path");

        assert_eq!(domain.state(), DomainJournalState::Released);
        assert!(observation.same_pid_exec_observed);
        assert!(observation.cgroup_membership_revalidated);
        assert!(observation.target_continued);

        eprintln!(
            "GBDCONTAINED released leaf={leaf_name} pid={} same_pid_exec={} membership_revalidated={} \
             target_continued={} journal_state={:?}",
            observation.pid,
            observation.same_pid_exec_observed,
            observation.cgroup_membership_revalidated,
            observation.target_continued,
            domain.state(),
        );

        let _ = cleanup_domain(&mut backend, &mut domain, MAX_CLEANUP_ATTEMPTS);
        let _ = fs::remove_dir_all(&inputs.root);
    }

    /// Control arm: the same release with one scope descriptor substituted for
    /// another equally real one this service holds.
    ///
    /// Nothing else changes, same plan, same digests, same target, same leaf.
    /// The controller recomposes the ruleset from the descriptors it was handed
    /// and finds it is not the ruleset the plan committed, so the release is
    /// refused before the helper is told anything.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_substituted_scope_descriptor_is_refused_against_the_plans_committed_ruleset() {
        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let mut backend = live.open_backend();
        let mut domain = live_prepared(
            prepare_domain(&mut backend, live.request()).expect("prepare the live command domain"),
        );
        let leaf_name = domain.leaf_name().to_owned();
        let Some(inputs) = ContainedReleaseInputs::build(
            &live.state_root,
            &leaf_name,
            rustix::process::geteuid().as_raw(),
        ) else {
            let _ = cleanup_domain(&mut backend, &mut domain, MAX_CLEANUP_ATTEMPTS);
            return;
        };

        let mut request = inputs.request("gbd-contained-static-target");
        // One input varied: the execution root's committed scope keeps its
        // object id, path and access bits, but is handed the private-temp
        // descriptor instead. Both are real directories this service created.
        {
            let containment = request.containment.as_mut().expect("the release is contained");
            let substitute = inputs
                .directories
                .authenticated_execution_root()
                .expect("duplicate a second real descriptor");
            let victim = containment
                .scopes
                .iter_mut()
                .find(|scope| scope.object_id != EXECUTION_ROOT_OBJECT_ID)
                .expect("the committed ruleset grants more than the execution root");
            victim.descriptor = substitute;
        }

        // The journal requires the staged launcher's request hash to be this
        // domain's own expected platform binding digest -- a label of the
        // test's choosing is refused by name.
        let binding_digest = domain
            .test_record()
            .native_launch
            .expected_platform_binding_digest
            .as_str()
            .to_owned();
        let identity = domain.leaf_identity().expect("the prepared leaf has an identity");
        let staged = backend
            .stage_held_launcher_with_test_helper_image(
                domain.test_token().expect("the prepared domain holds its token"),
                &leaf_name,
                identity,
                &binding_digest,
                fs::File::open(contained_release_runner_binary()).expect("open the runner image as the helper"),
            )
            .expect("stage the held launcher in the live leaf");
        attach_staged_launcher(&mut backend, &mut domain, staged)
            .expect("attach the staged launcher");

        let authorization = LinuxHeldChildReleaseAuthorization::test_for_record(domain.test_record());
        let error =
            release_attached_inert_target(&mut backend, &mut domain, authorization, request)
                .expect_err("a substituted scope must be refused");
        let rendered = format!("{error:?}");
        eprintln!("GBDCONTAINED control substituted-scope refusal={rendered}");
        assert!(
            rendered.contains("scope descriptor identity")
                || rendered.contains("not the ruleset the plan committed"),
            "the refusal did not name the substituted scope: {rendered}"
        );
        assert_ne!(domain.state(), DomainJournalState::Released);

        let _ = cleanup_domain(&mut backend, &mut domain, MAX_CLEANUP_ATTEMPTS);
        let _ = fs::remove_dir_all(&inputs.root);
    }

    /// Control arm: the same static target, sealed against a digest the plan
    /// did not commit.
    ///
    /// This is the substitution the seal exists to catch. The bytes are real
    /// and the seal set is exact; only the expectation differs, and the mint
    /// refuses rather than producing a descriptor for a binary the plan never
    /// measured.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_command_target_that_is_not_the_plans_binary_is_refused_at_the_seal() {
        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let state_root = live.state_root.clone();
        let Some(inputs) = ContainedReleaseInputs::build(
            &state_root,
            &leaf_shaped_name(0x7c),
            rustix::process::geteuid().as_raw(),
        ) else {
            return;
        };

        // Enforced: the plan's own digest seals.
        let mut source = fs::File::open(&inputs.target).expect("open the static target");
        let sealed = seal_contained_command_target(&mut source, &inputs.target_digest)
            .expect("the plan's own binary seals against its own digest");
        drop(sealed);

        // Control: one input varied, a digest of the same bytes plus one.
        let mut bytes = fs::read(&inputs.target).expect("read the static target");
        bytes.push(0);
        let foreign = Digest::sha256(&bytes);
        assert_ne!(foreign, inputs.target_digest);
        let mut source = fs::File::open(&inputs.target).expect("reopen the static target");
        let error = seal_contained_command_target(&mut source, &foreign)
            .expect_err("a target that is not the plan's binary must be refused");
        eprintln!("GBDCONTAINED control foreign-digest refusal={}", error.detail);
        assert!(
            error.detail.contains("while the plan committed"),
            "the refusal did not name the digest mismatch: {}",
            error.detail
        );

        let _ = fs::remove_dir_all(&inputs.root);
    }
