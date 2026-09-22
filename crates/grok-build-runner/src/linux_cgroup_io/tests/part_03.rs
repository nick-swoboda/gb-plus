    // Live command-domain reaping canaries.
    //
    // Every other test in this module drives `LinuxCgroupIo` against a
    // temporary directory that only *looks* like a delegated cgroup. These
    // drive the real `impl CgroupIo for LinuxCgroupIo` against a genuine
    // delegated cgroup-v2 subtree, with real processes inside the domain, and
    // mint the first `ReapedZeroSurvivors` proof this repository has ever
    // produced from live kernel readbacks rather than from a fixture.
    //
    // The delegated root is supplied out of band through
    // `GROK_BUILD_CGROUP_ROOT`, exactly as the twelve-control canary suite
    // takes it. Absent that root the enforced half cannot run, so each test
    // asserts the biconditional the absence canaries established: when a live
    // delegated root is present the full chain must succeed, and when it is
    // not the fixture must refuse to pretend otherwise.

    #[cfg(target_os = "linux")]
    use grok_build_core::CommandDomainCleanupDisposition;

    #[cfg(target_os = "linux")]
    use crate::linux_containment::{
        CgroupCleanupEvidence, LinuxNativeLaunchIdentity, MAX_CLEANUP_ATTEMPTS,
        PrepareDomainOutcome, PreparedDomain, RawCleanupObservation, cleanup_domain, prepare_domain,
    };

    /// Delegated cgroup-v2 subtree plus the private journal root one live
    /// command domain needs, created fresh per test and removed on drop.
    #[cfg(target_os = "linux")]
    pub(crate) struct LiveDelegation {
        pub(crate) state_root: PathBuf,
        /// The service parent this delegation hangs beneath, exposed so a
        /// service-mechanics harness can be composed against the live subtree.
        pub(crate) service_parent_path: PathBuf,
        delegation_path: PathBuf,
        delegation_name: String,
        expected_uid: u32,
    }

    /// One live service backend and the authority its plan was journaled under.
    ///
    /// The grant, the policy and the workspace travel together with the backend
    /// because `service_owned` refuses a handoff journaled under a different
    /// grant or execution policy than the backend was composed from -- so a
    /// caller that builds a command needs the *same* three, not equivalent ones.
    #[cfg(target_os = "linux")]
    pub(crate) struct ComposedServiceMechanics {
        pub(crate) io: LinuxCgroupIo,
        /// Removes its temporary directory on drop, and the journal lives
        /// inside it, so it must outlive the backend.
        pub(crate) fixture: Fixture,
        pub(crate) workspace: PathBuf,
        pub(crate) grant: grok_build_core::IssuedWorkspaceGrant,
        pub(crate) policy: grok_build_core::CompiledExecutionPolicy,
        /// The plan-scoped request `prepare_service_domain` will answer with,
        /// so a caller can name the same effect the journal is about to record.
        pub(crate) request: PrepareDomainRequest,
    }

    #[cfg(target_os = "linux")]
    impl LiveDelegation {
        /// Opens one fresh delegation beneath the out-of-band delegated root.
        ///
        /// Returns `None` when no delegated cgroup-v2 root is available, which
        /// is the only condition under which a caller may skip the enforced
        /// half.
        pub(crate) fn open() -> Option<Self> {
            let root = crate::linux_dev_domain::delegation_root_from_environment()?;
            let expected_uid = rustix::process::geteuid().as_raw();
            let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            // Each live delegation gets its **own service parent** rather than
            // hanging directly off the shared environment root, and the
            // delegation beneath it is named exactly `delegation`.
            //
            // That is what a real installer produces -- a service parent whose
            // `cgroup.procs` is delegated, with the delegation one level below
            // it -- and it is what lets the service-mechanics harness be
            // composed against a live subtree instead of a temp-directory
            // imitation of one. Sharing the environment root as the parent also
            // meant two concurrent live tests were siblings under one parent,
            // which is not the shape production has.
            let service_parent_path = root.join(format!("gbd-live-{}-{unique}", std::process::id()));
            fs::create_dir(&service_parent_path).ok()?;
            // The delegation can only expose controllers its parent delegates
            // downward, so the new intermediate parent has to pass them on.
            fs::write(
                service_parent_path.join("cgroup.subtree_control"),
                b"+memory +pids\n",
            )
            .ok()?;
            let delegation_name = "delegation".to_owned();
            let delegation_path = service_parent_path.join(&delegation_name);
            fs::create_dir(&delegation_path).ok()?;
            // The delegation must expose the controllers a command domain
            // configures. Enabling them here is the installer's job in
            // production; refusing to continue without them keeps the canary
            // from proving anything about a domain that has no ceilings.
            let controllers = fs::read(delegation_path.join("cgroup.controllers")).ok()?;
            let controllers = String::from_utf8(controllers).ok()?;
            for required in ["memory", "pids"] {
                if !controllers.split_ascii_whitespace().any(|one| one == required) {
                    let _ = fs::remove_dir(&delegation_path);
                    return None;
                }
            }
            // The delegation must also *delegate* those controllers downward,
            // because the durable preflight probe inspects a real child leaf
            // and requires every control file a command domain configures.
            // Writing this here is the installer's job in production; the set
            // is exactly the one `prepare_domain` re-enables and reads back.
            fs::write(
                delegation_path.join("cgroup.subtree_control"),
                b"+memory +pids\n",
            )
            .ok()?;
            fs::set_permissions(&delegation_path, fs::Permissions::from_mode(0o755)).ok()?;

            let state_root = std::env::temp_dir().join(format!(
                "gb-live-domain-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&state_root).ok()?;
            let state_root = fs::canonicalize(&state_root).ok()?;
            fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).ok()?;
            let journal_root = state_root.join(SERVICE_COMMAND_JOURNAL_DIRECTORY);
            fs::create_dir(&journal_root).ok()?;
            fs::set_permissions(&journal_root, fs::Permissions::from_mode(0o700)).ok()?;

            Some(Self {
                state_root,
                service_parent_path,
                delegation_path,
                delegation_name,
                expected_uid,
            })
        }

        fn service_parent(&self) -> Dir {
            Dir::open_ambient_dir(&self.service_parent_path, ambient_authority())
                .expect("open delegated service parent")
        }

        fn delegation(&self) -> Dir {
            Dir::open_ambient_dir(&self.delegation_path, ambient_authority())
                .expect("open live delegation")
        }

        fn expectation(&self) -> DelegationRootExpectation {
            let parent = self.service_parent();
            let parent_metadata = parent.dir_metadata().expect("inspect service parent");
            let delegation = self.delegation();
            let metadata = delegation.dir_metadata().expect("inspect delegation");
            DelegationRootExpectation {
                service_parent_identity: cgroup_identity(object_identity(&parent_metadata)),
                delegation_identity: cgroup_identity(object_identity(&metadata)),
                owner_uid: self.expected_uid,
                delegation_mode: OsMetadataExt::mode(&metadata) & 0o7777,
            }
        }

        /// Builds the production backend over the live delegation.
        ///
        /// `mechanics_guard: None` is the module's existing test seam. It does
        /// not weaken any cgroup mechanic: every syscall below this point is
        /// the production one. What it omits is the service-provenance join,
        /// which has no production mint, and this canary therefore claims
        /// nothing about provenance.
        /// Composes the **service-mechanics chain against this live
        /// delegation**, and returns a backend that holds it.
        ///
        /// This is the piece that has never existed. Every link -- plan,
        /// journalled receipt, bootstrap, admission, launch images, setup
        /// descriptors, child-launch closure, lifetime lock -- already had a
        /// production mint and a test that drove it, but only ever against
        /// `Fixture`'s simulated cgroup tree, whose control files are ordinary
        /// files in a temp directory. Composing them while the delegation is a
        /// *real* delegated subtree is what `LinuxCgroupIo::open_service_owned`
        /// needs, and therefore what `service_owned` and `launch` need.
        ///
        /// Only the delegation identities differ from the fixture path: none of
        /// the other links touch a cgroup at all.
        ///
        /// Returns `None` when the chain refuses, with the reason, so a caller
        /// reports a real blocker rather than skipping silently.
        #[allow(
            clippy::too_many_lines,
            reason = "one linear composition: fixture, bootstrap expectation, journal, grant, policy and backend are assembled in the single order `service_owned` requires, and splitting it would hide that order behind call sites"
        )]
        pub(crate) fn open_service_mechanics_backend(
            &self,
        ) -> Result<ComposedServiceMechanics, String> {
            let fixture = Fixture::new().with_live_service_cgroup(&self.service_parent_path);
            let expectation = fixture.bootstrap_expectation();
            let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
            let journaled = journal_linux_production_command_plan(
                plan.clone(),
                fixture.open_service_journal_authority(expectation),
            )
            .map_err(|error| format!("journal the live production command plan: {error:?}"))?;
            // `open_bootstrap_authority` panics on refusal; the fallible form
            // is used here so a live composition reports its blocker instead of
            // aborting the test binary.
            let evidence = fixture.bootstrap_evidence(&plan);
            {
                // Diagnostic: both sides of every field
                // `validate-bootstrap-delegation` compares.
                let delegation = self.delegation();
                let metadata = delegation.dir_metadata().expect("inspect live delegation");
                let journal = &evidence.plan_binding.journal;
                eprintln!(
                    "GBDBOOTSTRAP live_identity={:?} plan_identity={:?}",
                    cgroup_identity(object_identity(&metadata)),
                    journal.delegation_identity,
                );
                eprintln!(
                    "GBDBOOTSTRAP live_uid={} plan_owner_uid={}",
                    OsMetadataExt::uid(&metadata),
                    journal.owner_uid,
                );
                eprintln!(
                    "GBDBOOTSTRAP live_mode={:o} plan_delegation_mode={:o} world_writable={}",
                    OsMetadataExt::mode(&metadata) & 0o7777,
                    journal.delegation_mode,
                    OsMetadataExt::mode(&metadata) & 0o002 != 0,
                );
                let parent = self.service_parent();
                let parent_metadata = parent.dir_metadata().expect("inspect live service parent");
                eprintln!(
                    "GBDBOOTSTRAP live_parent={:?} plan_parent={:?} parent_world_writable={}",
                    cgroup_identity(object_identity(&parent_metadata)),
                    journal.service_parent_identity,
                    OsMetadataExt::mode(&parent_metadata) & 0o002 != 0,
                );
            }
            let bootstrap = fixture
                .open_bootstrap_authority_with_evidence(evidence)
                .map_err(|error| {
                    format!(
                        "open the live bootstrap authority: {} ({:?}) {}",
                        error.operation, error.certainty, error.detail
                    )
                })?;
            let bootstrapped =
                bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap).map_err(
                    |error| format!("bind the live plan to its bootstrap authority: {error:?}"),
                )?;
            let launch_images = Fixture::select_launch_images(fixture.admit(bootstrapped));
            let setup = fixture.bind_setup_descriptors(&plan, launch_images);
            let child = Fixture::bind_child_launch_closure(setup);
            let mechanics = retain_linux_native_service_mechanics_authority(child)
                .map_err(|error| format!("retain the live service mechanics: {error:?}"))?;
            let LinuxNativeServiceMechanicsAuthority {
                plan,
                receipt,
                request,
                journal_authority,
                bootstrap,
                service_process_image,
                launch_images,
                setup_descriptors,
                child_launch_closure,
                lifetime_lock,
            } = mechanics;
            // The authority owns the store the plan was committed into, and
            // that store carries the active-plan state a second `open_*` call
            // cannot reconstruct. Dropping it and reopening was why the
            // preflight reported "no durably committed command plan is active".
            let composed_request = request.clone();
            // Split at consumption: the store the service runs on, and the
            // authentication residual the runtime guard re-validates against.
            // One capability produced one authority; it yields exactly these.
            let (journal, residual) = journal_authority
                .into_journal(self.expectation())
                .map_err(|error| format!("split the journal authority: {error:?}"))?;
            let mechanics_guard = LinuxNativeServiceRuntimeGuard {
                residual,
                plan,
                receipt,
                request,
                bootstrap,
                service_process_image,
                launch_images,
                setup_descriptors,
                child_launch_closure,
                lifetime_lock,
            };
            mechanics_guard
                .validate_retained(&journal)
                .map_err(|error| format!("validate the retained live mechanics: {error:?}"))?;

            // The journal must be the one the plan was written into, which is
            // the fixture's, not the live state root. Two journal roots is what
            // `journal-root-identity` refuses, and correctly: a guard whose
            // receipt lives in one store cannot be restated from another.
            let io = LinuxCgroupIo {
                service_parent: self.service_parent(),
                delegation_name: self.delegation_name.clone(),
                delegation: self.delegation(),
                expectation: self.expectation(),
                journal,
                mechanics_guard: Some(mechanics_guard),
                // The real `grok-build-runner`, because the test binary this
                // runs inside does not speak the held-launcher protocol.
                helper_image_override: Some(
                    std::fs::File::open(contained_release_runner_binary()).map_err(|error| {
                        format!("open the runner image as the composed helper: {error}")
                    })?,
                ),
                leaves: BTreeMap::new(),
                active_probe: None,
                probe_reconciliation_required: false,
                procfs: LinuxProcfs::open_authenticated()
                    .map_err(|error| format!("open authenticated procfs: {error:?}"))?,
                held_launchers: HeldLauncherRegistry::default(),
            };
            // The plan was built from `plan_authority_fixture` over the
            // fixture's own workspace. Reproducing it with the identical
            // arguments yields the identical grant and policy -- issuance is a
            // digest over the contract and the workspace's device/inode, and
            // compilation is a function of the grant and the request -- so the
            // caller can build a command under the **same** authority the plan
            // was journaled under. `service_owned` requires exactly that.
            let workspace = fixture.path.join("workspace");
            let authority = crate::linux_command_plan::tests::plan_authority_fixture(
                crate::wire::RunnerRole::Worker,
                &workspace,
                "/usr/bin/cargo",
                grok_build_core::MutationMode::ShadowWorkspace,
            );

            // The fixture owns a temp directory it removes on drop, and the
            // journal above lives inside it, so it travels with the backend.
            Ok(ComposedServiceMechanics {
                io,
                fixture,
                request: composed_request,
                workspace,
                grant: authority.grant,
                policy: authority.policy,
            })
        }

        pub(crate) fn open_backend(&self) -> LinuxCgroupIo {
            let expectation = self.expectation();
            let state_root = Dir::open_ambient_dir(&self.state_root, ambient_authority())
                .expect("open live service-state root");
            let journal = CanonicalCgroupJournalStore::open_test_retained(
                state_root,
                SERVICE_COMMAND_JOURNAL_DIRECTORY,
                self.expected_uid,
            )
            .expect("open live command journal");
            LinuxCgroupIo {
                service_parent: self.service_parent(),
                delegation_name: self.delegation_name.clone(),
                delegation: self.delegation(),
                expectation,
                journal,
                mechanics_guard: None,
                helper_image_override: None,
                leaves: BTreeMap::new(),
                active_probe: None,
                probe_reconciliation_required: false,
                procfs: LinuxProcfs::open_authenticated().expect("open authenticated procfs"),
                held_launchers: HeldLauncherRegistry::default(),
            }
        }

        pub(crate) fn request(&self) -> PrepareDomainRequest {
            let expectation = self.expectation();
            let grant_hash = Digest::sha256(b"live-command-domain-grant");
            let policy_hash = Digest::sha256(b"live-command-domain-policy");
            PrepareDomainRequest {
                native_launch: LinuxNativeLaunchIdentity {
                    contract_version: CONTRACT_VERSION,
                    attempt_id: "live-attempt-1".into(),
                    native_journal_id: "live-native-journal-1".into(),
                    expected_platform_binding_digest: Digest::sha256(b"live-platform-binding"),
                    sprint_id: "live-sprint-1".into(),
                    launch_id: "live-launch-1".into(),
                    session_id: "live-session-1".into(),
                    cleanup_effect_id: "live-cleanup-effect-1".into(),
                    input_snapshot: Digest::sha256(b"live-input-snapshot"),
                    grant_hash: grant_hash.clone(),
                    policy_hash: policy_hash.clone(),
                    claimed_at_unix_ms: 1_000,
                },
                runner_session_id: "live-session-1".into(),
                effect_id: "live-effect-1".into(),
                grant_hash: grant_hash.to_string(),
                policy_hash: policy_hash.to_string(),
                command_hash: "live-command-hash".into(),
                request_digest: "a1b2c3d4".repeat(8),
                expected_delegation_identity: expectation.delegation_identity,
                expected_owner_uid: self.expected_uid,
                // Eight processes and 256 MiB leave room for a real shell and
                // its two descendants; a 1 MiB ceiling would have the kernel
                // OOM-kill the tree and the canary would then prove nothing
                // about `cgroup.kill`.
                limits: RequestedDomainLimits::derive(8, Some(256 * 1_024 * 1_024))
                    .expect("derive live domain limits"),
            }
        }

        fn leaf_path(&self, leaf_name: &str) -> PathBuf {
            self.delegation_path.join(leaf_name)
        }

        /// A canonical plan rebound to this live delegation.
        ///
        /// Only the installed-state identities are rebound. There is nothing
        /// to rebind for the leaf: schema version 2 does not name one.
        fn command_plan_for_binding(&self) -> ValidatedLinuxProductionCommandPlanV1 {
            let expectation = self.expectation();
            let workspace = self.state_root.join("plan-workspace");
            crate::linux_command_plan::tests::fixture_at_workspace(
                crate::wire::RunnerRole::Worker,
                &workspace,
            )
            .rebind_test_service_journal(&LinuxProductionCommandPlanJournalBindingV1 {
                authenticated_platform_service_digest: Digest::sha256(b"live-leaf-binding-image"),
                service_state_root_identity: self.state_root_identity(),
                singleton_journal_root_identity: self.journal_root_identity(),
                service_parent_identity: expectation.service_parent_identity,
                delegation_identity: expectation.delegation_identity,
                owner_uid: self.expected_uid,
                delegation_mode: expectation.delegation_mode,
            })
            .expect("rebind the plan to the live delegation")
            .rebind_test_cgroup_mount_id(
                retained_directory_mount_id(&self.delegation(), "live-leaf-binding")
                    .expect("read the live delegation's unique mount identity"),
            )
            .expect("rebind the plan to the live delegation mount")
        }

        fn state_root_identity(&self) -> CgroupObjectIdentity {
            let metadata = fs::metadata(&self.state_root).expect("stat the live state root");
            CgroupObjectIdentity {
                device: PortableMetadataExt::dev(&metadata),
                inode: PortableMetadataExt::ino(&metadata),
            }
        }

        fn journal_root_identity(&self) -> CgroupObjectIdentity {
            let metadata = fs::metadata(self.state_root.join(SERVICE_COMMAND_JOURNAL_DIRECTORY))
                .expect("stat the live journal root");
            CgroupObjectIdentity {
                device: PortableMetadataExt::dev(&metadata),
                inode: PortableMetadataExt::ino(&metadata),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for LiveDelegation {
        fn drop(&mut self) {
            if let Ok(entries) = fs::read_dir(&self.delegation_path) {
                for entry in entries.filter_map(Result::ok) {
                    if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                        let _ = fs::write(entry.path().join("cgroup.kill"), b"1\n");
                        let _ = fs::remove_dir(entry.path());
                    }
                }
            }
            let _ = fs::remove_dir(&self.delegation_path);
            let _ = fs::remove_dir_all(&self.state_root);
        }
    }

    /// Reads one leaf control file straight from the filesystem.
    ///
    /// This deliberately bypasses `LinuxCgroupIo` so the assertions about what
    /// the domain contained before cleanup are independent of the code under
    /// test.
    #[cfg(target_os = "linux")]
    fn read_leaf_control(leaf: &Path, name: &str) -> Vec<u8> {
        fs::read(leaf.join(name)).unwrap_or_else(|error| panic!("read {name}: {error}"))
    }

    /// Owns every process placed inside a live domain.
    ///
    /// The occupants are three *unrelated* direct children of this process.
    /// Each moved itself into the domain and then `exec`ed, so none is an
    /// ancestor of another and no orphaned grandchild can be left behind for
    /// some other reaper. Nothing links the three but the cgroup, which is
    /// exactly the property ADR-0006 requires of an accounting domain and
    /// denies to a process group: no single group or session signal could
    /// reach this set.
    #[cfg(target_os = "linux")]
    struct Occupants(Option<Vec<std::process::Child>>);

    #[cfg(target_os = "linux")]
    impl Occupants {
        /// Reaps every occupant on a second thread while `body` runs.
        ///
        /// This is not cosmetic. A process killed by `cgroup.kill` stays
        /// charged to the cgroup until its parent reaps it, and the reaper
        /// under test owns this thread for the whole of `body`. Reaping from a
        /// second thread is what lets the domain actually reach empty; without
        /// it the canary measures this test's own failure to wait rather than
        /// the kernel's kill.
        fn reap_while<T>(mut self, body: impl FnOnce() -> T) -> (T, Vec<std::process::ExitStatus>) {
            let children = self.0.take().expect("occupants were already reaped");
            let reaper = std::thread::spawn(move || {
                children
                    .into_iter()
                    .map(|mut child| child.wait().expect("await one reaped occupant"))
                    .collect::<Vec<_>>()
            });
            let value = body();
            let statuses = reaper.join().expect("join the occupant reaper");
            (value, statuses)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for Occupants {
        fn drop(&mut self) {
            for mut child in self.0.take().unwrap_or_default() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// Puts three unrelated processes inside `leaf` and returns their pids.
    ///
    /// Each process moves *itself* into the domain; nothing here writes another
    /// process's pid, which is the same discipline the production interface
    /// enforces by refusing to expose `cgroup.procs` as a writable leaf file.
    #[cfg(target_os = "linux")]
    fn occupy_domain(leaf: &Path) -> (Occupants, Vec<u32>) {
        let procs = leaf.join("cgroup.procs");
        let occupants = Occupants(Some(
            (0..3)
                .map(|_| {
                    Command::new("/bin/sh")
                        .arg("-c")
                        .arg(format!("echo $$ > {}; exec sleep 300", procs.display()))
                        .spawn()
                        .expect("spawn one live domain occupant")
                })
                .collect(),
        ));

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let members = parse_cgroup_procs(&read_leaf_control(leaf, "cgroup.procs"))
                .expect("parse live membership");
            if members.len() >= 3 {
                return (occupants, members);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "live domain never reached three members; saw {members:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[cfg(target_os = "linux")]
    fn live_prepared(outcome: PrepareDomainOutcome) -> PreparedDomain {
        match outcome {
            PrepareDomainOutcome::Prepared(domain) => *domain,
            PrepareDomainOutcome::ReconciliationRequired(lease) => {
                panic!("live prepare needed reconciliation: {:?}", lease.cause())
            }
            PrepareDomainOutcome::ProbeReconciliationRequired(lease) => {
                panic!("live probe needed reconciliation: {:?}", lease.cause())
            }
        }
    }

    /// The enforced arm: a real occupied cgroup-v2 domain is reaped through the
    /// complete journal state machine and yields a real `ReapedZeroSurvivors`
    /// proof.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_command_domain_reaps_real_processes_into_a_reaped_zero_survivors_proof() {
        let Some(live) = LiveDelegation::open() else {
            // No delegated root: the enforced half is unavailable and the
            // fixture refuses rather than substituting a fake one.
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let mut backend = live.open_backend();
        let mut domain = live_prepared(
            prepare_domain(&mut backend, live.request()).expect("prepare the live command domain"),
        );
        assert_eq!(domain.state(), DomainJournalState::Prepared);

        let leaf = live.leaf_path(domain.leaf_name());
        let (occupant_handle, occupants) = occupy_domain(&leaf);

        // What the domain genuinely contained, read independently of the code
        // under test. Without this the zero below would be vacuous.
        let populated_events = read_leaf_control(&leaf, "cgroup.events");
        let populated_procs = read_leaf_control(&leaf, "cgroup.procs");
        assert!(
            String::from_utf8_lossy(&populated_events).contains("populated 1"),
            "occupied domain did not report populated 1: {}",
            String::from_utf8_lossy(&populated_events)
        );
        assert!(occupants.len() >= 3, "occupants were {occupants:?}");
        // The read-back ceilings are the kernel's, not the request's copy.
        assert_eq!(
            read_leaf_control(&leaf, "pids.max"),
            b"8\n".to_vec(),
            "kernel pids.max readback"
        );
        assert_eq!(
            read_leaf_control(&leaf, "memory.max"),
            b"268435456\n".to_vec(),
            "kernel memory.max readback"
        );

        let (evidence, statuses) = occupant_handle
            .reap_while(|| cleanup_domain(&mut backend, &mut domain, MAX_CLEANUP_ATTEMPTS));
        let evidence = evidence.expect("reap the live command domain");
        assert_eq!(domain.state(), DomainJournalState::Removed);
        assert_eq!(evidence.journal_record.state, DomainJournalState::Removed);

        // The occupants were killed, not merely unobserved. None of the three
        // shares a process group with another, so nothing but the domain could
        // have reached all of them.
        assert_eq!(statuses.len(), 3);
        for status in &statuses {
            assert_eq!(
                std::os::unix::process::ExitStatusExt::signal(status),
                Some(9),
                "occupant was not killed by the domain kill: {status:?}"
            );
        }
        assert!(!leaf.exists(), "reaped leaf remained visible");

        // The endpoint bytes are readbacks: the last attempt's three
        // observations are what the kernel answered after the kill.
        let endpoint = &evidence.observations[evidence.observations.len() - 3..];
        assert_eq!(endpoint[0].file, LeafFile::CgroupEvents);
        assert_eq!(endpoint[1].file, LeafFile::CgroupProcs);
        assert_eq!(endpoint[2].file, LeafFile::CgroupProcs);
        assert!(
            String::from_utf8_lossy(&endpoint[0].bytes).contains("populated 0"),
            "endpoint events were {:?}",
            String::from_utf8_lossy(&endpoint[0].bytes)
        );
        assert!(endpoint[1].bytes.is_empty(), "endpoint procs were not empty");
        assert!(endpoint[2].bytes.is_empty(), "endpoint procs were not empty");
        // Those exact bytes differ from what the same files answered while the
        // domain was occupied, so the evidence cannot be a constant.
        assert_ne!(endpoint[0].bytes, populated_events);
        assert_ne!(endpoint[1].bytes, populated_procs);

        let proof = crate::cleanup_proof::ValidatedCommandDomainCleanupProof::from_linux_candidate(
            &evidence,
        )
        .expect("mint the live cleanup proof");
        // Reported in the same shape as the twelve-control canary so the
        // measurement lands in the run log rather than only in an assertion.
        eprintln!(
            "GBDLIVE ReapedZeroSurvivors leaf={} occupants={occupants:?} drain_attempts={} \
             endpoint_events={:?} endpoint_procs_empty={} evidence_bytes={}",
            evidence.leaf_name,
            evidence.observations.len() / 3,
            String::from_utf8_lossy(&endpoint[0].bytes),
            endpoint[1].bytes.is_empty() && endpoint[2].bytes.is_empty(),
            proof.os_evidence_bytes().len()
        );
        assert_eq!(
            proof.disposition(),
            CommandDomainCleanupDisposition::ReapedZeroSurvivors
        );
        assert_eq!(proof.surviving_processes(), 0);
        assert_eq!(
            proof.backend(),
            crate::cleanup_proof::CommandDomainCleanupBackend::LinuxCgroupV2
        );
        // The canonical bytes carry the kernel's own answer, so a reader can
        // re-derive the endpoint rather than trust the summary.
        let canonical = proof.os_evidence_bytes().to_vec();
        // The canonical envelope is JSON, so the retained bytes appear as a
        // numeric array. Rendering the endpoint read the same way and finding
        // it verbatim proves the proof carries the kernel's own answer rather
        // than a summary of it.
        let rendered = endpoint[0]
            .bytes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            String::from_utf8_lossy(&canonical).contains(&rendered),
            "canonical evidence does not carry the kernel endpoint read"
        );
        let reopened =
            crate::cleanup_proof::ValidatedCommandDomainCleanupProof::readback_with_disposition(
                &canonical,
                proof.os_evidence_digest(),
                crate::cleanup_proof::CommandDomainCleanupBackend::LinuxCgroupV2,
                proof.binding(),
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            )
            .expect("reopen the live cleanup proof");
        assert_eq!(reopened.os_evidence_bytes(), canonical.as_slice());
    }

    /// Control: an externally destroyed leaf must not be mistaken for a reaped
    /// one. Exactly one input differs from the enforced arm — the leaf is gone
    /// before cleanup runs — and an empty read there proves nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_cleanup_refuses_a_leaf_that_vanished_instead_of_reporting_zero_survivors() {
        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let mut backend = live.open_backend();
        let mut domain = live_prepared(
            prepare_domain(&mut backend, live.request()).expect("prepare the live command domain"),
        );
        let leaf = live.leaf_path(domain.leaf_name());
        assert!(leaf.exists());
        fs::remove_dir(&leaf).expect("destroy the live leaf out of band");

        let error = cleanup_domain(&mut backend, &mut domain, MAX_CLEANUP_ATTEMPTS)
            .expect_err("a vanished leaf must not mint a reaping proof");
        assert_ne!(domain.state(), DomainJournalState::Removed);
        let rendered = format!("{error:?}");
        assert!(
            rendered.contains("Reconciliation") || rendered.contains("reconciliation"),
            "unexpected refusal: {rendered}"
        );
    }

    /// Controls: the live proof with exactly one field changed. Two of the
    /// substitutions use bytes the kernel really produced moments earlier for
    /// the same domain, so they are honest reads placed where they do not
    /// belong rather than invented values.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_reaping_evidence_refuses_every_single_field_substitution() {
        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let mut backend = live.open_backend();
        let mut domain = live_prepared(
            prepare_domain(&mut backend, live.request()).expect("prepare the live command domain"),
        );
        let leaf = live.leaf_path(domain.leaf_name());
        let (occupant_handle, _) = occupy_domain(&leaf);
        let occupied_events = read_leaf_control(&leaf, "cgroup.events");
        let occupied_procs = read_leaf_control(&leaf, "cgroup.procs");
        assert!(!occupied_procs.is_empty());

        let (evidence, _) = occupant_handle
            .reap_while(|| cleanup_domain(&mut backend, &mut domain, MAX_CLEANUP_ATTEMPTS));
        let evidence = evidence.expect("reap the live command domain");
        evidence.validate().expect("the enforced evidence validates");

        let last = evidence.observations.len() - 3;

        let mut occupied_endpoint_events = evidence.clone();
        occupied_endpoint_events.observations[last].bytes = occupied_events;
        occupied_endpoint_events
            .journal_record
            .cleanup_observations
            .clone_from(&occupied_endpoint_events.observations);

        let mut occupied_endpoint_procs = evidence.clone();
        occupied_endpoint_procs.observations[last + 2].bytes = occupied_procs;
        occupied_endpoint_procs
            .journal_record
            .cleanup_observations
            .clone_from(&occupied_endpoint_procs.observations);

        let mut survivor = evidence.clone();
        survivor.surviving_processes = 1;

        let mut single_read = evidence.clone();
        single_read.stable_empty_reads = 1;

        let mut wrong_kill = evidence.clone();
        wrong_kill.kill_value = b"0\n".to_vec();
        wrong_kill.journal_record.kill_value = Some(b"0\n".to_vec());

        let mut not_removed = evidence.clone();
        not_removed.journal_record.state = DomainJournalState::RemoveIntended;

        let mut truncated = evidence.clone();
        truncated.observations.truncate(last);
        truncated
            .journal_record
            .cleanup_observations
            .clone_from(&truncated.observations);

        for (label, candidate) in [
            ("endpoint events read while occupied", occupied_endpoint_events),
            ("endpoint procs read while occupied", occupied_endpoint_procs),
            ("one surviving process", survivor),
            ("one stable empty read", single_read),
            ("a kill value that is not 1", wrong_kill),
            ("a record short of Removed", not_removed),
            ("a truncated observation sequence", truncated),
        ] {
            assert!(
                candidate.validate().is_err(),
                "{label} was accepted by the evidence validator"
            );
            assert!(
                crate::cleanup_proof::ValidatedCommandDomainCleanupProof::from_linux_candidate(
                    &candidate
                )
                .is_err(),
                "{label} minted a cleanup proof"
            );
        }
    }

    /// The reaping arm and the absence arm remain disjoint on live bytes, not
    /// only on fixtures: a real reaping proof must not satisfy the disposition
    /// the no-domain arm exists to carry.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_reaping_proof_cannot_pass_as_a_no_domain_proof() {
        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let mut backend = live.open_backend();
        let mut domain = live_prepared(
            prepare_domain(&mut backend, live.request()).expect("prepare the live command domain"),
        );
        let leaf = live.leaf_path(domain.leaf_name());
        let (occupant_handle, _) = occupy_domain(&leaf);
        let (evidence, _) = occupant_handle
            .reap_while(|| cleanup_domain(&mut backend, &mut domain, MAX_CLEANUP_ATTEMPTS));
        let evidence = evidence.expect("reap the live command domain");

        let proof = crate::cleanup_proof::ValidatedCommandDomainCleanupProof::from_linux_candidate(
            &evidence,
        )
        .expect("mint the live cleanup proof");
        assert!(
            crate::cleanup_proof::ValidatedCommandDomainCleanupProof::readback_with_disposition(
                proof.os_evidence_bytes(),
                proof.os_evidence_digest(),
                crate::cleanup_proof::CommandDomainCleanupBackend::LinuxCgroupV2,
                proof.binding(),
                CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
            )
            .is_err(),
            "a reaping proof satisfied the no-domain disposition"
        );
    }

    /// A helper for the observation shape assertions above, kept honest by
    /// pinning the canonical triple the kernel reads must arrive in.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_reaping_observations_arrive_as_canonical_events_procs_procs_triples() {
        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let mut backend = live.open_backend();
        let mut domain = live_prepared(
            prepare_domain(&mut backend, live.request()).expect("prepare the live command domain"),
        );
        let leaf = live.leaf_path(domain.leaf_name());
        let (occupant_handle, _) = occupy_domain(&leaf);
        let (evidence, _) = occupant_handle
            .reap_while(|| cleanup_domain(&mut backend, &mut domain, MAX_CLEANUP_ATTEMPTS));
        let evidence = evidence.expect("reap the live command domain");

        assert_eq!(evidence.observations.len() % 3, 0);
        for (index, chunk) in evidence.observations.chunks_exact(3).enumerate() {
            let attempt = u8::try_from(index + 1).expect("attempt fits");
            assert_eq!(chunk[0].file, LeafFile::CgroupEvents);
            assert_eq!(chunk[1].file, LeafFile::CgroupProcs);
            assert_eq!(chunk[2].file, LeafFile::CgroupProcs);
            for (offset, observation) in chunk.iter().enumerate() {
                assert_eq!(observation.attempt, attempt);
                let expected = u32::try_from(index * 3 + offset + 1).expect("sequence fits");
                assert_eq!(observation.sequence, expected);
            }
        }
        let _: &CgroupCleanupEvidence = &evidence;
        let _: &[RawCleanupObservation] = &evidence.observations;
    }

    // Route 1 increment 4: the leaf the plan does not name, bound after the
    // leaf exists, from a live read of it.
    //
    // Schema version 1 carried four leaf identities that nothing produced and
    // nothing checked against a leaf: the test rebind invented them as
    // `delegation_identity.inode + 1..=4`. This is what replaced them. The
    // plan states only the grammar and the creation rule; the identity below
    // came from `openat`/`statx` on a leaf `prepare_domain` really created.

    /// The enforced half: a real prepared leaf is observed and bound, and the
    /// binding is refused for every real object in the wrong role.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear canary keeps the live binding and every single-input control visible together"
    )]
    fn live_prepared_leaf_binds_to_a_plan_that_named_no_leaf() {
        use std::os::unix::fs::MetadataExt as StdMetadataExt;

        let Some(live) = LiveDelegation::open() else {
            assert!(crate::linux_dev_domain::delegation_root_from_environment().is_none());
            return;
        };
        let mut backend = live.open_backend();
        let domain = live_prepared(
            prepare_domain(&mut backend, live.request()).expect("prepare the live command domain"),
        );
        let leaf_name = domain.leaf_name().to_owned();
        let leaf_path = live.leaf_path(&leaf_name);
        let delegation = live.delegation();

        // The name is a value the plan could not have chosen: it did not exist
        // until `prepare_domain` drew it inside the delegation lock.
        assert!(leaf_name.starts_with("gb-"));
        assert_eq!(leaf_name.len(), 3 + 64);

        let observation =
            observe_prepared_command_domain_leaf(&delegation, &leaf_name, "live-leaf-binding")
                .expect("observe the prepared leaf");

        // Independent of the mint: stat the same paths through `std::fs`.
        let leaf_metadata = std::fs::metadata(&leaf_path).expect("independently stat the leaf");
        let observed_leaf = observation.leaf.kernel_observation();
        assert_eq!(observed_leaf.device_id, StdMetadataExt::dev(&leaf_metadata));
        assert_eq!(observed_leaf.inode, StdMetadataExt::ino(&leaf_metadata));
        assert_eq!(observed_leaf.mode, StdMetadataExt::mode(&leaf_metadata));
        assert_eq!(observed_leaf.owner_uid, StdMetadataExt::uid(&leaf_metadata));
        assert_eq!(observed_leaf.owner_gid, StdMetadataExt::gid(&leaf_metadata));
        assert_eq!(
            observed_leaf.link_count,
            StdMetadataExt::nlink(&leaf_metadata)
        );
        assert_eq!(observation.control_files.len(), 3);
        for control in &observation.control_files {
            let path = leaf_path.join(control.file.name());
            let metadata = std::fs::metadata(&path).expect("independently stat a control file");
            let observed = control.identity.kernel_observation();
            assert_eq!(observed.device_id, StdMetadataExt::dev(&metadata));
            assert_eq!(observed.inode, StdMetadataExt::ino(&metadata));
            assert_eq!(observed.owner_uid, StdMetadataExt::uid(&metadata));
        }

        // A plan rebound to this delegation. It names no leaf; the binding
        // below is the only place a leaf identity enters.
        let plan = live.command_plan_for_binding();
        let encoded = std::str::from_utf8(plan.canonical_bytes()).expect("plan is JSON");
        assert!(
            encoded.contains("not_named_by_the_plan_bound_after_preparation_from_a_live_read"),
            "the plan must state that it names no leaf"
        );
        assert!(
            !encoded.contains(&leaf_name),
            "the plan must not contain the leaf name"
        );

        let journal_identity = domain
            .leaf_identity()
            .expect("the prepared domain committed a leaf identity");
        let bound = plan
            .bind_prepared_command_domain_leaf(&leaf_name, journal_identity, &observation)
            .expect("bind the plan to the leaf that was actually prepared");
        assert_eq!(bound.leaf_name(), leaf_name);
        assert_eq!(bound.leaf_identity(), journal_identity);
        assert_eq!(bound.plan_digest(), plan.plan_digest());
        assert_eq!(bound.control_files().len(), 3);

        println!(
            "GBDLEAF bound leaf={leaf_name} identity={}:{} procs={} events={} kill={}",
            journal_identity.device,
            journal_identity.inode,
            bound.control_files()[0].identity.kernel_observation().inode,
            bound.control_files()[1].identity.kernel_observation().inode,
            bound.control_files()[2].identity.kernel_observation().inode,
        );

        // A measured fact that is part of why the plan cannot name a leaf: a
        // delegation with any child at all refuses to prepare. `mkdir` of a
        // predictable name by anyone able to write the delegation is therefore
        // a denial of the whole command domain, not a race to lose.
        drop(backend);
        let mut blocked_request = live.request();
        blocked_request.effect_id = "live-effect-blocked".into();
        blocked_request.native_launch.cleanup_effect_id = "live-cleanup-effect-blocked".into();
        let mut blocked_backend = live.open_backend();
        let blocked = prepare_domain(&mut blocked_backend, blocked_request)
            .expect_err("a delegation that already has a leaf must refuse to prepare");
        assert!(
            format!("{blocked:?}").contains("UnexpectedChildren"),
            "expected an unexpected-children refusal, got {blocked:?}"
        );
        drop(blocked_backend);

        // Control: a real second leaf, prepared by the same production path on
        // the same cgroup mount with the same owner, in its own delegation
        // because of the fact just measured. It is a genuine command-domain
        // leaf in the wrong role, not an invented identity.
        let Some(other) = LiveDelegation::open() else {
            panic!("the delegated root vanished between two opens")
        };
        let mut other_backend = other.open_backend();
        let second = live_prepared(
            prepare_domain(&mut other_backend, other.request())
                .expect("prepare a second live command domain"),
        );
        let second_name = second.leaf_name().to_owned();
        assert_ne!(second_name, leaf_name);
        let second_observation = observe_prepared_command_domain_leaf(
            &other.delegation(),
            &second_name,
            "live-leaf-binding",
        )
        .expect("observe the second prepared leaf");
        assert_eq!(
            second_observation.leaf.kernel_observation().device_id,
            observation.leaf.kernel_observation().device_id,
            "the control leaf must be on the same cgroup mount to be a real cross"
        );
        assert!(
            plan.bind_prepared_command_domain_leaf(
                &leaf_name,
                journal_identity,
                &second_observation
            )
            .is_err(),
            "another real leaf was bound as this episode's leaf"
        );
        assert!(
            plan.bind_prepared_command_domain_leaf(
                &second_name,
                journal_identity,
                &second_observation
            )
            .is_err(),
            "a real leaf was bound against another episode's committed identity"
        );

        // Control: the delegation itself, a real cgroup-v2 directory on the
        // same mount with the same owner, substituted for the leaf.
        let mut crossed_leaf = observation.clone();
        crossed_leaf.leaf = observe_prepared_delegation_identity(&delegation);
        assert!(
            plan.bind_prepared_command_domain_leaf(&leaf_name, journal_identity, &crossed_leaf)
                .is_err(),
            "the delegation itself was bound as a leaf"
        );

        // Control: the leaf directory's own identity substituted for a control
        // file -- a real object on the same mount, in the wrong role.
        let mut crossed_control = observation.clone();
        crossed_control.control_files[2].identity = observation.leaf.clone();
        assert!(
            plan.bind_prepared_command_domain_leaf(&leaf_name, journal_identity, &crossed_control)
                .is_err(),
            "a cgroup directory was bound as cgroup.kill"
        );

        // Control: two control files aliasing one real inode.
        let mut aliased = observation.clone();
        aliased.control_files[2].identity = observation.control_files[0].identity.clone();
        assert!(
            plan.bind_prepared_command_domain_leaf(&leaf_name, journal_identity, &aliased)
                .is_err(),
            "two control-file roles aliased one inode"
        );

        // Control: a name that is not one `prepare_domain` could mint. The
        // mint refuses before it opens anything.
        assert!(
            observe_prepared_command_domain_leaf(
                &delegation,
                &live.delegation_name,
                "live-leaf-binding"
            )
            .is_err(),
            "a non-domain name was observed as a leaf"
        );
        assert!(
            observe_prepared_command_domain_leaf(
                &delegation,
                "gb-not-sixty-four-hex",
                "live-leaf-binding"
            )
            .is_err()
        );

        // And the unvaried inputs still bind, so every refusal above is
        // attributable to the one value that changed.
        plan.bind_prepared_command_domain_leaf(&leaf_name, journal_identity, &observation)
            .expect("the unvaried binding still succeeds");
    }

    /// The delegation root read the same way a leaf is, so a control can put a
    /// real cgroup directory in the leaf's place.
    #[cfg(target_os = "linux")]
    fn observe_prepared_delegation_identity(delegation: &Dir) -> LinuxRetainedObjectIdentityV1 {
        let metadata = delegation.dir_metadata().expect("stat the live delegation");
        LinuxRetainedObjectIdentityV1::from_kernel_observation(
            "command-domain-leaf",
            LinuxRetainedObjectKindV1::CgroupDirectory,
            LinuxKernelObjectObservationV1 {
                device_id: PortableMetadataExt::dev(&metadata),
                inode: PortableMetadataExt::ino(&metadata),
                mount_id: retained_directory_mount_id(delegation, "live-leaf-binding")
                    .expect("delegation mount id"),
                mode: OsMetadataExt::mode(&metadata),
                owner_uid: OsMetadataExt::uid(&metadata),
                owner_gid: OsMetadataExt::gid(&metadata),
                link_count: PortableMetadataExt::nlink(&metadata),
                byte_length: None,
            },
        )
        .expect("mint the delegation identity")
    }
