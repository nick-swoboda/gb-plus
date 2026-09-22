    // -----------------------------------------------------------------------
    // The delegated-cgroup bootstrap probe, run live against real cgroup-v2
    // objects.
    //
    // The enforced and control arms differ in exactly one input: the
    // `cgroup.subtree_control` of the directory the probe is pointed at. Both
    // are real cgroups, created the same way, on the same filesystem, with the
    // same owner and mode; one has `memory pids` enabled for its children and
    // the other has nothing enabled. That single difference is what decides
    // whether a leaf created underneath carries `pids.max` at all, so the
    // probe's verdict is attributable to delegation and to nothing else.
    //
    // **The unavailable arm is enforced, never skipped.** Under the default
    // gate container `/sys/fs/cgroup` is mounted read-only, so no leaf can be
    // created; that is reported by errno and the arm returns without touching
    // anything. It is not a pass, and `./scripts/linux-verify.sh` green does
    // not cover this measurement.
    // -----------------------------------------------------------------------

    /// The two staged cgroups this test probes, and the process migration the
    /// kernel's no-internal-process rule forces in order to create them.
    ///
    /// A cgroup that holds processes directly cannot enable controllers for its
    /// children. The container's cgroup-namespace root holds this test process,
    /// so the staging moves this process into a leaf of its own first, and
    /// [`Drop`] moves it back and removes everything it created — including
    /// after a panic.
    #[cfg(target_os = "linux")]
    struct StagedBootstrapCgroupTopology {
        root: Dir,
        migrated: bool,
    }

    #[cfg(target_os = "linux")]
    impl StagedBootstrapCgroupTopology {
        const HOST: &'static str = "gbd-bootstrap-probe-host";
        const DELEGATION: &'static str = "gbd-bootstrap-probe-delegation";
        const CONTROL: &'static str = "gbd-bootstrap-probe-control";
        const ENABLE: &[u8] = b"+memory +pids\n";
        const DISABLE: &[u8] = b"-memory -pids\n";

        /// Moves every process out of `from` and into `to`.
        ///
        /// A numeric-PID write, which production code deliberately never
        /// performs — only the fixed held launcher self-attaches there. This is
        /// test staging on a container the test owns, not an authority path,
        /// and it exists because the kernel's no-internal-process rule leaves
        /// no other way to obtain a delegated cgroup on this host. The list is
        /// re-read between passes because it moves while it is being drained.
        fn drain(from: &Dir, to: &Dir) {
            for _pass in 0..8 {
                let Ok(bytes) =
                    read_control_file(from, LeafFile::CgroupProcs.name(), MAX_CGROUP_PROCS_BYTES)
                else {
                    return;
                };
                if bytes.is_empty() {
                    return;
                }
                for line in String::from_utf8_lossy(&bytes)
                    .lines()
                    .filter(|line| !line.is_empty())
                {
                    drop(write_control_file(
                        to,
                        LeafFile::CgroupProcs.name(),
                        format!("{line}\n").as_bytes(),
                    ));
                }
            }
        }

        fn stage() -> Option<Self> {
            let root = match Dir::open_ambient_dir("/sys/fs/cgroup", ambient_authority()) {
                Ok(root) => root,
                Err(error) => {
                    println!(
                        "GBDCGROUP cgroup-root-unavailable errno={:?} probe=not-run",
                        error.raw_os_error()
                    );
                    return None;
                }
            };
            match filesystem_magic(&root) {
                Ok(magic) if magic == CGROUP2_SUPER_MAGIC => {}
                other => {
                    println!("GBDCGROUP not-cgroup2 magic={other:?} probe=not-run");
                    return None;
                }
            }
            // The first write. It is what classifies this host: a read-only
            // cgroup mount refuses here and nothing has been changed yet.
            if let Err(error) = root.create_dir(Self::HOST)
                && error.kind() != io::ErrorKind::AlreadyExists
            {
                println!(
                    "GBDCGROUP delegation-unavailable errno={:?} detail={error} probe=not-run \
                     (this container cannot create a cgroup, so no bootstrap evidence can exist here)",
                    error.raw_os_error()
                );
                return None;
            }
            let mut staged = Self {
                root,
                migrated: false,
            };
            let host = staged
                .root
                .open_dir_nofollow(Self::HOST)
                .expect("the staged host cgroup opens");
            // Every process in the namespace root, not only this one. The
            // kernel refuses to enable controllers for the children of a cgroup
            // that holds any process directly, and a `cargo test` container
            // holds at least its shell, cargo, and this harness.
            staged.migrated = true;
            Self::drain(&staged.root, &host);
            write_control_file(
                &staged.root,
                DelegationFile::SubtreeControl.name(),
                Self::ENABLE,
            )
            .expect("the cgroup-namespace root enables memory and pids for its children");
            for name in [Self::DELEGATION, Self::CONTROL] {
                match staged.root.create_dir(name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("stage {name}: {error}"),
                }
            }
            // The one input that differs between the two arms.
            let delegation = staged
                .root
                .open_dir_nofollow(Self::DELEGATION)
                .expect("the staged delegation opens");
            write_control_file(
                &delegation,
                DelegationFile::SubtreeControl.name(),
                Self::ENABLE,
            )
            .expect("the staged delegation enables memory and pids for its children");
            Some(staged)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for StagedBootstrapCgroupTopology {
        fn drop(&mut self) {
            for name in [Self::DELEGATION, Self::CONTROL] {
                drop(self.root.remove_dir(name));
            }
            drop(write_control_file(
                &self.root,
                DelegationFile::SubtreeControl.name(),
                Self::DISABLE,
            ));
            if self.migrated
                && let Ok(host) = self.root.open_dir_nofollow(Self::HOST)
            {
                Self::drain(&host, &self.root);
            }
            drop(self.root.remove_dir(Self::HOST));
        }
    }

    /// Opens one staged cgroup exactly as
    /// `LinuxNativeServiceBootstrapCapabilities::open_retained` opens the real
    /// delegation.
    #[cfg(target_os = "linux")]
    fn retain_staged_delegation(root: &Dir, name: &str) -> (Dir, File, File, File) {
        let delegation = root
            .open_dir_nofollow(name)
            .expect("the staged delegation opens");
        let open = |file: &str| {
            open_retained_bootstrap_file(&delegation, file, "open-bootstrap-cgroup-controllers")
                .expect("a staged delegation control file opens")
                .0
        };
        let controllers = open(DelegationFile::Controllers.name());
        let subtree_control = open(DelegationFile::SubtreeControl.name());
        let procs = open(DelegationFile::Procs.name());
        (delegation, controllers, subtree_control, procs)
    }

    /// The delegated-cgroup probe proves a delegation is usable, and refuses a
    /// cgroup that enables nothing for its children.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_live_delegated_cgroup_bootstrap_probe_refuses_an_undelegated_parent() {
        let Some(staged) = StagedBootstrapCgroupTopology::stage() else {
            return;
        };

        let (delegation, controllers, subtree_control, procs) = retain_staged_delegation(
            &staged.root,
            StagedBootstrapCgroupTopology::DELEGATION,
        );
        let enforced = probe_delegated_cgroup(
            &delegation,
            StagedBootstrapCgroupTopology::DELEGATION,
            &controllers,
            &subtree_control,
            &procs,
        )
        .expect("a delegated cgroup admits the bootstrap probe");
        println!(
            "GBDCGROUP enforced controllers={:?} subtree={:?} procs={:?} probe_passed={} digest={}",
            enforced.controllers_readback,
            enforced.subtree_control_readback,
            enforced.cgroup_procs_readback,
            enforced.active_probe_passed,
            enforced.active_probe_result_digest.as_str()
        );
        assert!(enforced.active_probe_passed);
        assert!(enforced.cgroup_procs_readback.is_empty());
        assert!(!digest_is_zero(&enforced.active_probe_result_digest));
        assert_ne!(
            enforced.active_probe_result_digest,
            Digest::sha256(CGROUP_BOOTSTRAP_PROBE_CONTRACT),
            "a result digest that restated the contract would be a constant, not a measurement"
        );
        // The transient leaf is gone: the probe removed what it created.
        assert!(
            delegation
                .open_dir_nofollow(format!(
                    "{CGROUP_BOOTSTRAP_PROBE_LEAF_PREFIX}{}",
                    std::process::id()
                ))
                .is_err(),
            "the active probe left its leaf behind"
        );

        // The control. One input moves: this cgroup's `cgroup.subtree_control`
        // is empty, so a leaf created underneath carries no controller
        // interface file at all. Everything else — the filesystem, the parent,
        // the owner, the mode, the probe code — is identical.
        let (control_delegation, control_controllers, control_subtree, control_procs) =
            retain_staged_delegation(&staged.root, StagedBootstrapCgroupTopology::CONTROL);
        let refusal = probe_delegated_cgroup(
            &control_delegation,
            StagedBootstrapCgroupTopology::CONTROL,
            &control_controllers,
            &control_subtree,
            &control_procs,
        )
        .expect_err("a cgroup that enables no controller is not a usable delegation");
        println!("GBDCGROUP control detail={:?}", refusal.detail);
        assert_eq!(refusal.operation, "probe-bootstrap-delegated-cgroup");
        assert_eq!(refusal.certainty, EffectCertainty::NotApplied);
        assert!(
            refusal.detail.contains("enables no controller"),
            "the refusal is not the delegation clause: {refusal:?}"
        );

        // The live measurement is admissible against the untouched validator.
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let mut evidence = fixture.bootstrap_evidence(&plan);
        evidence.cgroup = enforced;
        validate_service_bootstrap_evidence(&evidence)
            .expect("the live delegated-cgroup probe binds the plan's controller requirement");

        assert!(!LinuxNativeServiceBootstrapAuthority::permits_execution());
    }

    /// All four host probes, measured live in one run, together satisfy
    /// `validate_service_bootstrap_evidence`.
    ///
    /// This is the statement the previous increment could not make: the
    /// validator admits an evidence value only when **every** probe result
    /// binds the plan, so four probes that each pass in isolation still prove
    /// nothing about whether a production bootstrap authority can exist. Here
    /// the delegated cgroup, the admitted Bubblewrap image's self-report, the
    /// Landlock boundary and the seccomp kill are all read from this host in
    /// one run, assembled into one evidence value, and submitted together.
    ///
    /// Every layer this host does not provide is reported and the arm returns;
    /// none is substituted.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_four_live_bootstrap_probes_together_satisfy_the_evidence_validator() {
        use crate::linux_command_plan::ADMITTED_BUBBLEWRAP_IMAGE_V1;

        let admitted = ADMITTED_BUBBLEWRAP_IMAGE_V1;
        let resolved = Path::new(admitted.resolved_path);
        let bubblewrap_parent = match Dir::open_ambient_dir(
            resolved.parent().expect("the admitted image has a parent"),
            ambient_authority(),
        ) {
            Ok(directory) => directory,
            Err(error) => {
                println!("GBDEVIDENCE bubblewrap-parent-unavailable errno={:?} probe=not-run",
                    error.raw_os_error());
                return;
            }
        };
        let name = resolved
            .file_name()
            .and_then(|name| name.to_str())
            .expect("the admitted image has a UTF-8 filename");
        let Ok((held, _identity)) =
            open_retained_bootstrap_file(&bubblewrap_parent, name, "open-bootstrap-bubblewrap")
        else {
            println!(
                "GBDEVIDENCE bubblewrap-absent path={} probe=not-run \
                 (this image admits no Bubblewrap, so no bootstrap evidence can exist here)",
                admitted.resolved_path
            );
            return;
        };
        let Some(staged) = StagedBootstrapCgroupTopology::stage() else {
            return;
        };

        let (delegation, controllers, subtree_control, procs) = retain_staged_delegation(
            &staged.root,
            StagedBootstrapCgroupTopology::DELEGATION,
        );
        let cgroup = probe_delegated_cgroup(
            &delegation,
            StagedBootstrapCgroupTopology::DELEGATION,
            &controllers,
            &subtree_control,
            &procs,
        )
        .expect("the delegated-cgroup probe completes");
        let bubblewrap = probe_retained_bubblewrap_version(&held)
            .expect("the admitted Bubblewrap image reports its version");
        // The ruleset and the filter the probes install are the plan's, and the
        // scope is still the directory that holds the admitted launcher — a
        // real directory this suite has already authenticated a file inside.
        let ruleset = live_landlock_ruleset(
            resolved
                .parent()
                .and_then(Path::to_str)
                .expect("the admitted image has a UTF-8 parent"),
            "/",
        );
        let filter = mint_command_seccomp_filter(
            LIVE_PROBE_AUDIT_ARCHITECTURE,
            "probe-bootstrap-seccomp",
        )
        .expect("this architecture has a compiled syscall table");
        let landlock = match probe_landlock_full_enforcement(&ruleset) {
            Ok(probe) => probe,
            Err(error) if bootstrap_probe_layer_is_absent(&error) => {
                println!("GBDEVIDENCE landlock-unavailable detail={:?} probe=not-run", error.detail);
                return;
            }
            Err(error) => panic!("the Landlock bootstrap probe refused: {error:?}"),
        };
        let seccomp = match probe_seccomp_forbidden_syscall(
            &filter,
            SECCOMP_BOOTSTRAP_PROBE_FORBIDDEN_TARGET,
        ) {
            Ok(probe) => probe,
            Err(error) if bootstrap_probe_layer_is_absent(&error) => {
                println!("GBDEVIDENCE seccomp-unavailable detail={:?} probe=not-run", error.detail);
                return;
            }
            Err(error) => panic!("the seccomp bootstrap probe refused: {error:?}"),
        };

        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let mut evidence = fixture.bootstrap_evidence(&plan);
        evidence.cgroup = cgroup;
        evidence.bubblewrap = bubblewrap;
        evidence.landlock = landlock;
        evidence.seccomp = seccomp;
        bind_live_mandatory_artefacts(&mut evidence, &ruleset, &filter);
        let verdict = validate_service_bootstrap_evidence(&evidence);
        println!(
            "GBDEVIDENCE four-live-probes verdict={} version_stdout={:?} observed_abi={} \
             seccomp_killed={} cgroup_probe_passed={}",
            match &verdict {
                Ok(()) => "admitted".to_owned(),
                Err(error) => format!("refused {error:?}"),
            },
            evidence.bubblewrap.version_stdout,
            evidence.landlock.observed_kernel_abi,
            evidence.seccomp.forbidden_syscall_killed,
            evidence.cgroup.active_probe_passed
        );
        verdict.expect("four live host probes produce admissible bootstrap evidence");

        assert!(!LinuxNativeServiceBootstrapAuthority::permits_execution());
    }
