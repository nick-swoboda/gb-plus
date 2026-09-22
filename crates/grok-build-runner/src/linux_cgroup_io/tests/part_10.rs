    // -----------------------------------------------------------------------
    // The Landlock and seccomp bootstrap probes, run live against this host.
    //
    // These are the two probes that need a probe *process*, and both tests
    // exercise the real one: the runner binary, re-executed with the internal
    // mode argument, confining itself and reporting what the kernel did.
    //
    // Each has a control run that differs from its enforced run in exactly one
    // input, and in both cases the control keeps the control layer installed:
    //
    //   Landlock  the ruleset and `restrict_self` are identical; only which
    //             path the confined child is asked to open moves, from one
    //             outside the grant to one inside it.
    //   seccomp   the filter, the architecture prologue and the
    //             no-new-privileges step are identical; only which of two
    //             syscalls the child invokes afterwards moves.
    //
    // So a control run is not "the same probe with the control switched off" —
    // there is no such mode in this binary. It is the same enforcement asked a
    // different question, which is what makes the enforced verdict attributable
    // to the kernel rather than to a constant in the report.
    // -----------------------------------------------------------------------

    /// Whether a refusal is this host lacking the capability rather than the
    /// capability failing.
    ///
    /// An unavailable layer is reported and the arm is not silently skipped:
    /// the caller prints what was missing, exactly as the Bubblewrap probe
    /// prints its `ENOENT`.
    #[cfg(target_os = "linux")]
    fn bootstrap_probe_layer_is_absent(failure: &CgroupIoFailure) -> bool {
        ["create the Landlock ruleset", "apply the filter", "set no-new-privileges"]
            .iter()
            .any(|reason| failure.detail.contains(reason))
    }

    /// One live `path_beneath` rule over a real directory on this host.
    ///
    /// The identity is read here rather than assumed, because the probe
    /// controller requires the child's own `fstat` of what it opened to equal
    /// it — which is the clause that makes a path in the artefact a hint and
    /// the inode the check.
    #[cfg(target_os = "linux")]
    fn live_landlock_scope(object_id: &str, path: &str, access_bits: u64) -> LinuxLandlockScopeV1 {
        let observed = rustix::fs::stat(path).expect("stat a live probe scope");
        LinuxLandlockScopeV1 {
            object_id: object_id.into(),
            resolved_path: path.into(),
            device_id: observed.st_dev,
            inode: observed.st_ino,
            access_bits,
        }
    }

    /// A committed ruleset over real objects on this host.
    #[cfg(target_os = "linux")]
    fn live_landlock_ruleset(scope_path: &str, witness_path: &str) -> LinuxLandlockRulesetV1 {
        let witness = rustix::fs::stat(witness_path).expect("stat a live probe witness");
        let mut ruleset = LinuxLandlockRulesetV1 {
            created_at_kernel_abi: crate::linux_command_plan::LINUX_LANDLOCK_MINIMUM_KERNEL_ABI,
            handled_access_bits:
                crate::linux_command_plan::LINUX_LANDLOCK_ABI_1_HANDLED_ACCESS_BITS,
            scopes: vec![live_landlock_scope(
                "probe-scope",
                scope_path,
                crate::linux_command_plan::LINUX_LANDLOCK_ABI_1_READ_ACCESS_BITS,
            )],
            denial_witness: LinuxLandlockDenialWitnessV1 {
                resolved_path: witness_path.into(),
                device_id: witness.st_dev,
                inode: witness.st_ino,
            },
            ruleset_sha256: Digest::sha256(&[]),
        };
        ruleset.ruleset_sha256 = ruleset.canonical_digest();
        ruleset
    }

    /// The audit architecture this test binary was compiled for.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const LIVE_PROBE_AUDIT_ARCHITECTURE: LinuxAuditArchitectureV1 =
        LinuxAuditArchitectureV1::Aarch64;

    /// See the `aarch64` definition.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const LIVE_PROBE_AUDIT_ARCHITECTURE: LinuxAuditArchitectureV1 = LinuxAuditArchitectureV1::X86_64;

    /// Replaces the fixture plan's committed artefacts with the ones a live
    /// probe was actually run against.
    ///
    /// Both halves are required now, and that is the whole point of the version
    /// 4 clause: the validator recomputes the probe's result commitment from
    /// the *plan's* artefact, so evidence from a probe over a different ruleset
    /// or a different filter no longer binds. The window is also widened to the
    /// production one — the fixture names `[6, 10]`, which no kernel this suite
    /// runs on implements, while a production plan commits
    /// `LINUX_LANDLOCK_MINIMUM_KERNEL_ABI`..`LINUX_LANDLOCK_MAXIMUM_MODELED_KERNEL_ABI`.
    #[cfg(target_os = "linux")]
    fn bind_live_mandatory_artefacts(
        evidence: &mut LinuxNativeServiceBootstrapEvidenceV1,
        ruleset: &LinuxLandlockRulesetV1,
        filter: &LinuxSeccompFilterV1,
    ) {
        evidence.plan_binding.landlock =
            LinuxLandlockBootstrapBindingV1::InstalledRulesetProvenByLiveBootstrapProbe {
                minimum_kernel_abi: crate::linux_command_plan::LINUX_LANDLOCK_MINIMUM_KERNEL_ABI,
                maximum_modeled_kernel_abi:
                    crate::linux_command_plan::LINUX_LANDLOCK_MAXIMUM_MODELED_KERNEL_ABI,
                ruleset: ruleset.clone(),
            };
        evidence.plan_binding.seccomp =
            LinuxSeccompBootstrapBindingV1::CompiledFilterProvenByLiveBootstrapProbe {
                audit_architecture: LIVE_PROBE_AUDIT_ARCHITECTURE,
                default_action: LinuxSeccompDefaultActionV1::KillProcess,
                filter: filter.clone(),
            };
    }

    /// Landlock really confines a child of this process **with the ruleset the
    /// plan commits**, and the probe refuses when the object the plan said must
    /// be unreachable is reachable.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_live_landlock_bootstrap_probe_enforces_and_refuses_a_reachable_path() {
        // A real directory that exists on every image this suite runs on, and
        // the filesystem root as the object the ruleset states it does not
        // grant — which is what a production mint commits.
        let ruleset = live_landlock_ruleset("/usr", "/");

        let enforced = match probe_landlock_full_enforcement(&ruleset) {
            Ok(probe) => probe,
            Err(error) if bootstrap_probe_layer_is_absent(&error) => {
                println!(
                    "GBDLANDLOCK landlock-unavailable detail={:?} probe=not-run \
                     (this host does not implement Landlock, so no bootstrap evidence can exist here)",
                    error.detail
                );
                return;
            }
            Err(error) => panic!("the Landlock bootstrap probe refused: {error:?}"),
        };
        println!(
            "GBDLANDLOCK enforced scope=/usr denied=/ observed_abi={} full_enforcement={} \
             ruleset={} digest={}",
            enforced.observed_kernel_abi,
            enforced.full_enforcement_passed,
            ruleset.ruleset_sha256.as_str(),
            enforced.active_probe_result_digest.as_str()
        );
        assert!(enforced.full_enforcement_passed);
        assert!(
            enforced.observed_kernel_abi >= 1,
            "a fully enforced ruleset cannot come from a kernel with no Landlock ABI"
        );
        assert!(!digest_is_zero(&enforced.active_probe_result_digest));

        // The control. One input moves: the object the child must be unable to
        // open becomes the very scope it was granted. The child still builds
        // the same ruleset and still calls `restrict_self`; the kernel
        // therefore lets it through, and the probe refuses because its own
        // measurement says the boundary did not bite.
        let control = probe_landlock_full_enforcement(&live_landlock_ruleset("/usr", "/usr"))
            .expect_err("a witness inside the granted scope is reachable, so the probe must refuse");
        println!("GBDLANDLOCK control detail={:?}", control.detail);
        assert_eq!(control.operation, "probe-bootstrap-landlock");
        assert_eq!(control.certainty, EffectCertainty::NotApplied);
        assert!(
            control.detail.contains("was not denied"),
            "the refusal is not the denial clause: {control:?}"
        );

        // A second control, on the clause version 4 added: the same live probe
        // result submitted against a plan that commits a *different* ruleset is
        // refused, where the version-3 validator would have admitted it because
        // the digest is not zero.
        let filter = mint_command_seccomp_filter(
            LIVE_PROBE_AUDIT_ARCHITECTURE,
            "probe-bootstrap-seccomp",
        )
        .expect("this architecture has a compiled syscall table");
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let mut crossed = fixture.bootstrap_evidence(&plan);
        crossed.landlock = enforced.clone();
        bind_live_mandatory_artefacts(
            &mut crossed,
            &live_landlock_ruleset("/usr", "/usr"),
            &filter,
        );
        let refusal = validate_service_bootstrap_evidence(&crossed)
            .expect_err("a probe result minted against another ruleset must not bind this plan");
        assert!(
            refusal
                .detail
                .contains("installed the exact ruleset this plan commits"),
            "the refusal is not the version-4 binding clause: {refusal:?}"
        );

        // The measured probe is admissible against the plan it was really run
        // for, so the refusal above is attributable to the ruleset and to
        // nothing else.
        let mut evidence = fixture.bootstrap_evidence(&plan);
        evidence.landlock = enforced;
        bind_live_mandatory_artefacts(&mut evidence, &ruleset, &filter);
        evidence.seccomp.active_probe_result_digest =
            seccomp_bootstrap_probe_result_digest(&filter);
        validate_service_bootstrap_evidence(&evidence)
            .expect("the live Landlock probe binds the plan's own committed ruleset");

        assert!(!LinuxNativeServiceBootstrapAuthority::permits_execution());
    }

    /// The committed seccomp filter installed by a child of this process really
    /// kills that child, and the probe refuses when the child survives.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_live_seccomp_bootstrap_probe_kills_its_child_and_refuses_a_survivor() {
        let filter = mint_command_seccomp_filter(
            LIVE_PROBE_AUDIT_ARCHITECTURE,
            "probe-bootstrap-seccomp",
        )
        .expect("this architecture has a compiled syscall table");
        let enforced = match probe_seccomp_forbidden_syscall(
            &filter,
            SECCOMP_BOOTSTRAP_PROBE_FORBIDDEN_TARGET,
        ) {
            Ok(probe) => probe,
            Err(error) if bootstrap_probe_layer_is_absent(&error) => {
                println!(
                    "GBDSECCOMP seccomp-unavailable detail={:?} probe=not-run \
                     (this host refuses seccomp(2), so no bootstrap evidence can exist here)",
                    error.detail
                );
                return;
            }
            Err(error) => panic!("the seccomp bootstrap probe refused: {error:?}"),
        };
        println!(
            "GBDSECCOMP enforced invoked={} denied_syscalls={} instructions={} killed={} \
             no_new_privs={} program={} digest={}",
            SECCOMP_BOOTSTRAP_PROBE_INVOKED_SYSCALL,
            filter.denied_syscalls.len(),
            filter.instruction_count,
            enforced.forbidden_syscall_killed,
            enforced.no_new_privileges_read_back,
            filter.program_sha256.as_str(),
            enforced.active_probe_result_digest.as_str()
        );
        assert!(enforced.forbidden_syscall_killed);
        assert!(enforced.no_new_privileges_read_back);
        assert!(!digest_is_zero(&enforced.active_probe_result_digest));

        // The control. One input moves: the child invokes the syscall the same
        // filter allows instead of the one it kills. The filter is installed
        // either way — the child reports the digest of the program it
        // assembled — so the survival is a fact about which syscall was called
        // and about nothing else.
        let control =
            probe_seccomp_forbidden_syscall(&filter, SECCOMP_BOOTSTRAP_PROBE_PERMITTED_TARGET)
                .expect_err("a permitted syscall does not kill the child, so the probe must refuse");
        println!("GBDSECCOMP control detail={:?}", control.detail);
        assert_eq!(control.operation, "probe-bootstrap-seccomp");
        assert_eq!(control.certainty, EffectCertainty::NotApplied);
        assert!(
            control.detail.contains("was not killed by SIGSYS"),
            "the refusal is not the kill clause: {control:?}"
        );

        // A filter the probe cannot invoke is refused rather than admitted
        // unproven, so no plan can obtain seccomp evidence for a filter this
        // host never exercised.
        let mut unprovable = filter.clone();
        unprovable
            .denied_syscalls
            .retain(|denied| denied.name != SECCOMP_BOOTSTRAP_PROBE_INVOKED_SYSCALL);
        unprovable.filter_sha256 = unprovable.canonical_digest(
            LIVE_PROBE_AUDIT_ARCHITECTURE,
            LinuxSeccompDefaultActionV1::KillProcess,
        );
        let unprovable_refusal = probe_seccomp_forbidden_syscall(
            &unprovable,
            SECCOMP_BOOTSTRAP_PROBE_FORBIDDEN_TARGET,
        )
        .expect_err("a filter that does not deny the one invocable syscall cannot be proven");
        assert!(
            unprovable_refusal.detail.contains("cannot be proven on this host"),
            "the refusal is not the unprovable-filter clause: {unprovable_refusal:?}"
        );

        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let ruleset = live_landlock_ruleset("/usr", "/");
        let mut evidence = fixture.bootstrap_evidence(&plan);
        evidence.seccomp = enforced;
        bind_live_mandatory_artefacts(&mut evidence, &ruleset, &filter);
        evidence.landlock.active_probe_result_digest = landlock_bootstrap_probe_result_digest(
            &ruleset,
            evidence.landlock.observed_kernel_abi,
        );
        validate_service_bootstrap_evidence(&evidence)
            .expect("the live seccomp probe binds the plan's own committed filter");

        assert!(!LinuxNativeServiceBootstrapAuthority::permits_execution());
    }

    /// The two compiled Landlock access sets are the crate's own.
    ///
    /// `LINUX_LANDLOCK_ABI_1_HANDLED_ACCESS_BITS` and its read subset are
    /// written as numbers because the plan module compiles on hosts with no
    /// Landlock crate. This is the assertion that keeps them honest.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_compiled_landlock_access_sets_are_the_crate_s_own() {
        use landlock::{ABI, Access as _, AccessFs};

        assert_eq!(
            AccessFs::from_all(ABI::V1).bits(),
            crate::linux_command_plan::LINUX_LANDLOCK_ABI_1_HANDLED_ACCESS_BITS
        );
        assert_eq!(
            AccessFs::from_read(ABI::V1).bits(),
            crate::linux_command_plan::LINUX_LANDLOCK_ABI_1_READ_ACCESS_BITS
        );
    }

    /// The probe process refuses an argument vocabulary it does not compile.
    ///
    /// The helper's whole argument surface is two modes and, inside them, two
    /// closed selectors. Nothing a caller supplies can make it execute anything
    /// else, and this is the test that says so rather than the comment.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_bootstrap_probe_process_refuses_an_unknown_mode() {
        let output = run_service_bootstrap_probe_process(
            "not-a-compiled-mode",
            &[],
            "probe-bootstrap-landlock",
        )
        .expect("the probe process starts");
        assert_eq!(
            output.status.code(),
            Some(i32::from(LINUX_SERVICE_BOOTSTRAP_PROBE_REFUSAL_CODE))
        );
        assert!(output.stdout.is_empty(), "a refused probe publishes no report");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("one of its two compiled modes"),
            "the refusal does not name the closed mode set"
        );
    }
