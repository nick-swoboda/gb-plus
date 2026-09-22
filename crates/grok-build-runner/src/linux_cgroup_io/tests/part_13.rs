    // ---------------------------------------------------------------------
    // Inhabiting `LinuxCgroupV2Domain`.
    //
    // Reached only from the live anchor-canary chain, immediately after
    // `LinuxCgroupIo::open_service_owned` returns a real service-owned backend.
    // Everything below is driven through the production types: the backend
    // prepares its own plan-scoped domain, a real `LinuxCgroupV2Domain` takes
    // custody of it, and the value is driven through `poll`, `terminate_all`
    // and `into_cleanup_proof` in the order and with the monotonicity the
    // supervisor's own loop requires.
    //
    // **No command runs here.** The processes placed in the domain are `sleep`
    // and a shell that moves itself into the leaf; none is a
    // `PreparedContainedCommand`, none arrives through a permit, a preflight
    // report or a backend `launch`, and nothing about this file claims a
    // containment control. What it proves is that the domain type is inhabited
    // and that its three methods do what their names say against a real kernel.
    // ---------------------------------------------------------------------

    /// Bytes the domain's leader writes to each stream before it sleeps.
    ///
    /// Long enough that a deliberately tiny poll bound has to answer in several
    /// chunks, so "bounded" is measured rather than asserted.
    #[cfg(target_os = "linux")]
    const DOMAIN_STDOUT_MARKER: &str = "GBDDOMAIN-STDOUT-0123456789-abcdefghij";
    #[cfg(target_os = "linux")]
    const DOMAIN_STDERR_MARKER: &str = "GBDDOMAIN-STDERR-0123456789-abcdefghij";
    /// Deliberately small, so the drain has to respect it more than once.
    #[cfg(target_os = "linux")]
    const DOMAIN_POLL_CHUNK: usize = 7;

    /// The live domain's compile-level position, asserted rather than described.
    ///
    /// The same standing form the bootstrap, setup and child-launch mints use.
    /// Three function pointers pin three things a later change could quietly
    /// undo: that `prepare_domain` is production code and not `cfg(test)`
    /// again, that the backend's own plan-scoped entry point still takes no
    /// caller-supplied request, and that the domain's constructor exists with
    /// the exact shape a `launch` would have to satisfy. A build in which any
    /// of them became test-only, changed shape, or disappeared fails to compile
    /// instead of regressing to "the domain is uninhabited".
    ///
    /// The `permits_execution` assertions are the other half: inhabiting the
    /// domain granted nothing, and this is where that stops being prose.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_live_command_domain_is_inhabited_and_grants_nothing() {
        use crate::command::linux_backend::LinuxCgroupV2Domain;

        let prepare: fn(
            &mut LinuxCgroupIo,
            PrepareDomainRequest,
        ) -> Result<
            crate::linux_containment::PrepareDomainOutcome,
            crate::linux_containment::CgroupError,
        > = crate::linux_containment::prepare_domain::<LinuxCgroupIo>;
        assert!(std::ptr::fn_addr_eq(
            prepare,
            crate::linux_containment::prepare_domain::<LinuxCgroupIo> as fn(_, _) -> _,
        ));
        let plan_scoped: fn(
            &mut LinuxCgroupIo,
        ) -> Result<
            crate::linux_containment::PrepareDomainOutcome,
            crate::linux_containment::CgroupError,
        > = LinuxCgroupIo::prepare_service_domain;
        assert!(std::ptr::fn_addr_eq(
            plan_scoped,
            LinuxCgroupIo::prepare_service_domain as fn(_) -> _,
        ));
        let custody: fn(
            LinuxCgroupIo,
            PreparedDomain,
            std::process::Child,
            std::os::fd::OwnedFd,
            std::os::fd::OwnedFd,
        )
            -> Result<LinuxCgroupV2Domain, crate::command::SupervisorError> =
            LinuxCgroupV2Domain::open_service_owned;
        assert!(std::ptr::fn_addr_eq(
            custody,
            LinuxCgroupV2Domain::open_service_owned as fn(_, _, _, _, _) -> _,
        ));

        assert!(!LinuxNativeServiceChildLaunchClosureAuthority::permits_execution());
        assert!(!LinuxNativeServiceSetupDescriptorAuthority::permits_execution());
        assert!(!LinuxNativeServiceMechanicsAuthority::permits_execution());
    }

    /// The production backend's service handoff, pinned at compile level.
    ///
    /// The same standing form the four mints use. These four function pointers
    /// are the statement that `LinuxCgroupV2Backend` can hold the native
    /// service's own `LinuxCgroupIo`, that composing it is gated by a clause
    /// taking the handoff **by reference** so a refusal cannot destroy live
    /// delegation custody, and that the backend — not a canary beside it —
    /// prepares and hands over this plan's one domain. A build in which any of
    /// them became test-only, changed shape or disappeared fails to compile
    /// rather than regressing to "the production backend cannot obtain a
    /// `LinuxCgroupIo`".
    ///
    /// The `permits_execution` assertions are the other half: obtaining the
    /// handoff granted nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_production_backend_can_hold_a_service_handoff_and_grants_nothing() {
        use crate::command::linux_backend::{LinuxCgroupV2Backend, LinuxCgroupV2Domain};

        let compose: fn(
            grok_build_core::IssuedWorkspaceGrant,
            grok_build_core::CompiledExecutionPolicy,
            &crate::command::SupervisorPaths,
            LinuxCgroupIo,
        ) -> Result<LinuxCgroupV2Backend, crate::command::SupervisorError> =
            LinuxCgroupV2Backend::service_owned;
        assert!(std::ptr::fn_addr_eq(
            compose,
            LinuxCgroupV2Backend::service_owned as fn(_, _, _, _) -> _,
        ));
        let join: fn(
            &grok_build_core::IssuedWorkspaceGrant,
            &grok_build_core::CompiledExecutionPolicy,
            &LinuxCgroupIo,
        ) -> Result<(), crate::command::SupervisorError> =
            crate::command::linux_backend::require_service_handoff_authority;
        assert!(std::ptr::fn_addr_eq(
            join,
            crate::command::linux_backend::require_service_handoff_authority
                as fn(_, _, _) -> _,
        ));
        let prepare: fn(
            &mut LinuxCgroupV2Backend,
        )
            -> Result<PreparedDomain, crate::command::SupervisorError> =
            LinuxCgroupV2Backend::prepare_service_domain;
        assert!(std::ptr::fn_addr_eq(
            prepare,
            LinuxCgroupV2Backend::prepare_service_domain as fn(_) -> _,
        ));
        let custody: fn(
            &mut LinuxCgroupV2Backend,
            PreparedDomain,
            std::process::Child,
            std::os::fd::OwnedFd,
            std::os::fd::OwnedFd,
        )
            -> Result<LinuxCgroupV2Domain, crate::command::SupervisorError> =
            LinuxCgroupV2Backend::open_service_domain;
        assert!(std::ptr::fn_addr_eq(
            custody,
            LinuxCgroupV2Backend::open_service_domain as fn(_, _, _, _, _) -> _,
        ));

        assert!(!LinuxNativeServiceMechanicsAuthority::permits_execution());
        assert!(!LinuxNativeServiceChildLaunchClosureAuthority::permits_execution());
    }

    /// The delegation this service was anchored to, from the same two variables
    /// the installed-service fixture reads.
    #[cfg(target_os = "linux")]
    fn anchored_delegation_path() -> Option<PathBuf> {
        let parent = environment_path(CGROUP_PARENT_VARIABLE)?;
        let delegation = std::env::var(DELEGATION_VARIABLE).ok()?;
        Some(PathBuf::from(parent).join(delegation))
    }

    /// Starts one process that moves **itself** into `leaf` and then sleeps.
    ///
    /// Nothing writes another process's pid. Each occupant is a direct child of
    /// this process and `exec`s, so none is an ancestor of another and no
    /// signal addressed to a process group or session could reach the set —
    /// which is the property that makes a later whole-domain kill mean
    /// something.
    #[cfg(target_os = "linux")]
    fn spawn_domain_occupant(
        leaf: &Path,
        speaks: bool,
    ) -> std::io::Result<std::process::Child> {
        let procs = leaf.join("cgroup.procs");
        let script = if speaks {
            format!(
                "echo $$ > {procs} || exit 97; printf '{DOMAIN_STDOUT_MARKER}'; \
                 printf '{DOMAIN_STDERR_MARKER}' >&2; exec sleep 300",
                procs = procs.display()
            )
        } else {
            format!(
                "echo $$ > {procs} || exit 97; exec sleep 300",
                procs = procs.display()
            )
        };
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script).stdin(std::process::Stdio::null());
        if speaks {
            command
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
        } else {
            command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
        }
        command.spawn()
    }

    /// The two private roots `LinuxCgroupV2Backend::new` requires, created for
    /// real beneath this run's scratch tree.
    ///
    /// `validate_supervisor_paths` refuses a relative path, a non-directory,
    /// anything group- or other-accessible, and any shadow root that is not
    /// disjoint from the live workspace, so these are real directories at
    /// `0o700` outside the grant's canonical root rather than names.
    #[cfg(target_os = "linux")]
    fn backend_supervisor_paths(scratch: &Path) -> crate::command::SupervisorPaths {
        let private_state_root = scratch.join("backend-private-state");
        // The shadow execution root is a strict child of the private state
        // root, which is what `contained_boundary::prepare` requires of any
        // command it will prepare. Composing the backend accepts a wider
        // shape, so the narrower one is chosen here rather than discovered
        // later by a command that cannot be prepared.
        let shadow_root = private_state_root.join("backend-shadow");
        let _ = fs::remove_dir_all(&private_state_root);
        for root in [&private_state_root, &shadow_root] {
            fs::create_dir_all(root).expect("create a private backend root");
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                .expect("seal a private backend root");
        }
        crate::command::SupervisorPaths::shadow(private_state_root, shadow_root)
    }

    /// Drives one real `LinuxCgroupV2Domain` from custody to a minted proof,
    /// **through the production backend that owns the handoff**.
    ///
    /// The `LinuxCgroupIo` no longer goes to the domain directly. It is
    /// composed into a `LinuxCgroupV2Backend` first, from the same grant and
    /// policy the journal committed this plan under, and every step below
    /// happens on generation `linux-cgroup-v2-v1`: the backend prepares the
    /// leaf, the backend hands the handoff to the domain, and the domain's
    /// methods are the trait's. That is the difference the previous increment
    /// could not buy — its domain was built beside the backend, so nothing it
    /// proved was about this generation.
    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear run keeps the composition, the preparation, the live occupancy, every polled observation and the minted proof visible in the order they happen"
    )]
    fn inhabit_and_prove_the_linux_command_domain(
        io: LinuxCgroupIo,
        grant: &grok_build_core::IssuedWorkspaceGrant,
        policy: &grok_build_core::CompiledExecutionPolicy,
        scratch: &Path,
    ) {
        use crate::command::contained_boundary::{
            BackendTermination, ContainedCommandBackend, ContainedDescendantDomain,
            DomainTerminationRequest,
        };
        use crate::command::linux_backend::LinuxCgroupV2Backend;

        let Some(delegation_path) = anchored_delegation_path() else {
            println!("GBDDOMAIN delegation-path-absent domain=not-inhabited");
            return;
        };

        // ---- control: a second, equally real command authority -------------
        //
        // The substituted grant and policy are minted by the same production
        // issuer and compiler this run's own were, over a real second workspace
        // directory. One input varies — which workspace the grant is over — and
        // the clause `service_owned` performs is exercised by reference, so the
        // refusal costs the service none of its live delegation custody.
        let control_workspace = scratch.join("control-workspace");
        let control = crate::linux_command_plan::tests::plan_authority_fixture(
            crate::wire::RunnerRole::Worker,
            &control_workspace,
            "/bin/true",
            grok_build_core::MutationMode::ShadowWorkspace,
        );
        let refusal = crate::command::linux_backend::require_service_handoff_authority(
            &control.grant,
            &control.policy,
            &io,
        )
        .expect_err("a handoff journaled for another command must not compose a backend");
        println!("GBDBACKEND control=crossed-authority detail={refusal}");
        crate::command::linux_backend::require_service_handoff_authority(grant, policy, &io)
            .expect("this run's own command authority is the handoff's own");

        // ---- the production backend takes the service handoff --------------
        //
        // `service_owned` is the constructor `LinuxCgroupV2Backend` did not
        // have. It composes exactly as `new` does and additionally requires the
        // handoff's own journaled grant and policy to be this backend's, so a
        // handoff for one command cannot end up inside a backend for another.
        let paths = backend_supervisor_paths(scratch);
        let mut backend =
            match LinuxCgroupV2Backend::service_owned(grant.clone(), policy.clone(), &paths, io) {
                Ok(backend) => backend,
                Err(error) => {
                    println!("GBDBACKEND service_owned=refused detail={error}");
                    return;
                }
            };
        assert!(backend.holds_service_handoff());
        assert_eq!(backend.backend_id(), "linux-cgroup-v2-v1");
        // Custody is not a control. The generation still enforces nothing and
        // this is where that stops being prose.
        assert!(
            backend.enforced_controls().is_empty(),
            "holding a service handoff named a control"
        );
        println!(
            "GBDBACKEND enforced service_owned=composed backend_id={} handoff=true \
             enforced_controls={:?}",
            backend.backend_id(),
            backend.enforced_controls()
        );

        // ---- the live canary episode, on this generation --------------------
        //
        // This is the call the whole adoption increment exists for. The
        // production backend's own preflight drives a canary episode through
        // the probe journal it holds: the journal creates the leaf under a
        // durable create-intent generation, the suite **adopts** it — no
        // `mkdirat`, no minted name, no unlink — and the journal removes it
        // under its own remove-intent generation. Whatever `enforced_controls`
        // says afterwards is a measurement of what a live canary proved here,
        // not a constant.
        //
        // The refusal is still expected and is still the correct result: ten
        // of the twelve controls have no installer on this path at all, so
        // `required_controls` cannot be a subset of anything this proves.
        let command_spec = grok_build_core::CommandSpec {
            program: "/usr/bin/true".into(),
            arguments: vec!["literal space".into(), "$HOME".into()],
            working_directory: PathBuf::from("src"),
        };
        let contained_cwd = paths.shadow_root().map(|root| root.join("src"));
        if let Some(cwd) = &contained_cwd {
            let _ = fs::create_dir_all(cwd);
        }
        match crate::command::tests::prepare_contained(
            grant.clone(),
            policy.clone(),
            &paths,
            &command_spec,
        ) {
            Ok(prepared) => {
                let refusal = backend
                    .active_preflight(&prepared)
                    .expect_err("no launcher installs a containment artefact on this generation");
                println!(
                    "GBDCANARY enforced backend_id={} journaled={:?} enforced_controls={:?}",
                    backend.backend_id(),
                    backend.service_canary_journaled(),
                    backend.enforced_controls()
                );
                println!("GBDCANARY refusal={refusal}");
                // `ActiveCanaries` is the one control whose installer is this
                // preflight itself. Everything else the suite proves, it
                // proves about the probe journal's leaf, which is not the leaf
                // a command would run in.
                for control in crate::command::contained_boundary::required_controls(
                    policy.contract().resource_limits,
                ) {
                    if control == crate::command::contained_boundary::BackendControl::ActiveCanaries {
                        continue;
                    }
                    assert!(
                        !backend.enforced_controls().contains(&control),
                        "a control with no installer on this path was named: {control:?}"
                    );
                }
            }
            Err(error) => {
                println!("GBDCANARY prepared-command=unavailable detail={error}");
            }
        }

        // ---- the backend prepares its own plan-scoped domain ---------------
        let prepared = match backend.prepare_service_domain() {
            Ok(prepared) => prepared,
            Err(error) => {
                println!("GBDDOMAIN prepare=refused detail={error}");
                return;
            }
        };
        assert_eq!(prepared.state(), DomainJournalState::Prepared);
        let leaf = delegation_path.join(prepared.leaf_name());
        let limits = prepared
            .read_back_limits()
            .expect("the prepared domain carries the kernel's own limit read-back");
        println!(
            "GBDDOMAIN prepared leaf={} pids_max={} memory_max={:?} oom_group={} \
             kernel_pids_max={} kernel_memory_max={}",
            prepared.leaf_name(),
            limits.pids_max,
            limits.memory_max,
            limits.memory_oom_group,
            String::from_utf8_lossy(&read_leaf_control(&leaf, "pids.max")).trim(),
            String::from_utf8_lossy(&read_leaf_control(&leaf, "memory.max")).trim(),
        );

        // ---- a second domain for the same effect is refused ----------------
        //
        // The one control this chain can afford: the mechanics authority is
        // one-plan-scoped and the delegation is single-writer, so asking the
        // same backend for a second domain must not answer with one. It is also
        // the measurement behind this generation having no preflight probe
        // suite — a probe domain and the command's domain cannot both exist.
        match backend.prepare_service_domain() {
            Ok(_) => panic!("a second domain for the same one-plan-scoped authority was prepared"),
            Err(error) => println!("GBDDOMAIN control=second-domain detail={error}"),
        }

        // ---- real occupants, each moving itself in -------------------------
        let extra_occupants = usize::min(2, (limits.pids_max as usize).saturating_sub(1));
        let mut leader = match spawn_domain_occupant(&leaf, true) {
            Ok(child) => child,
            Err(error) => panic!("could not start the domain leader: {error}"),
        };
        let occupants = Occupants(Some(
            (0..extra_occupants)
                .map(|_| {
                    spawn_domain_occupant(&leaf, false).expect("start one unrelated occupant")
                })
                .collect(),
        ));
        let expected_members = extra_occupants + 1;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let members = loop {
            let members = parse_cgroup_procs(&read_leaf_control(&leaf, "cgroup.procs"))
                .expect("parse the live domain membership");
            if members.len() >= expected_members {
                break members;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the live domain never reached {expected_members} members; saw {members:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        // What the domain genuinely contained, read independently of the code
        // under test. Without this every zero below would be vacuous.
        let populated_events = read_leaf_control(&leaf, "cgroup.events");
        let populated_procs = read_leaf_control(&leaf, "cgroup.procs");
        assert!(
            String::from_utf8_lossy(&populated_events).contains("populated 1"),
            "the occupied domain did not report populated 1: {}",
            String::from_utf8_lossy(&populated_events)
        );
        println!(
            "GBDDOMAIN occupied members={members:?} leader={} events={:?}",
            leader.id(),
            String::from_utf8_lossy(&populated_events).replace('\n', " "),
        );

        // ---- the domain takes custody -------------------------------------
        let stdout = std::os::fd::OwnedFd::from(
            leader.stdout.take().expect("the leader speaks on stdout"),
        );
        let stderr = std::os::fd::OwnedFd::from(
            leader.stderr.take().expect("the leader speaks on stderr"),
        );
        let mut domain = backend
            .open_service_domain(prepared, leader, stdout, stderr)
            .expect("a real live Linux command domain takes custody");
        assert_eq!(domain.journal_state(), DomainJournalState::Prepared);
        let leaf_name = domain.leaf_name().to_owned();
        // The handoff left the backend when the domain took it. Two owners of
        // one delegation lock is the thing single-writer custody exists to
        // prevent, so the backend must now answer that it holds none.
        assert!(!backend.holds_service_handoff());
        // Losing the handoff must not retract a claim that was already
        // measured, and must not grant one either. Before this increment the
        // set was empty on both sides of the move and the assertion could not
        // tell those two things apart; now a live canary episode has proven
        // `ActiveCanaries` on this generation, so the assertion is that custody
        // changed the measured set by exactly nothing.
        assert_eq!(
            backend.enforced_controls(),
            [crate::command::contained_boundary::BackendControl::ActiveCanaries]
                .into_iter()
                .collect(),
            "handing the delegation to a domain changed what a live canary proved"
        );

        // ---- drive it exactly the way the supervisor's loop does -----------
        let (proof, statuses) = occupants.reap_while(|| {
            let mut stdout_bytes = Vec::new();
            let mut stderr_bytes = Vec::new();
            let mut largest_chunk = 0usize;
            let mut chunks = 0usize;
            let mut polls = 0usize;
            let mut terminated = false;
            let mut leader_terminal = None;
            let mut previous_stdout_closed = false;
            let mut previous_stderr_closed = false;
            let mut previous_domain_empty = false;
            loop {
                let observation = domain
                    .poll(DOMAIN_POLL_CHUNK)
                    .expect("poll the live command domain");
                assert!(
                    observation.stdout.len() <= DOMAIN_POLL_CHUNK
                        && observation.stderr.len() <= DOMAIN_POLL_CHUNK,
                    "the domain exceeded the bound its caller set"
                );
                // Exactly the monotonicity the supervisor's own tracker
                // enforces, re-checked here so a regression fails in the
                // canary rather than only inside a path with no caller.
                assert!(
                    !(previous_stdout_closed
                        && (!observation.stdout.is_empty() || !observation.stdout_closed)),
                    "a closed stdout produced more bytes or reopened"
                );
                assert!(
                    !(previous_stderr_closed
                        && (!observation.stderr.is_empty() || !observation.stderr_closed)),
                    "a closed stderr produced more bytes or reopened"
                );
                assert!(
                    !previous_domain_empty || observation.domain_empty,
                    "an empty domain reported itself populated again"
                );
                if let Some(previous) = leader_terminal {
                    assert_eq!(
                        observation.leader,
                        Some(previous),
                        "a terminal leader status changed"
                    );
                }
                assert!(
                    !(observation.domain_empty && observation.leader.is_none()),
                    "the domain claimed emptiness before its leader terminated"
                );
                assert!(
                    !(observation.domain_empty
                        && !(observation.stdout_closed && observation.stderr_closed)),
                    "the domain claimed emptiness with a command stream still open"
                );
                for chunk in [&observation.stdout, &observation.stderr] {
                    if !chunk.is_empty() {
                        chunks += 1;
                        largest_chunk = largest_chunk.max(chunk.len());
                    }
                }
                stdout_bytes.extend_from_slice(&observation.stdout);
                stderr_bytes.extend_from_slice(&observation.stderr);
                leader_terminal = observation.leader;
                previous_stdout_closed = observation.stdout_closed;
                previous_stderr_closed = observation.stderr_closed;
                previous_domain_empty = observation.domain_empty;

                // The leader is alive and has spoken. Everything the domain
                // has said so far must therefore be "not finished".
                if !terminated
                    && stdout_bytes.len() >= DOMAIN_STDOUT_MARKER.len()
                    && stderr_bytes.len() >= DOMAIN_STDERR_MARKER.len()
                {
                    assert_eq!(
                        observation.leader, None,
                        "the leader terminated before it was asked to"
                    );
                    assert!(!observation.domain_empty, "a populated domain reported empty");
                    domain
                        .terminate_all(DomainTerminationRequest::Cancelled)
                        .expect("the whole live domain is terminated");
                    terminated = true;
                    println!(
                        "GBDDOMAIN terminate_all reason=Cancelled journal_state={:?}",
                        domain.journal_state()
                    );
                }
                if observation.leader.is_some()
                    && observation.stdout_closed
                    && observation.stderr_closed
                    && observation.domain_empty
                {
                    break;
                }
                polls += 1;
                assert!(polls < 20_000, "the live domain never completed");
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            assert!(terminated, "the domain completed without being terminated");
            assert_eq!(String::from_utf8_lossy(&stdout_bytes), DOMAIN_STDOUT_MARKER);
            assert_eq!(String::from_utf8_lossy(&stderr_bytes), DOMAIN_STDERR_MARKER);
            assert!(
                chunks > 2 && largest_chunk <= DOMAIN_POLL_CHUNK,
                "output arrived in {chunks} chunks, largest {largest_chunk}"
            );
            println!(
                "GBDDOMAIN pumped stdout_bytes={} stderr_bytes={} chunks={chunks} \
                 largest_chunk={largest_chunk} bound={DOMAIN_POLL_CHUNK} polls={polls} \
                 leader={:?}",
                stdout_bytes.len(),
                stderr_bytes.len(),
                leader_terminal,
            );
            assert_eq!(leader_terminal, Some(BackendTermination::Signaled(9)));
            domain.into_cleanup_proof()
        });
        let proof = proof.expect("the live domain mints its cleanup proof");

        // The unrelated occupants were killed, not merely unobserved. None of
        // them shares a process group with the leader, so nothing but the
        // domain could have reached them.
        assert_eq!(statuses.len(), extra_occupants);
        for status in &statuses {
            assert_eq!(
                std::os::unix::process::ExitStatusExt::signal(status),
                Some(9),
                "an unrelated occupant was not killed by the domain kill: {status:?}"
            );
        }
        assert!(!leaf.exists(), "the reaped leaf remained visible");
        assert_eq!(
            proof.disposition(),
            CommandDomainCleanupDisposition::ReapedZeroSurvivors
        );
        assert_eq!(proof.surviving_processes(), 0);
        assert_eq!(
            proof.backend(),
            crate::cleanup_proof::CommandDomainCleanupBackend::LinuxCgroupV2
        );
        // The canonical bytes carry the kernel's own endpoint answer, and that
        // answer differs from what the same file said while the domain was
        // occupied, so it cannot be a constant.
        let canonical = proof.os_evidence_bytes().to_vec();
        let rendered = |bytes: &[u8]| {
            bytes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        assert!(
            !String::from_utf8_lossy(&canonical).contains(&rendered(&populated_events)),
            "the canonical evidence carries the occupied events read"
        );
        assert!(
            !populated_procs.is_empty()
                && !String::from_utf8_lossy(&canonical).contains(&rendered(&populated_procs)),
            "the canonical evidence carries the occupied procs read"
        );
        let reopened =
            crate::cleanup_proof::ValidatedCommandDomainCleanupProof::readback_with_disposition(
                &canonical,
                proof.os_evidence_digest(),
                crate::cleanup_proof::CommandDomainCleanupBackend::LinuxCgroupV2,
                proof.binding(),
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            )
            .expect("reopen the live domain's cleanup proof");
        assert_eq!(reopened.os_evidence_bytes(), canonical.as_slice());
        println!(
            "GBDDOMAIN enforced ReapedZeroSurvivors leaf={leaf_name} occupants={members:?} \
             evidence_bytes={} verdict=domain-inhabited",
            canonical.len()
        );

        // ---- what the generation enforces, after all of that -----------------
        //
        // The domain above was prepared, occupied, drained, killed and reaped
        // by `LinuxCgroupV2Backend` on generation `linux-cgroup-v2-v1`. None of
        // that is a control, and it still is not one.
        //
        // What *is* named is `ActiveCanaries`, and only that: a live canary
        // episode ran on this generation, inside a leaf the probe journal
        // created and removed, and its installer is this backend's own
        // preflight. Every other control that episode proved, it proved about
        // the probe journal's leaf — nothing on the command's own path
        // installs Landlock, seccomp, the descriptor exec, the closed
        // descriptor table, the descriptor-relative cwd, the replaced
        // environment, the exact argv, the network mode or the external wall
        // clock around a command, and a ceiling read back off the command's
        // own leaf is a ceiling rather than a refused fork.
        assert_eq!(
            backend.enforced_controls(),
            [crate::command::contained_boundary::BackendControl::ActiveCanaries]
                .into_iter()
                .collect(),
            "the generation named a control no live canary earned on it"
        );
        assert!(!backend.holds_service_handoff());
        println!(
            "GBDBACKEND enforced_controls={:?} handoff=false verdict=canary-proven-not-installed",
            backend.enforced_controls()
        );
        drop(control);
    }
