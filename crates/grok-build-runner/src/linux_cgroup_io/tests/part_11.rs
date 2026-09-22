    // ---------------------------------------------------------------------
    // The production setup-descriptor mint, and the stopped-child descriptor
    // table.
    //
    // Two independent live halves. The first is the setup closure's own
    // building blocks — the service pipes and the endpoint validator — which
    // need no installed service and therefore run under the ordinary Linux
    // gate. The second is the stopped-child descriptor-table probe, which is
    // the measurement behind this increment's statement that the child-launch
    // closure cannot be materialised without `unsafe`.
    // ---------------------------------------------------------------------

    /// One endpoint binding, for a pipe role.
    #[cfg(target_os = "linux")]
    fn service_pipe_binding(
        role: LinuxServiceSetupEndpointRoleV1,
        access: LinuxServiceSetupDescriptorAccessV1,
    ) -> LinuxServiceSetupEndpointBindingV1 {
        LinuxServiceSetupEndpointBindingV1 {
            role,
            kind: LinuxServiceSetupEndpointKindV1::Pipe,
            access,
            close_on_exec_while_retained: true,
            source: LinuxServiceSetupEndpointSourceV1::ServicePipe,
        }
    }

    /// The production service-pipe mint answers with the end the role needs,
    /// and the endpoint validator refuses every real substitution of it.
    ///
    /// Every value varied here is a real kernel object: the other end of the
    /// same pipe, and the same end with its close-on-exec bit cleared. Nothing
    /// is synthesised.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_service_pipe_mint_answers_with_the_end_its_role_requires() {
        use std::os::fd::AsFd as _;

        for (role, access, expected_open) in [
            (
                LinuxServiceSetupEndpointRoleV1::SetupControl,
                LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                rustix::fs::OFlags::RDONLY,
            ),
            (
                LinuxServiceSetupEndpointRoleV1::SetupStatus,
                LinuxServiceSetupDescriptorAccessV1::WriteOnly,
                rustix::fs::OFlags::WRONLY,
            ),
        ] {
            let (endpoint, peer) = create_linux_native_service_setup_pipe(access)
                .expect("the production service-pipe mint creates a pipe");
            // The kernel's answers about the endpoint, before any validator.
            let status = rustix::fs::fcntl_getfl(endpoint.as_fd()).unwrap();
            let descriptor_flags = rustix::io::fcntl_getfd(endpoint.as_fd()).unwrap();
            let endpoint_metadata = endpoint.metadata().unwrap();
            let peer_metadata = peer.metadata().unwrap();
            assert_eq!(status & rustix::fs::OFlags::ACCMODE, expected_open);
            assert!(descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC));
            assert_eq!(
                OsMetadataExt::mode(&endpoint_metadata) & SETUP_DESCRIPTOR_FILE_TYPE_MASK,
                SETUP_DESCRIPTOR_PIPE_MODE
            );
            // Both ends of one pipe are one inode. That is exactly why the mint
            // creates one pipe per role and hands the peer back separately: two
            // roles holding two ends of one pipe would alias one kernel object,
            // and `validate_for` refuses that.
            assert_eq!(
                object_identity(&endpoint_metadata),
                object_identity(&peer_metadata),
                "a pipe's two ends share one inode"
            );

            let binding = service_pipe_binding(role, access);
            let authenticated = LinuxNativeServiceSetupEndpoint::from_retained(
                binding.clone(),
                endpoint.try_clone().unwrap(),
            )
            .expect("the endpoint the role requires authenticates");
            assert_eq!(authenticated.identity, object_identity(&endpoint_metadata));

            // Control 1: the other end of the same pipe. One input varied, and
            // the substituted value is a real descriptor on the same inode.
            let wrong_end =
                LinuxNativeServiceSetupEndpoint::from_retained(binding.clone(), peer)
                    .expect_err("the peer end must be refused");
            assert!(
                wrong_end.detail.contains("changed identity, access, or close-on-exec state"),
                "the peer end was refused for the wrong reason: {wrong_end:?}"
            );

            // Control 2: the same end with close-on-exec cleared by the kernel.
            let inheritable = endpoint.try_clone().unwrap();
            rustix::io::fcntl_setfd(inheritable.as_fd(), rustix::io::FdFlags::empty()).unwrap();
            let refused = LinuxNativeServiceSetupEndpoint::from_retained(binding, inheritable)
                .expect_err("a retained endpoint without close-on-exec must be refused");
            assert!(
                refused.detail.contains("changed identity, access, or close-on-exec state"),
                "the inheritable end was refused for the wrong reason: {refused:?}"
            );
            println!(
                "GBDSETUPPIPE role={role:?} access={access:?} accmode={:?} cloexec=true \
                 endpoint_inode={} peer_inode={} peer_end=refused inheritable=refused",
                status & rustix::fs::OFlags::ACCMODE,
                object_identity(&endpoint_metadata).inode,
                object_identity(&peer_metadata).inode,
            );
        }

        let read_write = create_linux_native_service_setup_pipe(
            LinuxServiceSetupDescriptorAccessV1::ReadWrite,
        )
        .expect_err("no canonical pipe role is read-write");
        assert!(read_write.detail.contains("never read-write"));
    }

    /// A real stopped child's real descriptor table, read out of procfs, and
    /// the two clauses of the plan's child table that cannot both hold.
    ///
    /// The enforced arm places four descriptors at fds 3..=6 over `SCM_RIGHTS`
    /// and reads the child's own `/proc/<pid>/fd` and `/proc/<pid>/fdinfo` while
    /// it is stopped. The control arm varies exactly one input — the order of
    /// the same four descriptors in the same placement message — and the same
    /// reads then disagree with the same expectation.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear run keeps the placement, the child's own table, and both clauses of the plan's child contract visible in the order they are measured"
    )]
    fn the_stopped_child_descriptor_table_is_read_from_the_child_and_not_the_parent() {
        use std::os::fd::AsFd as _;

        let root = std::env::temp_dir().join(format!(
            "gb-child-descriptor-probe-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create the probe scratch root");
        let root = fs::canonicalize(&root).expect("canonicalize the probe scratch root");

        // The four objects the plan puts at fds 3..=6: a sealed request memfd,
        // two service pipes, and the working directory.
        let sealed_request = create_test_setup_request(&root);
        let (setup_control, _control_peer) = create_linux_native_service_setup_pipe(
            LinuxServiceSetupDescriptorAccessV1::ReadOnly,
        )
        .unwrap();
        let (setup_status, _status_peer) = create_linux_native_service_setup_pipe(
            LinuxServiceSetupDescriptorAccessV1::WriteOnly,
        )
        .unwrap();
        let working_directory =
            Dir::open_ambient_dir(&root, cap_std::ambient_authority()).unwrap();

        // The three the plan puts at fds 0..=2 would be the target's stdio.
        // Only two of them can be delivered: fd 0 is the placement transport.
        let (target_stdout, _stdout_peer) = create_linux_native_service_setup_pipe(
            LinuxServiceSetupDescriptorAccessV1::WriteOnly,
        )
        .unwrap();
        let (target_stderr, _stderr_peer) = create_linux_native_service_setup_pipe(
            LinuxServiceSetupDescriptorAccessV1::WriteOnly,
        )
        .unwrap();

        let expected = |file: &File| object_identity(&file.metadata().unwrap());
        let expected_directory = object_identity(&working_directory.dir_metadata().unwrap());
        let image = service_bootstrap_probe_image();

        let run = |ordered: [std::os::fd::BorrowedFd<'_>; 4]| {
            let probe = spawn_linux_service_child_descriptor_probe(
                &image,
                target_stdout.try_clone().unwrap().into_std(),
                target_stderr.try_clone().unwrap().into_std(),
                &[
                    (3, ordered[0]),
                    (4, ordered[1]),
                    (5, ordered[2]),
                    (6, ordered[3]),
                ],
            )
            .expect("start the stopped-child descriptor probe");
            let pid = probe.pid();
            let table = observe_stopped_child_descriptor_table(pid, &[1, 2, 3, 4, 5, 6]);
            let transport = observe_one_stopped_child_descriptor(
                &open_authenticated_procfs_root().unwrap(),
                pid,
                0,
                "observe-child-transport",
            );
            let status = probe.kill_and_reap().expect("reap the probe");
            (table, transport, status)
        };

        // ---- enforced: the placement the plan names ------------------------
        let (table, transport, status) = run([
            sealed_request.as_fd(),
            setup_control.as_fd(),
            setup_status.as_fd(),
            working_directory.as_fd(),
        ]);
        let table = table.expect("the stopped child's descriptor table reads");
        assert!(
            !status.success(),
            "the probe is killed while stopped, so it never exits cleanly"
        );

        // Clause 1 of the plan's child table: the identities and the kinds.
        let by_fd = |target: u32| {
            *table
                .descriptors
                .iter()
                .find(|descriptor| descriptor.target_fd == target)
                .expect("every requested descriptor was observed")
        };
        assert_eq!(by_fd(3).identity, expected(&sealed_request));
        assert_eq!(by_fd(3).kind, LinuxServiceChildDescriptorKindV1::SealedRequestMemfd);
        assert_eq!(by_fd(3).access, LinuxServiceSetupDescriptorAccessV1::ReadWrite);
        assert_eq!(by_fd(4).identity, expected(&setup_control));
        assert_eq!(by_fd(4).kind, LinuxServiceChildDescriptorKindV1::Pipe);
        assert_eq!(by_fd(4).access, LinuxServiceSetupDescriptorAccessV1::ReadOnly);
        assert_eq!(by_fd(5).identity, expected(&setup_status));
        assert_eq!(by_fd(5).access, LinuxServiceSetupDescriptorAccessV1::WriteOnly);
        assert_eq!(by_fd(6).identity, expected_directory);
        assert_eq!(by_fd(6).kind, LinuxServiceChildDescriptorKindV1::Directory);

        // Clause 2, first half: descriptors delivered over `SCM_RIGHTS` and
        // placed with `F_DUPFD_CLOEXEC` carry close-on-exec, which is what the
        // plan requires of fds 3..=6.
        for target in [3, 4, 5, 6] {
            assert!(
                by_fd(target).close_on_exec,
                "fd {target} arrived over SCM_RIGHTS and must carry close-on-exec"
            );
        }
        // Clause 2, second half: descriptors delivered by `Stdio` — the only
        // mechanism that places an exact number without `unsafe` — arrive
        // **without** close-on-exec. The plan requires exactly that of fds
        // 0..=2, and requires the opposite of 3..=6, so the two halves of the
        // table cannot be delivered by one mechanism.
        for target in [1, 2] {
            assert!(
                !by_fd(target).close_on_exec,
                "fd {target} arrived through Stdio and cannot carry close-on-exec"
            );
        }
        assert_eq!(by_fd(1).identity, expected(&target_stdout));
        assert_eq!(by_fd(2).identity, expected(&target_stderr));

        // Clause 3, the closure: the child's table is exactly fds 0..=6 — and
        // fd 0 is the placement socket, not the descriptor the plan puts there.
        // A child cannot close it: `OwnedFd::from_raw_fd`,
        // `BorrowedFd::borrow_raw` and `rustix::io::close` are all `unsafe`.
        assert_eq!(table.open_fds, vec![0, 1, 2, 3, 4, 5, 6]);
        let transport = transport.expect_err("fd 0 is the transport socket, not a table kind");
        assert!(
            transport.detail.contains("socket:"),
            "fd 0 should have been refused as a socket: {transport:?}"
        );
        println!(
            "GBDCHILDFD enforced open_fds={:?} scm_cloexec=true stdio_cloexec=false \
             fd0={} verdict=table-cannot-be-the-planned-table",
            table.open_fds, transport.detail
        );

        // ---- control: the same four descriptors, one input varied ----------
        //
        // The placement list is permuted and nothing else changes: the same
        // child, the same code, the same four kernel objects, the same reads.
        let (control, _control_transport, _control_status) = run([
            setup_control.as_fd(),
            sealed_request.as_fd(),
            setup_status.as_fd(),
            working_directory.as_fd(),
        ]);
        let control = control.expect("the control child's descriptor table also reads");
        let control_fd3 = *control
            .descriptors
            .iter()
            .find(|descriptor| descriptor.target_fd == 3)
            .unwrap();
        assert_ne!(
            control_fd3.identity,
            expected(&sealed_request),
            "the control must not place the sealed request at fd 3"
        );
        assert_eq!(control_fd3.identity, expected(&setup_control));
        assert_eq!(control_fd3.kind, LinuxServiceChildDescriptorKindV1::Pipe);
        println!(
            "GBDCHILDFD control fd3_inode={} expected_inode={} verdict=refused-by-identity",
            control_fd3.identity.inode,
            expected(&sealed_request).inode,
        );

        let _ = fs::remove_dir_all(&root);
    }

    /// The first production setup-descriptor capability, minted over a live
    /// installed service.
    ///
    /// Every descriptor it holds comes from something already authenticated:
    /// the per-command directories this service created, the installer-anchored
    /// state root and journal root the bootstrap authority holds, the grant's
    /// workspace root, a sealed memfd this process created and authenticated
    /// against the anchored statement, and five pipes created one per role. The
    /// mint then submits the whole closure to the **untouched** `validate_for`.
    ///
    /// Three control arms follow, each varying exactly one input and each
    /// substituting a real kernel object rather than an invented value.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear run keeps every authenticated source, the mint, and the three controls visible in the order they happen"
    )]
    fn the_production_setup_descriptor_mint_opens_a_live_closure_and_refuses_every_substitution() {
        use crate::linux_command_plan::{
            ADMITTED_BUBBLEWRAP_IMAGE_V1, AuthenticatedBubblewrapImageV1, LinuxAuthenticatedFileV1,
            LinuxMeasuredTargetImageV1, LinuxProductionCommandPlanInputsV1, LinuxProgramImageV1,
            LinuxRetainedObjectIdentityV1, LinuxRetainedObjectKindV1, TARGET_IMAGE_OBJECT_ID,
        };

        let Some(service) = InstalledService::from_environment() else {
            assert!(environment_path(INSTALL_ROOT_VARIABLE).is_none() || own_effective_uid() == 0);
            return;
        };
        let expected = service.independently_observed_binding();
        let (handoff, _) = service.mint().expect("mint the installed handoff");
        let (capability, host_roots) = handoff
            .into_state_root_capability(&expected)
            .expect("derive the state-root capability from the installed anchor");
        let facts = match capability.observe_anchored_plan_facts(&host_roots) {
            Ok(facts) => facts,
            Err(error) => {
                assert!(
                    service_owned_cgroup_parent(),
                    "the anchored facts must mint on a delegator-owned parent: {error:?}"
                );
                println!("GBDSETUPMINT arm=service-owned-parent closure=not-minted");
                return;
            }
        };
        let anchored = facts.plan_anchored_facts();

        let scratch =
            std::env::temp_dir().join(format!("gb-setup-mint-{}", own_effective_uid()));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).expect("create the mint scratch root");
        let scratch = fs::canonicalize(&scratch).expect("canonicalize the mint scratch root");
        let workspace = scratch.join("workspace");
        fs::create_dir(&workspace).expect("create the mint workspace");
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o755)).unwrap();

        let target_path = build_static_target_image(&scratch);
        let target_name = target_path.to_str().expect("UTF-8 target path").to_owned();
        let held_target = std::fs::File::open(&target_path).expect("hold the target open");
        let target_bytes = fs::read(&target_path).expect("read the target completely");
        let target_length = u64::try_from(target_bytes.len()).unwrap();
        let measured = LinuxMeasuredTargetImageV1::measure(
            &held_target,
            target_length,
            anchored.host_architecture,
            "the target executable",
        )
        .expect("the real static target measures");
        let target_image = LinuxProgramImageV1::from_measured_image(
            &target_name,
            LinuxAuthenticatedFileV1::from_complete_readback(
                TARGET_IMAGE_OBJECT_ID,
                &target_name,
                target_length,
                Digest::sha256(&target_bytes),
            )
            .expect("authenticate the target readback"),
            &measured,
        )
        .expect("join the target slot");
        let target_object = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            TARGET_IMAGE_OBJECT_ID,
            LinuxRetainedObjectKindV1::RegularFile,
            observe_held_file(&held_target),
        )
        .expect("mint the target's retained identity");

        let fixture = crate::linux_command_plan::tests::plan_authority_fixture(
            crate::wire::RunnerRole::Worker,
            &workspace,
            &target_name,
            grok_build_core::MutationMode::ShadowWorkspace,
        );
        let input_snapshot = fixture
            .authority
            .envelope()
            .effect
            .as_ref()
            .expect("effect context")
            .input_snapshot
            .clone();

        let state_root_dir = open_ambient(&service.state_root);
        let workspace_dir = open_ambient(&workspace);
        let command_directory = leaf_shaped_name(0x77);
        let directories = create_per_command_retained_directories(
            &state_root_dir,
            &workspace_dir,
            &command_directory,
            expected.owner_uid,
        )
        .expect("create and observe this command's retained directories");
        // A second, equally real set. It is this test's sharpest control: the
        // substituted directories were created by the same production call, so
        // the refusal is attributable to identity and to nothing else.
        let control_directory = leaf_shaped_name(0x78);
        let control_directories = create_per_command_retained_directories(
            &state_root_dir,
            &workspace_dir,
            &control_directory,
            expected.owner_uid,
        )
        .expect("create a second, equally real retained directory set");

        let bubblewrap_path = ADMITTED_BUBBLEWRAP_IMAGE_V1.resolved_path;
        let cleanup = |scratch: &Path| {
            let _ = fs::remove_dir_all(scratch);
            for name in [&command_directory, &control_directory] {
                let _ = fs::remove_dir_all(
                    service
                        .state_root
                        .join(SERVICE_PER_COMMAND_RETAINED_ROOT)
                        .join(name),
                );
            }
        };
        let held_bubblewrap = match std::fs::File::open(bubblewrap_path) {
            Ok(file) => file,
            Err(error) => {
                assert_eq!(
                    error.raw_os_error(),
                    Some(rustix::io::Errno::NOENT.raw_os_error())
                );
                println!(
                    "GBDSETUPMINT bubblewrap-absent path={bubblewrap_path} errno=ENOENT \
                     closure=not-minted (this image admits no Bubblewrap, so no plan can exist)"
                );
                cleanup(&scratch);
                return;
            }
        };
        let bubblewrap_bytes = fs::read(bubblewrap_path).expect("read Bubblewrap completely");
        let bubblewrap = AuthenticatedBubblewrapImageV1::authenticate_admitted(
            bubblewrap_path,
            observe_held_file(&held_bubblewrap),
            &bubblewrap_bytes,
        )
        .expect("the admitted Bubblewrap image authenticates");

        // ---- component source 3b: the two mandatory kernel-control artefacts
        // Created and compiled against this running kernel, from the very
        // descriptors the directories above are held by. A host with no
        // Landlock refuses here, and no plan exists rather than a plan that
        // describes a ruleset nothing built.
        let mandatory_controls = match directories.mint_mandatory_control_artefacts(
            &workspace_dir,
            facts.host_architecture.architecture().audit_architecture(),
        ) {
            Ok(artefacts) => artefacts,
            Err(error) => {
                println!(
                    "GBDMINT mandatory-controls-unavailable detail={:?} plan=not-minted \
                     (this host cannot create the ruleset the plan would commit)",
                    error.detail
                );
                cleanup(&scratch);
                return;
            }
        };

        // ---- the sealed setup channel, created by production code ----------
        let statement = facts.setup_channel_statement(crate::wire::RunnerRole::Worker, &input_snapshot);
        let sealed = seal_linux_native_service_setup_channel(&statement)
            .expect("the service seals and authenticates its own setup channel");
        let plan = LinuxProductionCommandPlanInputsV1 {
            authority: fixture.authority.clone(),
            grant: &fixture.grant,
            policy: &fixture.policy,
            anchored,
            bubblewrap: &bubblewrap,
            setup_channel: sealed.authenticated(),
            target_image: &target_image,
            target_object: &target_object,
            directories: directories.identities(),
            mandatory_controls: &mandatory_controls,
        }
        .mint(fixture.native_launch.clone())
        .expect("the twelve components validate into one production plan");

        // The command's working directory is created under the retained
        // execution root *after* the directory observation, because that
        // observation is of a freshly created empty tree and its link count is
        // evidence about that. The mint reaches it only through the retained
        // descriptor, one `O_NOFOLLOW` component at a time.
        let cwd_component = plan
            .service_setup_descriptor_binding()
            .expect("project the setup closure")
            .cwd
            .root_relative_path;
        if !cwd_component.is_empty() {
            directories.descriptors()[1]
                .create_dir(&cwd_component)
                .expect("create the command's working directory under the execution root");
        }

        // ---- journal, bootstrap, admit, launch images ----------------------
        let (journal_handoff, _) = service.mint().expect("mint a second handoff");
        let (journal_capability, journal_roots) = journal_handoff
            .into_state_root_capability(&expected)
            .expect("derive the journal capability");
        let mut journal_authority =
            LinuxServiceCommandJournalAuthority::open_authenticated_service_singleton(
                journal_capability,
                service_journal_binding_from_plan(&expected),
            )
            .expect("open the service-owned singleton journal");
        // One capability mints exactly one authority. The bootstrap borrows it
        // for the duration of `publish`; the journaled plan then owns it.
        let bootstrap = LinuxNativeServiceBootstrapAuthority::open_authenticated(
            &mut journal_authority,
            journal_roots,
            &plan,
        )
        .expect("the production bootstrap authority mints against this plan");
        let journaled = journal_linux_production_command_plan(plan.clone(), journal_authority)
            .expect("durably commit the production plan");
        let bootstrapped =
            bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)
                .expect("join the journaled plan and the bootstrap");
        let admission = admit_linux_native_service_command(
            bootstrapped,
            LinuxNativeServiceProcessImageAuthority::observe_current_process()
                .expect("observe this process image"),
        )
        .expect("admit the command into the native service lifetime");
        let launch_authority = select_linux_native_service_launch_images(admission)
            .expect("select the immutable launch-image closure");

        // ---- the enforced arm: the production setup-descriptor mint --------
        let (closure, peers) = LinuxNativeServiceSetupDescriptorCapability::open_authenticated(
            &launch_authority,
            &directories,
            &workspace_dir,
            sealed,
        )
        .expect("the production setup-descriptor capability mints");
        closure
            .revalidate_for_test(&plan)
            .expect("the minted closure revalidates against the same untouched validator");
        assert!(!LinuxNativeServiceSetupDescriptorCapability::permits_execution());
        println!(
            "GBDSETUPMINT enforced endpoints={} mount_sources={} peers={} roles={:?} \
             execution_root={}:{} cwd={}:{} journal_root={}:{} verdict=minted",
            closure.endpoints.len(),
            closure.read_only_mount_sources.len(),
            peers.len(),
            peers.roles(),
            closure.execution_root.identity.device,
            closure.execution_root.identity.inode,
            closure.cwd.identity.device,
            closure.cwd.identity.inode,
            closure.singleton_journal_root.identity.device,
            closure.singleton_journal_root.identity.inode,
        );
        for endpoint in &closure.endpoints {
            println!(
                "GBDSETUPMINT endpoint role={:?} kind={:?} access={:?} inode={}",
                endpoint.binding.role,
                endpoint.binding.kind,
                endpoint.binding.access,
                endpoint.identity.inode
            );
        }

        // ---- control 1: a real directory in the workspace root's place -----
        let control_channel = seal_linux_native_service_setup_channel(&statement)
            .expect("seal a second, equally real setup channel");
        let refusal = LinuxNativeServiceSetupDescriptorCapability::open_authenticated(
            &launch_authority,
            &directories,
            directories.descriptors()[2],
            control_channel,
        )
        .expect_err("a different real directory in the workspace root's place must be refused");
        println!("GBDSETUPMINT control=workspace-root detail={}", refusal.detail);

        // ---- control 2: a second, equally real per-command directory set ---
        let control_channel = seal_linux_native_service_setup_channel(&statement)
            .expect("seal a third, equally real setup channel");
        let refusal = LinuxNativeServiceSetupDescriptorCapability::open_authenticated(
            &launch_authority,
            &control_directories,
            &workspace_dir,
            control_channel,
        )
        .expect_err("another command's retained directories must be refused");
        println!("GBDSETUPMINT control=retained-directories detail={}", refusal.detail);

        // ---- control 3: a real sealed channel over another real statement --
        let other_statement =
            facts.setup_channel_statement(crate::wire::RunnerRole::FinalVerifier, &input_snapshot);
        let other_channel = seal_linux_native_service_setup_channel(&other_statement)
            .expect("seal a real channel carrying another anchored role");
        let refusal = LinuxNativeServiceSetupDescriptorCapability::open_authenticated(
            &launch_authority,
            &directories,
            &workspace_dir,
            other_channel,
        )
        .expect_err("a sealed channel for another role must be refused");
        println!("GBDSETUPMINT control=setup-channel detail={}", refusal.detail);

        // ---- the next state, and where it stops ----------------------------
        let setup_authority = bind_linux_native_service_setup_descriptors(launch_authority, closure)
            .expect("the setup-descriptor authority binds");
        setup_authority
            .revalidate_for_test()
            .expect("the setup authority revalidates");
        assert!(!LinuxNativeServiceSetupDescriptorAuthority::permits_execution());
        println!("GBDSETUPMINT next=child-launch-closure production_mint=present");
        // The chain continues into the production child-launch-closure mint,
        // which materialises this plan's exact descriptor table in a real
        // child, stops it, and reads the table back out of that child.
        mint_and_prove_the_child_launch_closure(
            setup_authority,
            &fixture.grant,
            &fixture.policy,
            &scratch,
        );
        drop(peers);
        cleanup(&scratch);
    }
