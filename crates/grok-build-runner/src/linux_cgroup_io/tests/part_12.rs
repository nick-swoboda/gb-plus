    // ---------------------------------------------------------------------
    // The production child-launch-closure mint.
    //
    // Two halves again, and the split is the same one the setup mint has. The
    // first half needs no installed service: it materialises the plan's exact
    // seven-descriptor table in a real child out of seven real kernel objects
    // and reads it back out of that child's own procfs entries, so it runs
    // under the ordinary Linux gate. The second half is the live mint over an
    // installed service, and it runs only under the anchor canary.
    // ---------------------------------------------------------------------

    /// The seven real kernel objects the plan's child table is made of.
    ///
    /// Nothing here is a fixture or a stand-in: five pipes created one per role
    /// by the production pipe mint, one sealed memfd, and one directory.
    #[cfg(target_os = "linux")]
    struct ChildLaunchClosureObjects {
        sealed_request: File,
        sealed_request_read_only: std::os::fd::OwnedFd,
        setup_control: File,
        setup_status: File,
        working_directory: Dir,
        target_stdin: File,
        target_stdout: File,
        target_stderr: File,
        _peers: Vec<File>,
        root: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl ChildLaunchClosureObjects {
        fn create() -> Self {
            use std::os::fd::{AsFd as _, AsRawFd as _};

            let root = std::env::temp_dir()
                .join(format!("gb-child-launch-closure-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("create the closure scratch root");
            let root = fs::canonicalize(&root).expect("canonicalize the closure scratch root");

            let sealed_request = create_test_setup_request(&root);
            // The plan gives the child a **read-only** view of a request the
            // service retains read-write, and a duplicate cannot narrow an
            // access mode. The same inode is re-opened through its own procfs
            // entry, which is exactly what the production mint does.
            let procfs = open_authenticated_procfs_root().expect("open procfs");
            let sealed_request_read_only = rustix::fs::openat(
                &procfs,
                format!("self/fd/{}", sealed_request.as_fd().as_raw_fd()),
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .expect("re-open the sealed request read-only");

            let mut peers = Vec::new();
            let mut pipe = |access| {
                let (endpoint, peer) = create_linux_native_service_setup_pipe(access)
                    .expect("the production service-pipe mint creates a pipe");
                peers.push(peer);
                endpoint
            };
            let setup_control = pipe(LinuxServiceSetupDescriptorAccessV1::ReadOnly);
            let setup_status = pipe(LinuxServiceSetupDescriptorAccessV1::WriteOnly);
            let target_stdin = pipe(LinuxServiceSetupDescriptorAccessV1::ReadOnly);
            let target_stdout = pipe(LinuxServiceSetupDescriptorAccessV1::WriteOnly);
            let target_stderr = pipe(LinuxServiceSetupDescriptorAccessV1::WriteOnly);
            let working_directory =
                Dir::open_ambient_dir(&root, cap_std::ambient_authority()).unwrap();
            Self {
                sealed_request,
                sealed_request_read_only,
                setup_control,
                setup_status,
                working_directory,
                target_stdin,
                target_stdout,
                target_stderr,
                _peers: peers,
                root,
            }
        }

        fn identity(file: &File) -> ObjectIdentity {
            object_identity(&file.metadata().unwrap())
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ChildLaunchClosureObjects {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// The plan's complete child descriptor table, materialised in a real child
    /// and read back out of that child, with the one call that makes it
    /// possible removed in the control.
    ///
    /// The enforced arm is the production probe mode the mint uses. The control
    /// arm is the **same binary, the same seven kernel objects and the same
    /// reads**, with exactly one call not made: the `dup2` that installs fd 0
    /// over the placement transport. That single difference is the whole
    /// distance between "the table cannot be the planned table" — which is what
    /// the previous increment measured — and the table this mint now holds.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear run keeps the seven objects, the child's own table, and both controls visible in the order they are measured"
    )]
    fn the_child_launch_closure_table_is_materialised_in_a_real_child_and_read_back() {
        use std::os::fd::AsFd as _;

        let objects = ChildLaunchClosureObjects::create();
        let image = service_bootstrap_probe_image();
        let expected_directory =
            object_identity(&objects.working_directory.dir_metadata().unwrap());

        let stdio = || {
            (
                objects.target_stdout.try_clone().unwrap().into_std(),
                objects.target_stderr.try_clone().unwrap().into_std(),
            )
        };
        let read_table = |probe: LinuxServiceChildDescriptorProbe, targets: &[u32]| {
            let pid = probe.pid();
            let table = observe_stopped_child_descriptor_table(pid, targets);
            let transport = observe_one_stopped_child_descriptor(
                &open_authenticated_procfs_root().unwrap(),
                pid,
                0,
                "observe-child-transport",
            );
            let status = probe.kill_and_reap().expect("reap the probe");
            (table, transport, status)
        };

        // ---- enforced: every slot the plan names, in one real child --------
        let (stdout, stderr) = stdio();
        let (table, transport, status) = read_table(
            spawn_linux_service_child_launch_closure_probe(
                &image,
                stdout,
                stderr,
                &[
                    (0, objects.target_stdin.as_fd()),
                    (3, objects.sealed_request_read_only.as_fd()),
                    (4, objects.setup_control.as_fd()),
                    (5, objects.setup_status.as_fd()),
                    (6, objects.working_directory.as_fd()),
                ],
            )
            .expect("start the child-launch closure probe"),
            &[0, 1, 2, 3, 4, 5, 6],
        );
        let table = table.expect("the stopped child's complete descriptor table reads");
        assert!(
            !status.success(),
            "the child is killed while stopped, so it never exits cleanly"
        );
        transport.expect("fd 0 is now a pipe the plan names, not the placement socket");

        // Clause 1: the table is closed at exactly the plan's contiguous run.
        assert_eq!(table.open_fds, vec![0, 1, 2, 3, 4, 5, 6]);
        let by_fd = |target: u32| {
            *table
                .descriptors
                .iter()
                .find(|descriptor| descriptor.target_fd == target)
                .expect("every planned descriptor was observed")
        };

        // Clause 2: every slot holds the exact kernel object.
        assert_eq!(
            by_fd(0).identity,
            ChildLaunchClosureObjects::identity(&objects.target_stdin)
        );
        assert_eq!(
            by_fd(1).identity,
            ChildLaunchClosureObjects::identity(&objects.target_stdout)
        );
        assert_eq!(
            by_fd(2).identity,
            ChildLaunchClosureObjects::identity(&objects.target_stderr)
        );
        assert_eq!(
            by_fd(3).identity,
            ChildLaunchClosureObjects::identity(&objects.sealed_request)
        );
        assert_eq!(
            by_fd(4).identity,
            ChildLaunchClosureObjects::identity(&objects.setup_control)
        );
        assert_eq!(
            by_fd(5).identity,
            ChildLaunchClosureObjects::identity(&objects.setup_status)
        );
        assert_eq!(by_fd(6).identity, expected_directory);

        // Clause 3: the kinds and the access modes the plan gives the child.
        // Fd 3 is read-only in the child while the service retains the same
        // inode read-write, which is the reason the mint re-opens rather than
        // duplicates.
        for (target, kind, access) in [
            (
                0,
                LinuxServiceChildDescriptorKindV1::Pipe,
                LinuxServiceSetupDescriptorAccessV1::ReadOnly,
            ),
            (
                1,
                LinuxServiceChildDescriptorKindV1::Pipe,
                LinuxServiceSetupDescriptorAccessV1::WriteOnly,
            ),
            (
                2,
                LinuxServiceChildDescriptorKindV1::Pipe,
                LinuxServiceSetupDescriptorAccessV1::WriteOnly,
            ),
            (
                3,
                LinuxServiceChildDescriptorKindV1::SealedRequestMemfd,
                LinuxServiceSetupDescriptorAccessV1::ReadOnly,
            ),
            (
                4,
                LinuxServiceChildDescriptorKindV1::Pipe,
                LinuxServiceSetupDescriptorAccessV1::ReadOnly,
            ),
            (
                5,
                LinuxServiceChildDescriptorKindV1::Pipe,
                LinuxServiceSetupDescriptorAccessV1::WriteOnly,
            ),
            (
                6,
                LinuxServiceChildDescriptorKindV1::Directory,
                LinuxServiceSetupDescriptorAccessV1::ReadOnly,
            ),
        ] {
            assert_eq!(by_fd(target).kind, kind, "fd {target} kind");
            assert_eq!(by_fd(target).access, access, "fd {target} access");
        }

        // Clause 4: close-on-exec, read from the child's own `fdinfo`. Fds 0..=2
        // crossed this child's `execve` and therefore cannot carry the bit;
        // fds 3..=6 were created **after** that `execve` by `F_DUPFD_CLOEXEC`
        // and do. That is the measured reason a `pre_exec` closure cannot
        // deliver this table: anything it sets close-on-exec is closed by the
        // very exec it precedes.
        for target in [0, 1, 2] {
            assert!(
                !by_fd(target).close_on_exec,
                "fd {target} crossed execve and cannot carry close-on-exec"
            );
        }
        for target in [3, 4, 5, 6] {
            assert!(
                by_fd(target).close_on_exec,
                "fd {target} was placed with F_DUPFD_CLOEXEC after execve"
            );
        }
        println!(
            "GBDCHILDCLOSURE enforced open_fds={:?} \
             cloexec_clear=[0, 1, 2] cloexec_set=[3, 4, 5, 6] \
             fd0_inode={} fd3_inode={} fd3_access={:?} fd6_kind={:?} \
             verdict=the-planned-table",
            table.open_fds,
            by_fd(0).identity.inode,
            by_fd(3).identity.inode,
            by_fd(3).access,
            by_fd(6).kind,
        );

        // ---- control 1: the same child, without the one `dup2` -------------
        //
        // The observe mode places fds 3..=6 identically and never installs fd 0,
        // so the transport socket stays where the plan puts the target's stdin.
        // One call varied; the same reads then refuse.
        let (stdout, stderr) = stdio();
        let (control, transport, _status) = read_table(
            spawn_linux_service_child_descriptor_probe(
                &image,
                stdout,
                stderr,
                &[
                    (3, objects.sealed_request_read_only.as_fd()),
                    (4, objects.setup_control.as_fd()),
                    (5, objects.setup_status.as_fd()),
                    (6, objects.working_directory.as_fd()),
                ],
            )
            .expect("start the same child without the fd 0 installation"),
            &[1, 2, 3, 4, 5, 6],
        );
        control.expect("the control child's table also reads");
        let transport = transport.expect_err("fd 0 is the placement socket in the control");
        assert!(
            transport.detail.contains("socket:"),
            "fd 0 should have been refused as a socket: {transport:?}"
        );
        println!(
            "GBDCHILDCLOSURE control=no-dup2 fd0={} verdict=table-cannot-be-the-planned-table",
            transport.detail
        );

        // ---- control 2: the same seven objects, one placement permuted -----
        let (stdout, stderr) = stdio();
        let (permuted, _transport, _status) = read_table(
            spawn_linux_service_child_launch_closure_probe(
                &image,
                stdout,
                stderr,
                &[
                    (0, objects.target_stdin.as_fd()),
                    (3, objects.setup_control.as_fd()),
                    (4, objects.sealed_request_read_only.as_fd()),
                    (5, objects.setup_status.as_fd()),
                    (6, objects.working_directory.as_fd()),
                ],
            )
            .expect("start the permuted child"),
            &[0, 1, 2, 3, 4, 5, 6],
        );
        let permuted = permuted.expect("the permuted child's table also reads");
        let permuted_fd3 = *permuted
            .descriptors
            .iter()
            .find(|descriptor| descriptor.target_fd == 3)
            .unwrap();
        assert_eq!(
            permuted_fd3.identity,
            ChildLaunchClosureObjects::identity(&objects.setup_control)
        );
        assert_ne!(
            permuted_fd3.identity,
            ChildLaunchClosureObjects::identity(&objects.sealed_request)
        );
        println!(
            "GBDCHILDCLOSURE control=permuted fd3_inode={} expected_inode={} \
             verdict=refused-by-identity",
            permuted_fd3.identity.inode,
            ChildLaunchClosureObjects::identity(&objects.sealed_request).inode,
        );
    }

    /// The production mint's compile-level position, asserted rather than
    /// described.
    ///
    /// The two constants exist for the same reason the bootstrap and setup
    /// mints have theirs: a build in which the production constructor became
    /// test-only, changed shape or disappeared fails to compile instead of
    /// quietly regressing to "no production mint exists". The route function is
    /// the statement that `LinuxCgroupIo::open_service_owned` is reachable from
    /// production code, and the assertions below are the statement that nothing
    /// on that route grants execution.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_child_launch_closure_has_a_production_mint_that_grants_nothing() {
        let mint: LinuxNativeServiceChildLaunchClosureMint =
            LINUX_NATIVE_SERVICE_CHILD_LAUNCH_CLOSURE_PRODUCTION_MINT;
        assert!(
            std::ptr::fn_addr_eq(
                mint,
                LinuxNativeServiceChildLaunchClosureCapability::open_authenticated
                    as LinuxNativeServiceChildLaunchClosureMint,
            ),
            "the production mint constant must name the production constructor"
        );
        // The route from setup custody to the service-owned backend is ordinary
        // production code, and this binding is where a build that made any step
        // of it `cfg(test)` stops compiling.
        let route: fn(
            LinuxNativeServiceSetupDescriptorAuthority,
        ) -> Result<LinuxCgroupIo, CgroupIoFailure> = open_linux_native_service_owned_backend;
        assert!(
            std::ptr::fn_addr_eq(route, open_linux_native_service_owned_backend as fn(_) -> _),
            "the production route to the service-owned backend must exist"
        );
        assert!(!LinuxNativeServiceChildLaunchClosureCapability::permits_execution());
        assert!(!LinuxNativeServiceChildLaunchClosureAuthority::permits_execution());
        assert!(!LinuxNativeServiceSetupDescriptorAuthority::permits_execution());
    }

    /// Mints the child-launch closure over a live setup authority, and refuses
    /// every real substitution of the child table.
    ///
    /// Called from the live anchor-canary chain, which is the only place a
    /// genuine `LinuxNativeServiceSetupDescriptorAuthority` exists. Each control
    /// varies exactly one input and every substituted value is a real kernel
    /// object read out of a real stopped child.
    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear run keeps the live mint, the child's own table and all three real substitutions visible in the order they happen"
    )]
    fn mint_and_prove_the_child_launch_closure(
        setup_authority: LinuxNativeServiceSetupDescriptorAuthority,
        grant: &grok_build_core::IssuedWorkspaceGrant,
        policy: &grok_build_core::CompiledExecutionPolicy,
        scratch: &Path,
    ) {
        use std::os::fd::AsFd as _;

        // ---- the enforced arm: the production child-launch mint ------------
        let closure =
            LinuxNativeServiceChildLaunchClosureCapability::open_authenticated(&setup_authority)
                .expect("the production child-launch closure capability mints");
        closure
            .revalidate_for_test(&setup_authority)
            .expect("the minted closure revalidates against the same untouched validator");
        assert!(!LinuxNativeServiceChildLaunchClosureCapability::permits_execution());
        let observed = closure
            .observed_child_table()
            .expect("the production mint carries a real stopped child's table");
        println!(
            "GBDCHILDMINT enforced pid={} open_fds={:?} slots={} verdict=minted",
            observed.pid,
            observed.open_fds,
            observed.descriptors.len(),
        );
        for slot in &observed.descriptors {
            println!(
                "GBDCHILDMINT slot fd={} kind={:?} access={:?} cloexec={} inode={} mnt_id={}",
                slot.target_fd,
                slot.kind,
                slot.access,
                slot.close_on_exec,
                slot.identity.inode,
                slot.mount_id,
            );
        }

        // The controls all re-materialise the same table with exactly one input
        // varied, and submit the child's own reading of it to the same
        // validator the mint used.
        let plan = &setup_authority.bootstrapped.journaled.plan;
        let expected = plan
            .service_child_launch_closure_binding()
            .expect("project the plan's child table");
        let slots = resolve_linux_native_service_child_launch_slots(
            &setup_authority.setup_descriptors,
            &expected.inner_launcher_descriptor_table,
            "control-linux-native-service-child-launch-closure",
        )
        .expect("resolve the same retained descriptors the mint resolved");
        let descriptor_of = |target: u32| {
            slots
                .iter()
                .find(|slot| slot.binding.target_fd == target)
                .expect("every planned slot resolved")
                .descriptor
                .as_fd()
        };
        let stdio = || {
            (
                std::fs::File::from(
                    rustix::io::fcntl_dupfd_cloexec(descriptor_of(1), 0).unwrap(),
                ),
                std::fs::File::from(
                    rustix::io::fcntl_dupfd_cloexec(descriptor_of(2), 0).unwrap(),
                ),
            )
        };
        let planned_fds = expected
            .inner_launcher_descriptor_table
            .iter()
            .map(|descriptor| descriptor.target_fd)
            .collect::<Vec<_>>();
        let materialise = |placements: &[(u32, std::os::fd::BorrowedFd<'_>)],
                           closure_mode: bool| {
            let (stdout, stderr) = stdio();
            let image = service_bootstrap_probe_image();
            let probe = if closure_mode {
                spawn_linux_service_child_launch_closure_probe(&image, stdout, stderr, placements)
            } else {
                spawn_linux_service_child_descriptor_probe(&image, stdout, stderr, placements)
            }
            .expect("start a control child");
            let pid = probe.pid();
            let table = observe_stopped_child_descriptor_table(pid, &planned_fds);
            probe.kill_and_reap().expect("reap the control child");
            table.map(|table| LinuxNativeServiceStoppedChildTable {
                pid,
                open_fds: table.open_fds,
                descriptors: table
                    .descriptors
                    .into_iter()
                    .map(|descriptor| LinuxNativeServiceObservedChildDescriptor {
                        target_fd: descriptor.target_fd,
                        identity: descriptor.identity,
                        access: descriptor.access,
                        close_on_exec: descriptor.close_on_exec,
                        kind: descriptor.kind,
                        mount_id: descriptor.mount_id,
                    })
                    .collect(),
            })
        };

        // ---- control 1: the same child without the fd 0 installation -------
        let refusal = materialise(
            &[
                (3, descriptor_of(3)),
                (4, descriptor_of(4)),
                (5, descriptor_of(5)),
                (6, descriptor_of(6)),
            ],
            false,
        )
        .expect_err("a table whose fd 0 is the placement socket must be refused");
        println!("GBDCHILDMINT control=no-dup2 detail={}", refusal.detail);

        // ---- control 2: the same descriptors, fds 3 and 4 permuted ---------
        let permuted = materialise(
            &[
                (0, descriptor_of(0)),
                (3, descriptor_of(4)),
                (4, descriptor_of(3)),
                (5, descriptor_of(5)),
                (6, descriptor_of(6)),
            ],
            true,
        )
        .expect("the permuted child's table reads");
        let refusal = validate_observed_child_descriptor_table(
            &permuted,
            &expected.inner_launcher_descriptor_table,
            &setup_authority.setup_descriptors,
        )
        .expect_err("a permuted child table must be refused");
        assert!(refusal.detail.contains("not the retained"));
        println!("GBDCHILDMINT control=permuted detail={}", refusal.detail);

        // ---- control 3: the sealed request at the access the service holds --
        //
        // The same inode at fd 3, delivered as the read-write descriptor the
        // service retains instead of the read-only view the plan gives the
        // child. Only the access mode differs, and only the access mode refuses.
        let retained_request = setup_authority
            .setup_descriptors
            .endpoints
            .iter()
            .find(|endpoint| {
                endpoint.binding.role == LinuxServiceSetupEndpointRoleV1::SetupRequest
            })
            .expect("the setup closure retains its sealed request")
            .file
            .as_fd();
        let crossed = materialise(
            &[
                (0, descriptor_of(0)),
                (3, retained_request),
                (4, descriptor_of(4)),
                (5, descriptor_of(5)),
                (6, descriptor_of(6)),
            ],
            true,
        )
        .expect("the crossed-access child's table reads");
        let refusal = validate_observed_child_descriptor_table(
            &crossed,
            &expected.inner_launcher_descriptor_table,
            &setup_authority.setup_descriptors,
        )
        .expect_err("the service's own read-write request must be refused at fd 3");
        assert!(refusal.detail.contains("not the planned"));
        println!("GBDCHILDMINT control=crossed-access detail={}", refusal.detail);
        drop(slots);

        // ---- the next state, and where it stops ----------------------------
        let child_authority =
            bind_linux_native_service_child_launch_closure(setup_authority, closure)
                .expect("the child-launch closure authority binds");
        child_authority
            .revalidate_for_test()
            .expect("the child-launch authority revalidates");
        assert!(!LinuxNativeServiceChildLaunchClosureAuthority::permits_execution());
        let mechanics = retain_linux_native_service_mechanics_authority(child_authority)
            .expect("the mechanics authority retains this plan's custody");
        println!("GBDCHILDMINT next=open_service_owned production_route=present");

        // ---- the first call `open_service_owned` has ever received ---------
        //
        // Everything above is the route the previous increment proved
        // constructible and did not take. This is the call, and whatever it
        // answers is the measurement: a refusal from these real inputs is a
        // result, not a failure of the harness.
        match LinuxCgroupIo::open_service_owned(mechanics) {
            Ok(backend) => {
                println!("GBDBACKEND enforced open_service_owned=constructed");
                // The chain continues into the production `LinuxCgroupV2Backend`
                // itself, which composes around this handoff and prepares its
                // own live command domain on generation `linux-cgroup-v2-v1`.
                inhabit_and_prove_the_linux_command_domain(backend, grant, policy, scratch);
            }
            Err(failure) => println!(
                "GBDBACKEND open_service_owned=refused operation={} certainty={:?} detail={}",
                failure.operation, failure.certainty, failure.detail
            ),
        }
    }
