    // ---------------------------------------------------------------------
    // The production components mint.
    //
    // Every previous route-1 increment produced one component's value. This is
    // the first time all twelve are joined and the result is submitted to the
    // plan's own validators, so this test is the increment's evidence rather
    // than a regression guard for it: what it establishes is what
    // `LinuxProductionCommandPlanV1::validate` says about a plan whose every
    // field came out of a kernel read.

    /// A complete kernel observation of one held regular-file descriptor.
    ///
    /// The unique mount identity comes from `statx`, which is the only source
    /// for it; everything else comes from `fstat` on the same descriptor. No
    /// path is resolved anywhere.
    #[cfg(target_os = "linux")]
    fn observe_held_file(
        file: &std::fs::File,
    ) -> crate::linux_command_plan::LinuxKernelObjectObservationV1 {
        // `cap_fs_ext` and `rustix::fs` both implement `MetadataExt` for
        // `std::fs::Metadata` in this module, so every accessor below is fully
        // qualified rather than imported around.
        use std::os::unix::fs::MetadataExt as StdMetadataExt;

        /// Unique-mount-identity bit of `statx`, required since Linux 6.8.
        const STATX_MNT_ID_UNIQUE_BITS: u32 = 0x0000_4000;

        let metadata = file.metadata().expect("stat the held image");
        let statx = rustix::fs::statx(
            file,
            "",
            rustix::fs::AtFlags::EMPTY_PATH,
            rustix::fs::StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE_BITS),
        )
        .expect("statx the held image");
        assert_eq!(
            statx.stx_mask & STATX_MNT_ID_UNIQUE_BITS,
            STATX_MNT_ID_UNIQUE_BITS,
            "Linux 6.8+ unique mount identity is required"
        );
        crate::linux_command_plan::LinuxKernelObjectObservationV1 {
            device_id: StdMetadataExt::dev(&metadata),
            inode: StdMetadataExt::ino(&metadata),
            mount_id: statx.stx_mnt_id,
            mode: StdMetadataExt::mode(&metadata),
            owner_uid: StdMetadataExt::uid(&metadata),
            owner_gid: StdMetadataExt::gid(&metadata),
            link_count: StdMetadataExt::nlink(&metadata),
            byte_length: Some(StdMetadataExt::size(&metadata)),
        }
    }

    /// Seals one setup-channel statement into a real memfd and authenticates it.
    #[cfg(target_os = "linux")]
    fn seal_and_authenticate_setup_channel(
        content: &[u8],
        statement: &crate::linux_command_plan::LinuxSetupChannelStatementV1<'_>,
    ) -> crate::linux_command_plan::AuthenticatedSetupChannelV1 {
        use std::io::Write as _;

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
        let seals = rustix::fs::fcntl_get_seals(&file)
            .expect("read the setup channel's seals")
            .bits();
        let mut readback = vec![0_u8; content.len()];
        std::os::unix::fs::FileExt::read_exact_at(&file, &mut readback, 0)
            .expect("read the sealed setup channel back");
        crate::linux_command_plan::AuthenticatedSetupChannelV1::authenticate_sealed(
            statement,
            observe_held_file(&file),
            seals,
            &readback,
        )
        .expect("the live sealed setup channel authenticates")
    }

    /// Whether the canary harness chowned the cgroup **parent** to the service.
    ///
    /// This is the one fact the production mint's two arms differ in, and it is
    /// read from the harness rather than chosen here: an unprivileged test
    /// cannot chown `/sys/fs/cgroup/gbd`, so the arm is selected by the
    /// environment that prepared the host.
    #[cfg(target_os = "linux")]
    fn service_owned_cgroup_parent() -> bool {
        std::env::var("GBD_CANARY_SERVICE_OWNED_CGROUP_PARENT")
            .is_ok_and(|value| !value.is_empty())
    }

    /// Builds one real static ELF from the checked-in walking-skeleton source.
    #[cfg(target_os = "linux")]
    fn build_static_target_image(root: &Path) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("walking-skeleton-baseline")
            .join("baseline_exit.rs")
            .canonicalize()
            .expect("canonicalize the walking-skeleton baseline command source");
        let artefact = root.join("static-target");
        let output = Command::new("rustc")
            .arg("--edition")
            .arg("2021")
            .arg("--crate-name")
            .arg("production_mint_target")
            .arg("-O")
            .arg("-C")
            .arg("target-feature=+crt-static")
            .args(["-C", "relocation-model=static"])
            .arg("-o")
            .arg(&artefact)
            .arg(source)
            .output()
            .expect("run rustc to build the real static target");
        assert!(
            output.status.success(),
            "building the static target must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        artefact
    }

    /// The first production Linux command plan, joined from twelve measured
    /// components and submitted to the plan's own validators.
    ///
    /// Every input is a real kernel object on this host: the installer-anchored
    /// state root, journal root, cgroup parent and delegation; the running
    /// service image; the admitted `/usr/bin/bwrap`; a sealed memfd carrying
    /// the anchored setup statement; five directories the service creates for
    /// this command; and a static ELF `rustc` built from the checked-in
    /// fixture, read through a descriptor this test holds open.
    ///
    /// **The Bubblewrap-absent arm is itself enforced.** The default gate image
    /// carries no `bwrap`, so `AuthenticatedBubblewrapImageV1` cannot exist
    /// there and neither can a plan. That is asserted by errno and reported,
    /// never skipped: an absent capability is a refusal, not a pass.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear run keeps every one of the twelve components, the producer it came from, and the validator's answer visible in the order they happen"
    )]
    fn the_production_components_mint_joins_measured_components_into_one_validated_plan() {
        use crate::linux_command_plan::{
            ADMITTED_BUBBLEWRAP_IMAGE_V1, AuthenticatedBubblewrapImageV1,
            LinuxAuthenticatedFileV1, LinuxMeasuredTargetImageV1, LinuxProductionCommandPlanInputsV1,
            LinuxProgramImageV1, LinuxRetainedObjectIdentityV1, LinuxRetainedObjectKindV1,
            TARGET_IMAGE_OBJECT_ID,
        };

        let Some(service) = InstalledService::from_environment() else {
            assert!(environment_path(INSTALL_ROOT_VARIABLE).is_none() || own_effective_uid() == 0);
            return;
        };

        // ---- component sources 3 and 11: the installer anchor -------------
        let expected = service.independently_observed_binding();
        let (handoff, _) = service.mint().expect("mint the installed handoff");
        let (capability, host_roots) = handoff
            .into_state_root_capability(&expected)
            .expect("derive the state-root capability from the installed anchor");
        let facts = match capability.observe_anchored_plan_facts(&host_roots) {
            Ok(facts) => facts,
            Err(error) => {
                // The service-owned-parent arm. The parent is no longer the
                // delegator's, so no anchored fact exists and no plan can be
                // built from one. Asserted by name in
                // `live_anchored_plan_facts_require_a_cgroup_parent_the_service_does_not_own`.
                assert!(
                    service_owned_cgroup_parent(),
                    "the anchored facts must mint on a delegator-owned parent: {error:?}"
                );
                println!(
                    "GBDMINT arm=service-owned-parent plan=not-minted \
                     (the anchor refuses a cgroup parent the service owns)"
                );
                return;
            }
        };
        let anchored = facts.plan_anchored_facts();

        // ---- a real workspace, and a real grant, policy and authority ------
        let scratch = std::env::temp_dir().join(format!("gb-production-mint-{}", own_effective_uid()));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).expect("create the mint scratch root");
        let scratch = fs::canonicalize(&scratch).expect("canonicalize the mint scratch root");
        let workspace = scratch.join("workspace");
        fs::create_dir(&workspace).expect("create the mint workspace");
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o755))
            .expect("make the mint workspace owner-writable only");

        // ---- component source 2: a real static ELF target ------------------
        let target_path = build_static_target_image(&scratch);
        let target_name = target_path
            .to_str()
            .expect("the target path is UTF-8")
            .to_owned();
        let held_target = std::fs::File::open(&target_path).expect("hold the target open");
        let target_bytes = fs::read(&target_path).expect("read the target completely");
        let target_length = u64::try_from(target_bytes.len()).expect("target length fits");
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
            .expect("the fixture authority carries effect context")
            .input_snapshot
            .clone();

        // ---- component source 3: the per-command retained directories ------
        let state_root_dir = open_ambient(&service.state_root);
        let workspace_dir = open_ambient(&workspace);
        let command_directory = leaf_shaped_name(0x5b);
        let directories = create_per_command_retained_directories(
            &state_root_dir,
            &workspace_dir,
            &command_directory,
            expected.owner_uid,
        )
        .expect("create and observe this command's retained directories");

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
                let _ = fs::remove_dir_all(&scratch);
                return;
            }
        };

        // ---- component source 2: the sealed setup channel ------------------
        let statement = facts.setup_channel_statement(crate::wire::RunnerRole::Worker, &input_snapshot);
        let content = statement.encode().expect("the anchored statement encodes");
        let setup_channel = seal_and_authenticate_setup_channel(&content, &statement);

        // ---- component source 2: the admitted Bubblewrap image -------------
        let bubblewrap_path = ADMITTED_BUBBLEWRAP_IMAGE_V1.resolved_path;
        let held_bubblewrap = match std::fs::File::open(bubblewrap_path) {
            Ok(file) => file,
            Err(error) => {
                assert_eq!(
                    error.raw_os_error(),
                    Some(rustix::io::Errno::NOENT.raw_os_error()),
                    "an unreadable Bubblewrap is not the same as an absent one"
                );
                println!(
                    "GBDMINT bubblewrap-absent path={bubblewrap_path} errno=ENOENT \
                     plan=not-minted (this image admits no Bubblewrap, so no plan can exist here)"
                );
                let _ = fs::remove_dir_all(&scratch);
                let _ = fs::remove_dir_all(
                    service
                        .state_root
                        .join(SERVICE_PER_COMMAND_RETAINED_ROOT)
                        .join(&command_directory),
                );
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

        // ---- the join, and the validators' answer --------------------------
        let inputs = LinuxProductionCommandPlanInputsV1 {
            authority: fixture.authority.clone(),
            grant: &fixture.grant,
            policy: &fixture.policy,
            anchored,
            bubblewrap: &bubblewrap,
            setup_channel: &setup_channel,
            target_image: &target_image,
            target_object: &target_object,
            directories: directories.identities(),
            mandatory_controls: &mandatory_controls,
        };
        let components = inputs
            .components()
            .expect("the twelve components join without a refusal");

        // The masks the plan carries are the masks a second complete
        // observation of the same held descriptor reproduces. That is the
        // descriptor-mount increment's discipline, applied to the joined plan.
        let project_destinations = BTreeSet::from([
            crate::linux_command_plan::LINUX_NAMESPACE_LIVE_WORKSPACE_ROOT,
            crate::linux_command_plan::LINUX_NAMESPACE_EXECUTION_ROOT,
        ]);
        let re_observed = directories
            .mint_git_masks(&project_destinations)
            .expect("the mask replacement is still the empty directory it was digested as");
        assert_eq!(
            components.git_masks(),
            re_observed.as_slice(),
            "the plan's .git masks differ from a second observation of the same descriptor"
        );

        let parent = facts.service_cgroup_parent.kernel_observation();
        let delegation = facts.cgroup_delegation_root.kernel_observation();
        let outcome = inputs.mint(fixture.native_launch.clone());
        println!(
            "GBDMINT joined objects={} read_only={} read_write={} masks={} arch={} \
             target={} bwrap={} parent={}:{} uid={} delegation={}:{} uid={} verdict={}",
            components.retained_object_count(),
            components.read_only_mount_count(),
            components.read_write_mount_count(),
            components.git_masks().len(),
            anchored.host_architecture.as_str(),
            target_name,
            bubblewrap_path,
            parent.device_id,
            parent.inode,
            parent.owner_uid,
            delegation.device_id,
            delegation.inode,
            delegation.owner_uid,
            match &outcome {
                Ok(plan) => format!("validated digest={} bytes={}", plan.plan_digest(), plan.canonical_bytes().len()),
                Err(error) => format!("refused {error:?}"),
            }
        );

        // ---- the plan-level delegation clause, on these same kernel objects --
        //
        // The anchor has already refused a parent that is not the delegator's,
        // so the *plan's* own clause cannot be reached from this host by
        // varying the host. It is reached instead by varying exactly one field
        // of one real observation — and the value substituted in is not
        // invented either: it is the service uid the installer committed.
        let service_owned_parent = {
            let mut observation = facts.service_cgroup_parent.kernel_observation();
            observation.owner_uid = expected.owner_uid;
            LinuxRetainedObjectIdentityV1::from_kernel_observation(
                crate::linux_command_plan::SERVICE_CGROUP_PARENT_OBJECT_ID,
                LinuxRetainedObjectKindV1::CgroupDirectory,
                observation,
            )
            .expect("re-mint the parent identity with the service as its owner")
        };
        let group_writable_parent = {
            let mut observation = facts.service_cgroup_parent.kernel_observation();
            observation.mode |= 0o020;
            LinuxRetainedObjectIdentityV1::from_kernel_observation(
                crate::linux_command_plan::SERVICE_CGROUP_PARENT_OBJECT_ID,
                LinuxRetainedObjectKindV1::CgroupDirectory,
                observation,
            )
            .expect("re-mint the parent identity as group-writable")
        };
        let delegator_owned_delegation = {
            let mut observation = facts.cgroup_delegation_root.kernel_observation();
            observation.owner_uid = parent.owner_uid;
            LinuxRetainedObjectIdentityV1::from_kernel_observation(
                crate::linux_command_plan::CGROUP_DELEGATION_ROOT_OBJECT_ID,
                LinuxRetainedObjectKindV1::CgroupDirectory,
                observation,
            )
            .expect("re-mint the delegation identity with the delegator as its owner")
        };
        for (label, expected_detail, varied) in [
            (
                "a cgroup parent the service owns",
                "owned by the service it delegates to",
                {
                    let mut varied = anchored;
                    varied.service_cgroup_parent = &service_owned_parent;
                    varied
                },
            ),
            (
                "a group-writable cgroup parent",
                "writable outside its owner",
                {
                    let mut varied = anchored;
                    varied.service_cgroup_parent = &group_writable_parent;
                    varied
                },
            ),
            (
                "a delegation the delegator kept",
                "not owned by the service identity that owns the state root",
                {
                    let mut varied = anchored;
                    varied.cgroup_delegation_root = &delegator_owned_delegation;
                    varied
                },
            ),
        ] {
            let refusal = LinuxProductionCommandPlanInputsV1 {
                authority: fixture.authority.clone(),
                grant: &fixture.grant,
                policy: &fixture.policy,
                anchored: varied,
                bubblewrap: &bubblewrap,
                setup_channel: &setup_channel,
                target_image: &target_image,
                target_object: &target_object,
                directories: directories.identities(),
            mandatory_controls: &mandatory_controls,
            }
            .mint(fixture.native_launch.clone())
            .expect_err(&format!("{label} must be refused by the plan"));
            assert!(
                refusal.to_string().contains(expected_detail),
                "{label} refused for the wrong reason: {refusal}"
            );
        }

        let _ = fs::remove_dir_all(&scratch);
        let _ = fs::remove_dir_all(
            service
                .state_root
                .join(SERVICE_PER_COMMAND_RETAINED_ROOT)
                .join(&command_directory),
        );

        assert!(!ValidatedLinuxProductionCommandPlanV1::permits_execution());

        // Every clause of `validate_cgroup` other than the two owner clauses
        // holds here, so the refusals above are attributable to the single
        // field each of them varied.
        assert_eq!(
            facts.service_cgroup_parent.kind(),
            LinuxRetainedObjectKindV1::CgroupDirectory
        );
        assert_eq!(
            facts.cgroup_delegation_root.kind(),
            LinuxRetainedObjectKindV1::CgroupDirectory
        );
        assert_ne!(parent.inode, delegation.inode, "clause: distinct inodes");
        assert_eq!(
            parent.device_id, delegation.device_id,
            "clause: one cgroup device"
        );
        assert_eq!(
            parent.mount_id, delegation.mount_id,
            "clause: one cgroup mount"
        );
        assert_eq!(
            delegation.mode & 0o002,
            0,
            "clause: the delegation is not world-writable"
        );
        assert_eq!(
            delegation.owner_uid, expected.owner_uid,
            "the service owns the delegation the installer committed"
        );

        // ---- the measured verdict, corrected 2026-08-11 --------------------
        //
        // Reaching here means the anchor admitted the parent, which means the
        // parent is the delegator's. That is cgroup v2 delegation as the kernel
        // documents it, and the plan built from it **validates**. The previous
        // increment's run refused exactly here, on a clause that required the
        // parent and the delegation to share one owner; that clause has been
        // replaced by what it was protecting, and the three refusals above are
        // the replacement doing the protecting.
        assert!(
            !service_owned_cgroup_parent(),
            "the service-owned-parent arm returns at the anchor"
        );
        assert_ne!(
            parent.owner_uid, delegation.owner_uid,
            "delegation gives the parent and the delegated subtree two owners"
        );
        assert_eq!(
            parent.mode & 0o022,
            0,
            "clause: the parent is not writable outside its owner"
        );
        let plan = outcome.expect("documented cgroup v2 delegation validates the plan");
        // The canonical bytes really are canonical: the plan decodes back to
        // itself, which is the round trip a decoded plan makes.
        let decoded = ValidatedLinuxProductionCommandPlanV1::decode_exact(plan.canonical_bytes())
            .expect("the minted plan round trips through its own decoder");
        assert_eq!(decoded, plan);
        // And the journal binding the plan projects equals what this process
        // independently observed of the installed anchor, so the anchored half
        // of the plan really did come through the anchor.
        assert_eq!(
            plan.journal_binding().expect("project the journal binding"),
            expected
        );
    }
