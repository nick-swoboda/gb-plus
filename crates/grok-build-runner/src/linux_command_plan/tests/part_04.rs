    // The portable half of the descriptor-based `.git` mask mount.
    //
    // The live half in `linux_cgroup_io::tests` performs a real `open_tree` and
    // a real `move_mount` and reads the destination out of the kernel. This
    // half varies one kernel answer at a time and requires a named refusal, so
    // every way the binding can be broken is provable on a host with no Linux
    // kernel in front of it, including the ways a privileged container is
    // needed to produce for real.

    /// The control project view the mask below covers.
    const MOUNT_BINDING_WORKSPACE: &str = "/work";

    /// The unique mount identity `open_tree` answered for the clone.
    ///
    /// It differs from the directory's own by construction: a clone is a new
    /// mount, and the binding refuses when the two are equal.
    const CLONE_MOUNT_ID: u64 = 9_001;

    fn mount_binding_mask() -> (LinuxGitMaskV1, LinuxRetainedObjectIdentityV1) {
        let observation = mask_observation();
        let identity = mask_identity(&observation);
        let mask = LinuxGitMaskV1::from_empty_directory_observation(
            MOUNT_BINDING_WORKSPACE,
            &identity,
            &observation,
        )
        .expect("the control mask mints from an empty directory observation");
        (mask, identity)
    }

    /// The control clone observation: the same directory, reached through a
    /// new mount.
    fn clone_observation() -> LinuxGitMaskEmptyDirectoryObservationV1 {
        let mut observation = mask_observation();
        observation.object.mount_id = CLONE_MOUNT_ID;
        observation
    }

    fn control_binding() -> LinuxGitMaskMountBindingV1 {
        let (mask, identity) = mount_binding_mask();
        LinuxGitMaskMountBindingV1::from_cloned_mount_observation(
            &mask,
            &identity,
            &mask_observation(),
            &clone_observation(),
        )
        .expect("the control clone is the observed directory reached through a new mount")
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear table keeps every varied kernel answer and the control it is varied from visible in the order they are checked"
    )]
    fn the_git_mask_mount_binding_requires_the_clone_to_be_the_observed_directory() {
        let (mask, identity) = mount_binding_mask();
        let directory = mask_observation();

        // Control: the clone answers the same device, inode, mode, owner, link
        // count, filesystem and (empty) enumeration, and a different unique
        // mount identity.
        let control = LinuxGitMaskMountBindingV1::from_cloned_mount_observation(
            &mask,
            &identity,
            &directory,
            &clone_observation(),
        )
        .expect("the control clone binds");
        assert_eq!(
            control.masked_destination(),
            format!("{MOUNT_BINDING_WORKSPACE}/.git")
        );
        assert_eq!(
            control.directory_observation_digest(),
            mask.expected_empty_observation_digest()
        );
        assert_eq!(control.source_mount_id(), directory.object.mount_id);
        assert_eq!(control.detached_mount_id(), CLONE_MOUNT_ID);
        // The two digests are over the same directory and are still different,
        // because the role name and the mount identity are both inside the
        // bytes. A directory observation can never be replayed as a mount one.
        assert_ne!(
            control.mount_observation_digest(),
            control.directory_observation_digest()
        );

        let mut refusals = Vec::new();
        for (label, clone) in [
            ("another inode", {
                let mut clone = clone_observation();
                clone.object.inode += 1;
                clone
            }),
            ("another device", {
                let mut clone = clone_observation();
                clone.object.device_id += 1;
                clone
            }),
            ("another mode", {
                let mut clone = clone_observation();
                clone.object.mode = DIRECTORY_MODE | 0o700;
                clone
            }),
            ("another owner", {
                let mut clone = clone_observation();
                clone.object.owner_uid += 1;
                clone
            }),
            ("another group", {
                let mut clone = clone_observation();
                clone.object.owner_gid += 1;
                clone
            }),
            ("another filesystem", {
                let mut clone = clone_observation();
                clone.filesystem_magic = 0x0102_0304;
                clone
            }),
            ("the directory's own mount identity", mask_observation()),
            ("no unique mount identity", {
                let mut clone = clone_observation();
                clone.object.mount_id = 0;
                clone
            }),
            ("a populated clone", {
                let mut clone = clone_observation();
                clone.entry_names = vec!["HEAD".to_owned()];
                clone
            }),
            ("a clone with three links", {
                let mut clone = clone_observation();
                clone.object.link_count = 3;
                clone
            }),
            ("a clone carrying a byte length", {
                let mut clone = clone_observation();
                clone.object.byte_length = Some(4_096);
                clone
            }),
            ("a group-writable clone", {
                let mut clone = clone_observation();
                clone.object.mode = DIRECTORY_MODE | 0o520;
                clone
            }),
        ] {
            let refusal = LinuxGitMaskMountBindingV1::from_cloned_mount_observation(
                &mask,
                &identity,
                &directory,
                &clone,
            )
            .expect_err(&format!("{label} must be refused"));
            refusals.push(refusal.to_string());
        }

        // A directory observation that no longer reproduces the mask's own
        // committed digest is refused before the clone is looked at at all.
        let mut moved_directory = directory.clone();
        moved_directory.object.inode += 7;
        refusals.push(
            LinuxGitMaskMountBindingV1::from_cloned_mount_observation(
                &mask,
                &mask_identity(&moved_directory),
                &moved_directory,
                &clone_observation(),
            )
            .expect_err("a directory that no longer reproduces the committed digest is refused")
            .to_string(),
        );

        let distinct = refusals.iter().collect::<BTreeSet<_>>();
        assert_eq!(
            distinct.len(),
            refusals.len(),
            "each refusal must name its own reason: {refusals:#?}"
        );

        // Control again, after every enforced arm.
        LinuxGitMaskMountBindingV1::from_cloned_mount_observation(
            &mask,
            &identity,
            &directory,
            &clone_observation(),
        )
        .expect("the control clone still binds");
    }

    #[test]
    fn the_attached_mount_must_reproduce_the_detached_mount_observation() {
        let binding = control_binding();

        // Control: the destination reads back exactly what the clone read.
        binding
            .require_attached_mount(&clone_observation())
            .expect("the destination carrying this very mount is admissible");

        let mut refusals = Vec::new();
        for (label, attached) in [
            // The sharpest arm: the same directory, still empty, reached
            // through some *other* mount. Only the unique mount identity
            // separates it, and the kernel never reuses one.
            ("the same directory through another mount", {
                let mut attached = clone_observation();
                attached.object.mount_id = CLONE_MOUNT_ID + 1;
                attached
            }),
            ("the directory itself, unmounted", mask_observation()),
            ("another directory through this mount", {
                let mut attached = clone_observation();
                attached.object.inode += 1;
                attached
            }),
            ("another device", {
                let mut attached = clone_observation();
                attached.object.device_id += 1;
                attached
            }),
            ("another filesystem", {
                let mut attached = clone_observation();
                attached.filesystem_magic = 0x0102_0304;
                attached
            }),
            ("a destination that gained an entry", {
                let mut attached = clone_observation();
                attached.entry_names = vec!["HEAD".to_owned()];
                attached
            }),
            ("a destination with three links", {
                let mut attached = clone_observation();
                attached.object.link_count = 3;
                attached
            }),
            ("a destination that became group-writable", {
                let mut attached = clone_observation();
                attached.object.mode = DIRECTORY_MODE | 0o520;
                attached
            }),
            ("a destination that is not a directory read", {
                let mut attached = clone_observation();
                attached.object.byte_length = Some(1);
                attached
            }),
        ] {
            let refusal = binding
                .require_attached_mount(&attached)
                .expect_err(&format!("{label} must be refused at the destination"));
            refusals.push(refusal.to_string());
        }

        // A mount identity that matches but a mode that does not still fails
        // the digest, so the explicit identity comparison is not the only
        // thing doing work.
        let mut restyled = clone_observation();
        restyled.object.mode = DIRECTORY_MODE | 0o700;
        let restyled_refusal = binding
            .require_attached_mount(&restyled)
            .expect_err("a destination with this mount identity and another mode is refused");
        assert!(
            restyled_refusal.to_string().contains("observed as"),
            "{restyled_refusal}"
        );
        refusals.push(restyled_refusal.to_string());

        let distinct = refusals.iter().collect::<BTreeSet<_>>();
        assert_eq!(
            distinct.len(),
            refusals.len(),
            "each destination refusal must name its own reason: {refusals:#?}"
        );

        binding
            .require_attached_mount(&clone_observation())
            .expect("the control destination is still admissible");
    }

    #[test]
    fn the_mount_role_observation_encodes_under_its_own_role_name() {
        let clone = clone_observation();
        let mount_identity = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            GIT_MASK_MOUNT_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            clone.object,
        )
        .expect("the clone observation is an admissible retained identity");
        let encoded = clone
            .encode(&mount_identity)
            .expect("the mount-role observation encodes");
        let text = String::from_utf8(encoded.clone()).expect("the observation is ASCII");
        let lines = text.lines().collect::<Vec<_>>();

        // Line 0 is the same protocol descriptor the directory role uses:
        // there is one observation contract in the workspace, and the role is
        // carried by the object line rather than by a second format.
        assert_eq!(lines[0], LINUX_GIT_MASK_EMPTY_OBSERVATION_DESCRIPTOR_V1);
        assert!(
            lines[2].starts_with(&format!("{GIT_MASK_MOUNT_OBJECT_ID}:")),
            "{}",
            lines[2]
        );
        assert!(
            lines[2].contains(&format!(":{CLONE_MOUNT_ID}:")),
            "the unique mount identity is inside the digested bytes: {}",
            lines[2]
        );
        assert_eq!(lines.last(), Some(&"end"));

        // The identity has to describe the observation it is encoded with, so
        // a mount-role digest cannot be minted over another object's read.
        let mut elsewhere = clone.clone();
        elsewhere.object.inode += 1;
        assert!(
            elsewhere
                .encode(&mount_identity)
                .expect_err("an identity describing another object is refused")
                .to_string()
                .contains("different kernel object")
        );

        // The directory role and the mount role digest the same directory
        // differently, which is what domain-separates them.
        let directory_identity = mask_identity(&clone);
        assert_ne!(
            clone
                .digest(&directory_identity)
                .expect("the directory-role digest exists"),
            clone
                .digest(&mount_identity)
                .expect("the mount-role digest exists")
        );
    }

    // ---------------------------------------------------------------------
    // The production components mint, portable half.
    //
    // The mint itself cannot be exercised on a host with no `bwrap`, because
    // `AuthenticatedBubblewrapImageV1` can only exist where the admitted image
    // does. What is portable is everything the mint chooses rather than
    // measures, the namespace layout and the contract constructors, and
    // those are exactly the parts a reviewer most needs held to the same
    // validators the plan applies.

    /// The four namespace destinations the mint names must each satisfy the
    /// bounds `validate_mounts` applies, and must be distinct from one another.
    #[test]
    fn the_production_namespace_layout_is_distinct_bounded_and_git_free() {
        let layout = [
            LINUX_NAMESPACE_LIVE_WORKSPACE_ROOT,
            LINUX_NAMESPACE_EXECUTION_ROOT,
            LINUX_NAMESPACE_PRIVATE_TEMP,
            LINUX_NAMESPACE_OUTPUT_SPOOL,
        ];
        for destination in layout {
            validate_absolute_path(destination, "namespace layout")
                .unwrap_or_else(|error| panic!("{destination} is not a mount destination: {error}"));
            assert_ne!(destination, "/", "{destination} is the host root");
            assert!(
                !contains_git_component(destination),
                "{destination} enters .git"
            );
        }
        assert_eq!(
            layout.iter().collect::<BTreeSet<_>>().len(),
            layout.len(),
            "two namespace destinations collide, so two mounts would too"
        );

        // A read-only worker executes in the live workspace itself, the
        // equality `validate_mounts` requires when it crosses the execution
        // mount against the retained grant root, and the other two views do
        // not.
        assert_eq!(
            execution_namespace_root(LinuxExecutionViewV1::WorkerReadOnly),
            LINUX_NAMESPACE_LIVE_WORKSPACE_ROOT
        );
        for view in [
            LinuxExecutionViewV1::WorkerShadow,
            LinuxExecutionViewV1::FinalVerifierSnapshot,
        ] {
            assert_eq!(
                execution_namespace_root(view),
                LINUX_NAMESPACE_EXECUTION_ROOT
            );
            assert_ne!(
                execution_namespace_root(view),
                LINUX_NAMESPACE_LIVE_WORKSPACE_ROOT
            );
        }
    }

    /// Every contract constructor the mint uses is required to satisfy the
    /// validator that reads it, rather than merely to compile.
    #[test]
    fn the_production_contract_constructors_satisfy_the_validators_that_read_them() {
        // The two mandatory kernel controls.
        for architecture in [
            LinuxMachineArchitectureV1::X86_64,
            LinuxMachineArchitectureV1::Aarch64,
        ] {
            let seccomp = LinuxSeccompPlanV1::contract(
                architecture.audit_architecture(),
                fixture_seccomp_filter(architecture.audit_architecture()),
                fixture_namespace_filter(architecture.audit_architecture()),
            );
            let landlock = LinuxLandlockPlanV1::contract(fixture_landlock_ruleset());
            validate_mandatory_kernel_controls(&landlock, &seccomp)
                .expect("the compiled kernel-control contract satisfies its validator");
            assert_eq!(seccomp.audit_architecture().architecture(), architecture);
        }
        assert_eq!(
            LinuxLandlockPlanV1::contract(fixture_landlock_ruleset()).minimum_kernel_abi(),
            LINUX_LANDLOCK_MINIMUM_KERNEL_ABI
        );
        assert_ne!(
            LINUX_LANDLOCK_MINIMUM_KERNEL_ABI, 0,
            "a zero minimum would admit a kernel with no Landlock at all"
        );
        // A compile-time check, because a modeled window past the schema's hard
        // bound should never build rather than never run.
        const { assert!(LINUX_LANDLOCK_MAXIMUM_MODELED_KERNEL_ABI <= MAX_LANDLOCK_ABI) };

        // The limits are the compiled policy's own, and swap is refused.
        let limits = ResourceLimits {
            wall_time_ms: 60_000,
            max_output_bytes: 1_048_576,
            max_processes: 16,
            max_memory_bytes: Some(536_870_912),
        };
        let planned = LinuxResourceLimitsV1::from_compiled_policy(limits);
        validate_resource_limits(&planned, limits)
            .expect("the compiled limits satisfy their validator");
        assert_eq!(planned.swap_bytes, 0);

        // The terminal evidence is the complete required set, in order.
        let evidence = LinuxExpectedTerminalEvidenceV1::contract();
        assert_eq!(evidence.runtime_requirements, REQUIRED_RUNTIME_EVIDENCE);
        assert_eq!(evidence.cleanup_requirements_in_order, REQUIRED_CLEANUP);

        // The release contract carries the digest it was handed and nothing
        // else that could be chosen.
        let release = LinuxProductionReleaseExpectationV1::contract(digest(40));
        assert_eq!(release.schema, LINUX_PRODUCTION_HELD_RELEASE_SCHEMA);
        assert_eq!(release.authenticated_platform_service_digest, digest(40));

        // Both fixed-surface contracts have exactly one expressible value, and
        // the mint writes that value down rather than accepting one.
        assert_eq!(
            LinuxPrivilegeNamespacePlanV1::contract().user,
            LinuxNamespaceRequirementV1::NewAndVerified
        );
        assert_eq!(
            LinuxProcessSurfaceV1::contract().command,
            LinuxCommandBindingPolicyV1::ExactAuthorityArgvAndRetainedCwd
        );

        // The network mode follows the compiled policy, and the renewed-action
        // arm carries the two hashes `validate_network` crosses.
        assert_eq!(
            network_policy(ExecutionNetwork::None, &digest(2), &digest(3)),
            LinuxNetworkNamespacePolicyV1::NewIsolatedNamespace
        );
        assert_eq!(
            network_policy(ExecutionNetwork::FullForAction, &digest(2), &digest(3)),
            LinuxNetworkNamespacePolicyV1::RetainHostNamespaceForRenewedAction {
                grant_hash: digest(2),
                policy_hash: digest(3),
            }
        );

        // A role that runs no contained command names no execution view.
        for (role, mode) in [
            (RunnerRole::Worker, MutationMode::ReadOnly),
            (RunnerRole::Worker, MutationMode::ShadowWorkspace),
            (RunnerRole::FinalVerifier, MutationMode::ReadOnly),
        ] {
            execution_view(role, mode).expect("a command role names a view");
        }
        for (role, mode) in [
            (RunnerRole::FinalVerifier, MutationMode::ShadowWorkspace),
            (RunnerRole::Applier, MutationMode::ReadOnly),
            (RunnerRole::LiveStateVerifier, MutationMode::ReadOnly),
        ] {
            assert!(
                execution_view(role, mode)
                    .expect_err("a non-command role names no view")
                    .to_string()
                    .contains("name no execution view")
            );
        }
    }

    // -----------------------------------------------------------------------
    // The cgroup v2 delegation boundary.
    //
    // `validate_cgroup` used to require the service cgroup parent and the
    // delegation to share one owner. Under delegation as the kernel documents
    // it, and as this project's own installer performs it, they do not: the
    // delegator keeps the parent and chowns only the delegated subtree. The
    // clause has been replaced by what it was reaching for, and this is the
    // portable half of that claim: one field varied per arm, against the same
    // control, with the control re-checked after every variation so each
    // refusal is attributable to the one value that moved.
    // -----------------------------------------------------------------------

    /// The service identity every fixture object but the cgroup parent carries.
    const FIXTURE_SERVICE_UID: u32 = 1_000;

    /// One retained object of the valid fixture plan, varied in place.
    fn vary_object(
        valid: &ValidatedLinuxProductionCommandPlanV1,
        object_id: &str,
        change: impl FnOnce(&mut LinuxRetainedObjectIdentityV1),
    ) -> LinuxProductionCommandPlanV1 {
        let mut varied = valid.plan.clone();
        let object = varied
            .components
            .retained
            .objects
            .iter_mut()
            .find(|candidate| candidate.object_id == object_id)
            .expect("the fixture carries this retained object");
        change(object);
        varied
    }

    fn delegation_refusal(plan: LinuxProductionCommandPlanV1) -> String {
        ValidatedLinuxProductionCommandPlanV1::from_plan(plan)
            .expect_err("this delegation shape must be refused")
            .to_string()
    }

    #[test]
    fn the_delegation_boundary_requires_two_owners_and_a_parent_the_service_cannot_write() {
        let valid = fixture(RunnerRole::Worker);
        let parent = &valid.plan.components.retained.cgroup.service_parent_object_id.clone();
        let delegation = &valid.plan.components.retained.cgroup.delegation_root_object_id.clone();

        // Control: delegation as the kernel documents it. The parent is the
        // delegator's, the delegated subtree is the service's, and the plan
        // validates. Under the old clause this exact shape was refused.
        assert_ne!(
            valid.journal_binding().expect("project the binding").owner_uid,
            DELEGATOR_UID,
            "the delegation is the service's, not the delegator's"
        );
        ValidatedLinuxProductionCommandPlanV1::from_plan(valid.plan.clone())
            .expect("documented cgroup v2 delegation validates");

        // Enforced, and this is the arm the old clause did not have: a parent
        // the service owns. The old validator *required* this shape; it lets
        // the service create sibling delegations beside its own and rmdir this
        // one, so it is now the sharpest refusal here.
        let refusal = delegation_refusal(vary_object(&valid, parent, |object| {
            object.owner_uid = FIXTURE_SERVICE_UID;
        }));
        assert!(
            refusal.contains("owned by the service it delegates to"),
            "a service-owned cgroup parent must be refused by name: {refusal}"
        );

        // Enforced: a parent the service might reach through its groups. Group
        // membership is not something a plan can read, so group write is
        // refused outright rather than reasoned about.
        for extra_mode in [0o020, 0o002, 0o022] {
            let refusal = delegation_refusal(vary_object(&valid, parent, |object| {
                object.mode |= extra_mode;
            }));
            assert!(
                refusal.contains("writable outside its owner"),
                "a parent writable at {extra_mode:o} must be refused: {refusal}"
            );
        }

        // Enforced: the delegated subtree owned by someone who is not the
        // service. Both directions are refused, a third identity, and the
        // delegator keeping it, because either means no delegation happened.
        for owner in [2_000, DELEGATOR_UID] {
            let refusal = delegation_refusal(vary_object(&valid, delegation, |object| {
                object.owner_uid = owner;
            }));
            assert!(
                refusal.contains("not owned by the service identity that owns the state root"),
                "a delegation owned by uid {owner} must be refused: {refusal}"
            );
        }

        // Enforced: the service identity really is read off the state root
        // rather than assumed. Move the service's own two roots to another uid
        // and the unchanged delegation stops being the service's.
        let mut moved_service = valid.plan.clone();
        for object in &mut moved_service.components.retained.objects {
            if object.object_id == "private-state" || object.object_id == "journal-index" {
                object.owner_uid = 2_000;
            }
        }
        let refusal = delegation_refusal(moved_service);
        assert!(
            refusal.contains("not owned by the service identity that owns the state root"),
            "the service identity comes from the state root: {refusal}"
        );

        // Every clause the old owner-equality also caught is still caught, and
        // by the same validator: a delegation that is the parent, a delegation
        // on another device or mount, a non-cgroup kind, and a world-writable
        // delegation.
        for (label, varied) in [
            (
                "delegation on another device",
                vary_object(&valid, delegation, |object| object.device_id += 1),
            ),
            (
                "delegation on another mount",
                vary_object(&valid, delegation, |object| object.mount_id += 1),
            ),
            (
                "a delegation that is not a cgroup directory",
                vary_object(&valid, delegation, |object| {
                    object.kind = LinuxRetainedObjectKindV1::Directory;
                }),
            ),
            (
                "a parent that is not a cgroup directory",
                vary_object(&valid, parent, |object| {
                    object.kind = LinuxRetainedObjectKindV1::Directory;
                }),
            ),
            (
                "a world-writable delegation",
                vary_object(&valid, delegation, |object| object.mode |= 0o002),
            ),
        ] {
            assert!(
                ValidatedLinuxProductionCommandPlanV1::from_plan(varied).is_err(),
                "{label} must still be refused"
            );
        }

        // And the unvaried control still validates, so every refusal above is
        // attributable to the single field that moved.
        ValidatedLinuxProductionCommandPlanV1::from_plan(valid.plan.clone())
            .expect("the unvaried control still validates");
    }

    /// `validate_release_and_evidence` carries the delegation boundary a second
    /// time, and both sites were corrected together.
    ///
    /// A complete plan cannot reach it with a crossed parent, because
    /// `validate_cgroup` runs first and refuses, equally true of the clause it
    /// replaces. So the second site is exercised directly, which is the only
    /// way to show it states the corrected boundary rather than the old
    /// equality.
    #[test]
    fn the_release_site_carries_the_same_delegation_boundary_as_the_cgroup_site() {
        let valid = fixture(RunnerRole::Worker);
        let release_verdict = |retained: &LinuxRetainedCapabilitySetV1| {
            let objects = retained
                .objects
                .iter()
                .map(|object| (object.object_id.as_str(), object))
                .collect::<BTreeMap<_, _>>();
            validate_release_and_evidence(
                &valid.plan.components.release,
                &valid.plan.components.terminal_evidence,
                retained,
                &objects,
            )
        };

        // Control: the delegator's parent, the service's journal, state root
        // and delegation.
        release_verdict(&valid.plan.components.retained)
            .expect("the release site admits documented delegation");

        // Enforced: the parent brought inside the service's owner set, which
        // is exactly what this site used to require.
        let mut service_owned_parent = valid.plan.components.retained.clone();
        for object in &mut service_owned_parent.objects {
            if object.object_id == service_owned_parent_id(&valid) {
                object.owner_uid = FIXTURE_SERVICE_UID;
            }
        }
        assert!(
            release_verdict(&service_owned_parent)
                .expect_err("a service-owned parent must be refused here too")
                .to_string()
                .contains("cgroup parent is not the delegator's")
        );

        // Enforced: a parent the service could write through its groups.
        let mut writable_parent = valid.plan.components.retained.clone();
        for object in &mut writable_parent.objects {
            if object.object_id == service_owned_parent_id(&valid) {
                object.mode |= 0o020;
            }
        }
        assert!(release_verdict(&writable_parent).is_err());

        // Enforced: the delegation outside the service's owner set, which this
        // site has always required and still does.
        let mut crossed_delegation = valid.plan.components.retained.clone();
        let delegation_id = valid
            .plan
            .components
            .retained
            .cgroup
            .delegation_root_object_id
            .clone();
        for object in &mut crossed_delegation.objects {
            if object.object_id == delegation_id {
                object.owner_uid = 2_000;
            }
        }
        assert!(release_verdict(&crossed_delegation).is_err());

        // And the control still passes afterwards.
        release_verdict(&valid.plan.components.retained)
            .expect("the unvaried control still passes the release site");
    }

    fn service_owned_parent_id(plan: &ValidatedLinuxProductionCommandPlanV1) -> String {
        plan.plan
            .components
            .retained
            .cgroup
            .service_parent_object_id
            .clone()
    }

    /// The checked-in artefact of the version-4 plan builder.
    ///
    /// Captured from `fixture(RunnerRole::Worker)` on the version-4 tree and
    /// committed at `78d05a7` before the version-5 bump. One-way for the same
    /// reason the version-3 record is: a plan carries live identities and a
    /// temporary-directory name embedding a process id. It is aarch64 where the
    /// version-3 record is `x86_64`, a property of where each was captured, and
    /// irrelevant to a refusal that happens before any architecture field is
    /// read.
    const SCHEMA_V4_RECORD: &str = "fixtures/linux-plan-schema/schema-v4-command-plan-record.json";

    /// A persisted version-4 record is refused by name, and never migrated.
    ///
    /// Version 5's addition is a second committed filter beside the first, so
    /// the refusal has to hold on two independent grounds and does: the schema
    /// version differs, and, because `LinuxSeccompPlanV1` is
    /// `deny_unknown_fields` with a required `namespace_filter`, a renumbered
    /// version-4 document is still refused by the decoder itself. Renumbering
    /// is not a migration path.
    #[test]
    fn a_persisted_schema_v4_record_is_refused_by_a_message_that_names_both_versions() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(SCHEMA_V4_RECORD);
        let bytes = std::fs::read(&path).expect("the frozen version-4 record is checked in");
        assert_eq!(bytes.len(), 14_057, "the frozen record changed size");
        assert_eq!(
            Digest::sha256(&bytes).as_str(),
            "02c7dd8165e1a02d4d86efb1304ce997c5ab587a78757a9fe29b270a20ef2d96",
            "the frozen record is not the bytes this test was written against"
        );
        assert!(
            bytes.starts_with(br#"{"schema_version":4,"contract_version":1"#),
            "the frozen record is not a version-4 document"
        );

        let refusal = ValidatedLinuxProductionCommandPlanV1::decode_exact(&bytes)
            .expect_err("a version-4 record must be refused rather than upgraded");
        let message = refusal.to_string();
        assert!(
            message.contains("schema version 4"),
            "the refusal does not name the version it read: {message}"
        );
        assert!(
            message.contains(&format!(
                "required version {LINUX_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION}"
            )),
            "the refusal does not name the version it requires: {message}"
        );
        assert!(
            message.contains("never migrated"),
            "the refusal does not say that no migration exists: {message}"
        );
        assert!(
            message.contains("namespace-filter channel"),
            "the v4 refusal must say v5 adds the namespace channel, not that v4 carried no artefact: {message}"
        );
        assert!(
            !message.contains("carry no artefact that could be measured"),
            "v4 already carried artefacts; the refusal must not say otherwise: {message}"
        );

        // The same bytes with only the version number rewritten. Version 5 is
        // not version 4 with a different number: the seccomp plan gained a
        // required field, so the decoder refuses this on its own merits.
        let renumbered = String::from_utf8(bytes)
            .expect("the frozen record is UTF-8")
            .replacen(
                r#"{"schema_version":4,"#,
                r#"{"schema_version":5,"#,
                1,
            );
        assert!(
            ValidatedLinuxProductionCommandPlanV1::decode_exact(renumbered.as_bytes()).is_err(),
            "a renumbered version-4 record was admitted as version 5"
        );
    }

    /// The checked-in artefact of the version-3 plan builder.
    ///
    /// It is a real record: `fixture(RunnerRole::Worker)` emitted these exact
    /// bytes on the version-3 tree, and they are frozen here rather than
    /// regenerated because a plan carries live identities and a workspace path,
    /// so no later tree can reproduce them. The increment that measured this
    /// blocker captured the same builder's output at 13,408 bytes with plan
    /// digest `44a7293e…`; that artefact differed from this one only in the
    /// transient temporary-directory name it carried, which embeds a process
    /// id, and it was recorded rather than committed, so it cannot be
    /// reproduced and this one is committed instead.
    const SCHEMA_V3_RECORD: &str = "fixtures/linux-plan-schema/schema-v3-command-plan-record.json";

    /// A persisted version-3 record is refused by name, and never migrated.
    ///
    /// Plans **are** persisted, `persist_complete_command_plan` writes
    /// canonical bytes into the journal directory, and they **are** re-read at
    /// open, through `decode_exact`. So a schema increment owes a disposition
    /// for every record already on disk, and this test drives it with real
    /// version-3 bytes rather than with a hand-written document.
    ///
    /// Two things are asserted, and the second is the one that matters. The
    /// refusal names both versions, which the version-3 message did not do,
    /// it said only that "the schema version differs", leaving an operator with
    /// no way to tell what was found or what was wanted. And the record is not
    /// migratable by rewriting that number: the version-3 document's mandatory
    /// kernel-control components carry variant tags version 4 does not define,
    /// so a renumbered record is refused by the decoder itself. There is no
    /// silent misreading available in either direction.
    #[test]
    fn a_persisted_schema_v3_record_is_refused_by_a_message_that_names_both_versions() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(SCHEMA_V3_RECORD);
        let bytes = std::fs::read(&path).expect("the frozen version-3 record is checked in");
        assert_eq!(bytes.len(), 13_405, "the frozen record changed size");
        assert_eq!(
            Digest::sha256(&bytes).as_str(),
            "6028da5783e0bbf8117e50624f15bab3b8c99cdfbd62154254f25e8ed1ee7708",
            "the frozen record is not the bytes this test was written against"
        );
        assert!(
            bytes.starts_with(br#"{"schema_version":3,"contract_version":1"#),
            "the frozen record is not a version-3 document"
        );

        let refusal = ValidatedLinuxProductionCommandPlanV1::decode_exact(&bytes)
            .expect_err("a version-3 record must be refused rather than upgraded");
        let message = refusal.to_string();
        assert!(
            message.contains("schema version 3"),
            "the refusal does not name the version it read: {message}"
        );
        assert!(
            message.contains(&format!(
                "required version {LINUX_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION}"
            )),
            "the refusal does not name the version it requires: {message}"
        );
        assert!(
            message.contains("never migrated"),
            "the refusal does not say that no migration exists: {message}"
        );

        // The same bytes with only the version number rewritten. If version 4
        // were version 3 with a different number, this would now be admitted.
        let renumbered = String::from_utf8(bytes)
            .expect("the frozen record is UTF-8")
            .replacen(
                r#"{"schema_version":3,"#,
                // The current schema version, for the same reason the
                // held-launcher renumber arm uses the current spoken one:
                // renumbering to a version that is itself stale would be
                // refused by the version check before the decoder ever met
                // version 3's variant tags, which is what this arm is about.
                r#"{"schema_version":5,"#,
                1,
            );
        let second = ValidatedLinuxProductionCommandPlanV1::decode_exact(renumbered.as_bytes())
            .expect_err("a renumbered version-3 record is still not a current record");
        assert!(
            second
                .to_string()
                .contains("not_implemented_so_the_plan_commits_no_contract_or_probe_digest"),
            "the renumbered record was refused for the wrong reason: {second}"
        );
    }

    /// The digest domain must move with the schema version. Staying on `/v4\0`
    /// while `schema_version` is 5 would let a version-5 document share a digest
    /// with a version-4 one.
    #[test]
    fn the_plan_digest_domain_is_version_5() {
        let domain = std::str::from_utf8(LINUX_PRODUCTION_COMMAND_PLAN_DOMAIN)
            .expect("the domain is UTF-8");
        assert!(
            domain.contains("/v5"),
            "the plan digest domain must advance with schema version 5: {domain:?}"
        );
        assert!(
            !domain.contains("/v4"),
            "the plan digest domain must not remain on v4: {domain:?}"
        );
        assert_eq!(
            LINUX_PRODUCTION_COMMAND_PLAN_DOMAIN.last().copied(),
            Some(0),
            "the domain is NUL-terminated"
        );
    }

    fn plan_with_namespace_mutated(
        mutate: impl FnOnce(&mut LinuxSeccompNamespaceFilterV1),
    ) -> Result<ValidatedLinuxProductionCommandPlanV1, LinuxProductionCommandPlanError> {
        let valid = fixture(RunnerRole::Worker);
        let mut plan = valid.plan;
        let LinuxSeccompPlanV1::CompiledFilterProvenByLiveBootstrapProbe {
            namespace_filter,
            audit_architecture,
            ..
        } = &mut plan.components.seccomp;
        mutate(namespace_filter);
        namespace_filter.filter_sha256 = namespace_filter.canonical_digest(*audit_architecture);
        ValidatedLinuxProductionCommandPlanV1::from_plan(plan)
    }

    /// Validation requires the full namespace set. Incomplete tables refuse.
    #[test]
    fn an_incomplete_namespace_table_is_refused() {
        let drop_unshare = plan_with_namespace_mutated(|filter| {
            filter.denied_syscalls.retain(|denied| denied.name != "unshare");
        });
        assert!(
            drop_unshare.is_err(),
            "dropping unshare must refuse: {drop_unshare:?}"
        );

        let drop_clone = plan_with_namespace_mutated(|filter| {
            filter.denied_syscalls.retain(|denied| denied.name != "clone");
        });
        assert!(
            drop_clone.is_err(),
            "dropping clone must refuse: {drop_clone:?}"
        );

        let drop_flag = plan_with_namespace_mutated(|filter| {
            for denied in &mut filter.denied_syscalls {
                if let LinuxSeccompDenialConditionV1::AnyArgumentFlagSet { flags, .. } =
                    &mut denied.condition
                {
                    flags.pop();
                }
            }
        });
        assert!(
            drop_flag.is_err(),
            "dropping one CLONE_NEW* bit must refuse: {drop_flag:?}"
        );

        let empty_flags = plan_with_namespace_mutated(|filter| {
            for denied in &mut filter.denied_syscalls {
                if let LinuxSeccompDenialConditionV1::AnyArgumentFlagSet { flags, .. } =
                    &mut denied.condition
                {
                    flags.clear();
                }
            }
        });
        assert!(
            empty_flags.is_err(),
            "an empty flag list must refuse: {empty_flags:?}"
        );
    }

    #[test]
    fn x32_numbers_are_emitted_only_for_x86_64() {
        let native = namespace_conditional_clone(LinuxAuditArchitectureV1::X86_64).1;
        let x86 = namespace_filter_syscall_numbers(native, LinuxAuditArchitectureV1::X86_64);
        assert_eq!(x86, vec![native, native | LINUX_X32_SYSCALL_BIT]);
        let arm = namespace_filter_syscall_numbers(native, LinuxAuditArchitectureV1::Aarch64);
        assert_eq!(arm, vec![native]);
    }

    /// The bootstrap probe process has two modes. Neither is a namespace arm,
    /// and the variant name still refers to the network filter.
    #[test]
    fn the_namespace_filter_is_not_claimed_as_bootstrap_probe_proven() {
        let encoded = serde_json::to_string(&LinuxSeccompPlanV1::contract(
            LinuxAuditArchitectureV1::X86_64,
            fixture_seccomp_filter(LinuxAuditArchitectureV1::X86_64),
            fixture_namespace_filter(LinuxAuditArchitectureV1::X86_64),
        ))
        .expect("encode");
        assert!(
            encoded.contains("compiled_filter_proven_by_live_bootstrap_probe"),
            "the network filter's variant name is unchanged"
        );
        assert!(
            encoded.contains("namespace_filter"),
            "the namespace field is present"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mint_shaped_and_launcher_shaped_assembly_match() {
        for architecture in [
            LinuxAuditArchitectureV1::Aarch64,
            LinuxAuditArchitectureV1::X86_64,
        ] {
            let committed = committed_namespace_denials(architecture);
            let minted = assemble_namespace_program(&committed, architecture)
                .expect("mint-shaped assembly");
            let reconstructed = assemble_namespace_program(&committed, architecture)
                .expect("launcher-shaped assembly");
            assert_eq!(
                minted.len(),
                reconstructed.len(),
                "{architecture:?} instruction counts differ"
            );
            for (index, (left, right)) in minted.iter().zip(reconstructed.iter()).enumerate() {
                assert_eq!(left.code, right.code, "{architecture:?} code at {index}");
                assert_eq!(left.jt, right.jt, "{architecture:?} jt at {index}");
                assert_eq!(left.jf, right.jf, "{architecture:?} jf at {index}");
                assert_eq!(left.k, right.k, "{architecture:?} k at {index}");
            }

            let mut dropped = committed.clone();
            for denied in &mut dropped {
                if let LinuxSeccompDenialConditionV1::AnyArgumentFlagSet { flags, .. } =
                    &mut denied.condition
                {
                    flags.pop();
                }
            }
            let shorter = assemble_namespace_program(&dropped, architecture)
                .expect("incomplete table still assembles");
            assert_ne!(
                minted.len(),
                shorter.len(),
                "dropping a CLONE_NEW* bit must change the program"
            );

            let mut retargeted = committed.clone();
            for denied in &mut retargeted {
                if let LinuxSeccompDenialConditionV1::AnyArgumentFlagSet { flags, .. } =
                    &mut denied.condition
                {
                    flags[0].bit <<= 1;
                }
            }
            let different = assemble_namespace_program(&retargeted, architecture)
                .expect("changed mask still assembles");
            let same = minted.iter().zip(different.iter()).all(|(left, right)| {
                left.code == right.code
                    && left.jt == right.jt
                    && left.jf == right.jf
                    && left.k == right.k
            });
            assert!(!same, "changing a clone mask must change the program");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn assembled_x86_64_program_covers_x32_numbers() {
        let committed = committed_namespace_denials(LinuxAuditArchitectureV1::X86_64);
        let program = assemble_namespace_program(&committed, LinuxAuditArchitectureV1::X86_64)
            .expect("assemble x86-64");
        let ks: Vec<u32> = program.iter().map(|instruction| instruction.k).collect();
        for denied in &committed {
            for number in
                namespace_filter_syscall_numbers(denied.number, LinuxAuditArchitectureV1::X86_64)
            {
                let expected = u32::try_from(number).expect("syscall number fits u32");
                assert!(
                    ks.contains(&expected),
                    "assembled x86-64 program must name {number:#x} ({}); k values were {ks:?}",
                    denied.name
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn assembled_aarch64_program_does_not_claim_x32() {
        let committed = committed_namespace_denials(LinuxAuditArchitectureV1::Aarch64);
        let program = assemble_namespace_program(&committed, LinuxAuditArchitectureV1::Aarch64)
            .expect("assemble aarch64");
        let ks: Vec<u32> = program.iter().map(|instruction| instruction.k).collect();
        for denied in &committed {
            let x32 = u32::try_from(denied.number | LINUX_X32_SYSCALL_BIT)
                .expect("x32 number fits u32");
            assert!(
                !ks.contains(&x32),
                "aarch64 has no x32 ABI; {} at {x32:#x} must not appear",
                denied.name
            );
        }
    }
