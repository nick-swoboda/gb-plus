    #[test]
    fn retained_mechanics_authority_rejects_request_receipt_and_descriptor_substitution() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = fixture.open_bootstrap_authority(&plan);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped =
            bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap).unwrap();
        let launch_images = Fixture::select_launch_images(fixture.admit(bootstrapped));
        let setup = fixture.bind_setup_descriptors(&plan, launch_images);
        let child = Fixture::bind_child_launch_closure(setup);
        let mechanics = retain_linux_native_service_mechanics_authority(child).unwrap();

        let mut crossed_request = mechanics.request.clone();
        crossed_request.effect_id = "crossed-mechanics-effect".into();
        let error = mechanics
            .require_exact_request(&crossed_request)
            .unwrap_err();
        assert_eq!(error.operation, "bind-linux-service-mechanics-request");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let controller = fixture
            .path
            .join("service-cgroup/delegation/cgroup.subtree_control");
        let displaced = fixture
            .path
            .join("service-cgroup/delegation/displaced-subtree-control");
        let exact_bytes = fs::read(&controller).unwrap();
        fs::rename(&controller, displaced).unwrap();
        fs::write(&controller, exact_bytes).unwrap();
        let error = mechanics.revalidate_for_test().unwrap_err();
        assert_eq!(error.operation, "validate-bootstrap-subtree-control");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let receipt_fixture = Fixture::new();
        let expectation = receipt_fixture.bootstrap_expectation();
        let plan = receipt_fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = receipt_fixture.open_bootstrap_authority(&plan);
        let mut journaled = journal_linux_production_command_plan(
            plan,
            receipt_fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        journaled.receipt.effect_id = "crossed-durable-receipt-effect".into();
        let error = bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)
            .unwrap_err();
        assert_eq!(error.operation, "bind-linux-service-bootstrap-plan");
        assert_eq!(error.certainty, EffectCertainty::Ambiguous);
    }

    #[test]
    fn native_service_admission_derives_the_complete_set_and_rejects_absent_or_mount_crossed_images()
     {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            fixture.open_bootstrap_authority(&plan),
        )
        .unwrap();
        fs::rename(
            fixture.path.join("authenticated-tools/libc.so.6"),
            fixture.path.join("authenticated-tools/displaced-libc.so.6"),
        )
        .unwrap();
        let error =
            admit_linux_native_service_command(bootstrapped, fixture.service_process_image())
                .unwrap_err();
        assert_eq!(error.operation, "open-native-service-executable");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let mount_crossed = Fixture::new();
        let expectation = mount_crossed.bootstrap_expectation();
        let mut inner = mount_crossed.executable_file_binding("inner-launcher");
        inner.mount_id = inner.mount_id.checked_add(1).unwrap();
        let inner_path = mount_crossed
            .path
            .join("authenticated-tools/inner-launcher");
        let plan = mount_crossed
            .bootstrap_plan(crate::wire::RunnerRole::Worker)
            .rebind_test_executable_file("inner", inner_path.to_str().unwrap(), &inner)
            .unwrap();
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            mount_crossed.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            mount_crossed.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let error =
            admit_linux_native_service_command(bootstrapped, mount_crossed.service_process_image())
                .unwrap_err();
        assert_eq!(error.operation, "validate-native-service-executable");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
    }

    #[test]
    fn live_executable_set_rejects_one_inode_across_distinct_mount_identities() {
        let identity = ObjectIdentity {
            device: 81,
            inode: 82,
        };
        let mut observed = BTreeMap::new();
        require_distinct_executable_kernel_object(&mut observed, "inner", identity, 83).unwrap();
        let error =
            require_distinct_executable_kernel_object(&mut observed, "target", identity, 84)
                .unwrap_err();
        assert_eq!(error.operation, "validate-native-service-executable-set");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(error.detail.contains("alias one kernel inode"));
        assert!(error.detail.contains("mount 83"));
        assert!(error.detail.contains("mount 84"));
    }

    #[test]
    fn sealed_executable_snapshot_evidence_is_exact_and_fail_closed() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let binding = plan
            .service_executable_bindings()
            .unwrap()
            .into_iter()
            .find(|binding| binding.object_id == "target")
            .expect("test plan contains a target executable");
        let launch_binding = plan
            .service_launch_image_bindings()
            .unwrap()
            .into_iter()
            .find(|binding| binding.object_id == "target")
            .expect("test plan contains a target launch image");
        let canonical = LinuxSealedExecutableSnapshotObservation {
            identity: ObjectIdentity {
                device: 101,
                inode: 102,
            },
            regular_file: true,
            memfd_filesystem: true,
            owner_is_effective_identity: true,
            link_count: 0,
            permissions: 0o500,
            byte_length: binding.file.byte_length,
            content_sha256: binding.file.content_sha256.clone(),
            seal_bits: REQUIRED_EXECUTABLE_SNAPSHOT_SEAL_BITS,
            close_on_exec: true,
        };
        validate_sealed_executable_snapshot_observation(&binding, &canonical).unwrap();
        validate_launch_image_snapshot_observation(&launch_binding, &canonical).unwrap();

        let mut crossed_content = canonical.clone();
        crossed_content.content_sha256 = Digest::sha256(b"crossed snapshot");
        let mut crossed_seals = canonical.clone();
        crossed_seals.seal_bits &= !0x20;
        let mut linked = canonical.clone();
        linked.link_count = 1;
        let mut inheritable = canonical.clone();
        inheritable.close_on_exec = false;
        let mut non_memfd = canonical.clone();
        non_memfd.memfd_filesystem = false;
        let mut zero_identity = canonical.clone();
        zero_identity.identity.inode = 0;
        let mut crossed_owner = canonical.clone();
        crossed_owner.owner_is_effective_identity = false;
        let mut crossed_mode = canonical.clone();
        crossed_mode.permissions = 0o700;
        let mut crossed_length = canonical.clone();
        crossed_length.byte_length = crossed_length.byte_length.checked_add(1).unwrap();
        let mut non_regular = canonical;
        non_regular.regular_file = false;

        for crossed in [
            crossed_content,
            crossed_seals,
            linked,
            inheritable,
            non_memfd,
            zero_identity,
            crossed_owner,
            crossed_mode,
            crossed_length,
            non_regular,
        ] {
            let error =
                validate_sealed_executable_snapshot_observation(&binding, &crossed).unwrap_err();
            assert_eq!(error.operation, "validate-native-service-sealed-executable");
            assert_eq!(error.certainty, EffectCertainty::NotApplied);
            let error =
                validate_launch_image_snapshot_observation(&launch_binding, &crossed).unwrap_err();
            assert_eq!(error.operation, "validate-native-service-sealed-executable");
            assert_eq!(error.certainty, EffectCertainty::NotApplied);
        }
        let mut maximum_image = binding.clone();
        maximum_image.file.byte_length = MAX_NATIVE_SERVICE_EXECUTABLE_BYTES as u64;
        let oversized = [
            maximum_image.clone(),
            maximum_image.clone(),
            maximum_image.clone(),
            maximum_image.clone(),
            maximum_image,
        ];
        let error = validate_executable_snapshot_set_preflight(&oversized).unwrap_err();
        assert_eq!(error.operation, "bind-native-service-sealed-executable-set");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
    }

    #[test]
    fn executable_snapshot_preflight_bounds_descriptors_before_open_or_allocation() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let binding = plan
            .service_executable_bindings()
            .unwrap()
            .into_iter()
            .find(|binding| binding.object_id == "target")
            .expect("test plan contains a target executable");

        let absent_path = fixture
            .path
            .join("preflight-must-not-open")
            .join("missing-image");
        assert!(!absent_path.exists());
        let mut shallow = binding.clone();
        shallow.resolved_path = absent_path
            .to_str()
            .expect("preflight path is UTF-8")
            .to_owned();
        let shallow_descriptor_cost = executable_provenance_component_count(
            &shallow.resolved_path,
            "test-executable-snapshot-preflight",
        )
        .unwrap()
            + 2;
        let oversized_count = MAX_EXECUTABLE_SNAPSHOT_RETAINED_DESCRIPTORS
            .checked_div(shallow_descriptor_cost)
            .unwrap()
            + 1;
        let oversized = vec![shallow; oversized_count];
        let error = validate_executable_snapshot_set_preflight(&oversized).unwrap_err();
        assert_eq!(error.operation, "preflight-native-service-executable-set");
        assert!(error.detail.contains("retained descriptors"));
        assert!(!absent_path.exists());

        let component_count = MAX_EXECUTABLE_SNAPSHOT_RETAINED_DESCRIPTORS - 1;
        let mut deep = binding;
        deep.resolved_path = format!("/{}", vec!["d"; component_count].join("/"));
        assert!(deep.resolved_path.len() < MAX_EXECUTABLE_PROVENANCE_PATH_BYTES);
        let error = validate_executable_snapshot_set_preflight(&[deep]).unwrap_err();
        assert_eq!(error.operation, "preflight-native-service-executable-set");
        assert!(error.detail.contains("retained descriptors"));
    }

    #[test]
    fn runtime_object_source_mode_is_nonwritable_without_requiring_execute() {
        let accepted = Fixture::new();
        let accepted_path = accepted.path.join("authenticated-tools/libc.so.6");
        fs::set_permissions(&accepted_path, fs::Permissions::from_mode(0o644)).unwrap();
        let accepted_plan = accepted.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let accepted_binding = accepted_plan
            .service_executable_bindings()
            .unwrap()
            .into_iter()
            .find(|binding| binding.role == LinuxServiceExecutableRoleV1::RuntimeObject)
            .expect("test plan contains a runtime object");
        let accepted_descriptor =
            LinuxNativeServiceExecutableDescriptor::open_planned(&accepted_binding).unwrap();
        accepted_descriptor
            .validate_source_for(&accepted_binding)
            .expect("an owner-readable nonwritable runtime object needs no execute bit");

        for rejected_mode in [0o664, 0o777] {
            let rejected = Fixture::new();
            let rejected_path = rejected.path.join("authenticated-tools/libc.so.6");
            fs::set_permissions(&rejected_path, fs::Permissions::from_mode(rejected_mode)).unwrap();
            let rejected_plan = rejected.bootstrap_plan(crate::wire::RunnerRole::Worker);
            let rejected_binding = rejected_plan
                .service_executable_bindings()
                .unwrap()
                .into_iter()
                .find(|binding| binding.role == LinuxServiceExecutableRoleV1::RuntimeObject)
                .expect("test plan contains a runtime object");
            let rejected_descriptor =
                LinuxNativeServiceExecutableDescriptor::open_planned(&rejected_binding).unwrap();
            let error = rejected_descriptor
                .validate_source_for(&rejected_binding)
                .unwrap_err();
            assert_eq!(error.operation, "validate-native-service-executable");
            assert_eq!(error.certainty, EffectCertainty::NotApplied);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sealed_executable_snapshot_survives_same_byte_source_replacement() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let binding = plan
            .service_executable_bindings()
            .unwrap()
            .into_iter()
            .find(|binding| binding.object_id == "target")
            .expect("test plan contains a target executable");
        let mut descriptor = LinuxNativeServiceExecutableDescriptor::open_planned(&binding)
            .expect("open exact planned source descriptor");
        descriptor
            .validate_source_for(&binding)
            .expect("source validates before immutable copy");
        descriptor
            .seal_snapshot_for(&binding)
            .expect("copy and seal exact executable image");
        let snapshot = descriptor
            .sealed_snapshot
            .as_ref()
            .expect("Linux admission retains the sealed image");
        snapshot
            .validate_for(&binding)
            .expect("sealed snapshot has exact kernel evidence");

        let source_path = fixture.path.join("authenticated-tools/target");
        let bytes = fs::read(&source_path).unwrap();
        fs::rename(
            &source_path,
            fixture
                .path
                .join("authenticated-tools/displaced-sealed-target"),
        )
        .unwrap();
        fs::write(&source_path, bytes).unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o700)).unwrap();

        snapshot
            .validate_for(&binding)
            .expect("sealed descriptor remains the exact admitted bytes");
        let error = descriptor.validate_source_for(&binding).unwrap_err();
        assert_eq!(error.operation, "validate-native-service-executable");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
    }

    #[test]
    fn reusable_or_zero_mount_id_evidence_is_not_unique_mount_authority() {
        const REUSABLE_STATX_MNT_ID_BITS: u32 = 0x0000_1000;

        for (returned_mask, mount_id) in [
            (REUSABLE_STATX_MNT_ID_BITS, 91),
            (STATX_MNT_ID_UNIQUE_BITS, 0),
        ] {
            let error =
                require_unique_mount_id(returned_mask, mount_id, "test-unique-mount-identity")
                    .unwrap_err();
            assert_eq!(error.operation, "test-unique-mount-identity");
            assert_eq!(error.certainty, EffectCertainty::NotApplied);
            assert!(error.detail.contains("STATX_MNT_ID_UNIQUE"));
        }
        assert_eq!(
            require_unique_mount_id(STATX_MNT_ID_UNIQUE_BITS, 92, "test-unique-mount-identity")
                .unwrap(),
            92
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a native Linux mount namespace with CAP_SYS_ADMIN; an ignored result is not Gate evidence"]
    fn root_capable_bind_mount_alias_has_distinct_unique_mount_ids_but_is_rejected() {
        let fixture = Fixture::new();
        let source = fixture.path.join("authenticated-tools/target");
        let alias = fixture.path.join("bind-mounted-target-alias");
        fs::write(&alias, b"bind mount point\n").unwrap();
        let status = Command::new("mount")
            .arg("--bind")
            .arg(&source)
            .arg(&alias)
            .status()
            .expect("run mount for bind-alias fixture");
        assert!(
            status.success(),
            "ignored bind-alias fixture must run only with CAP_SYS_ADMIN"
        );
        let mount = BindMountGuard(Some(alias.clone()));

        let source_file = fs::File::open(&source).unwrap();
        let alias_file = fs::File::open(&alias).unwrap();
        let source_metadata = source_file.metadata().unwrap();
        let alias_metadata = alias_file.metadata().unwrap();
        let source_identity = ObjectIdentity {
            device: PortableMetadataExt::dev(&source_metadata),
            inode: PortableMetadataExt::ino(&source_metadata),
        };
        let alias_identity = ObjectIdentity {
            device: PortableMetadataExt::dev(&alias_metadata),
            inode: PortableMetadataExt::ino(&alias_metadata),
        };
        assert_eq!(source_identity, alias_identity);
        assert_eq!(PortableMetadataExt::nlink(&source_metadata), 1);
        assert_eq!(PortableMetadataExt::nlink(&alias_metadata), 1);
        let source_mount_id =
            retained_descriptor_mount_id(&source_file, "probe-bind-source-mount").unwrap();
        let alias_mount_id =
            retained_descriptor_mount_id(&alias_file, "probe-bind-alias-mount").unwrap();
        assert_ne!(source_mount_id, alias_mount_id);

        let mut observed = BTreeMap::new();
        require_distinct_executable_kernel_object(
            &mut observed,
            "inner",
            source_identity,
            source_mount_id,
        )
        .unwrap();
        let error = require_distinct_executable_kernel_object(
            &mut observed,
            "target",
            alias_identity,
            alias_mount_id,
        )
        .unwrap_err();
        assert!(error.detail.contains("alias one kernel inode"));

        mount.unmount();
    }

    #[test]
    fn native_service_admission_binds_and_retains_the_exact_service_process_image() {
        let crossed = Fixture::new();
        let expectation = crossed.bootstrap_expectation();
        let plan = crossed.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            crossed.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            crossed.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let crossed_image_path = crossed.path.join("authenticated-tools/target");
        let crossed_image = LinuxNativeServiceProcessImageAuthority::open_test_absolute(
            crossed_image_path.to_str().unwrap(),
        )
        .unwrap();
        let error = admit_linux_native_service_command(bootstrapped, crossed_image).unwrap_err();
        assert_eq!(error.operation, "bind-native-service-process-image");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let before_admission = Fixture::new();
        let expectation = before_admission.bootstrap_expectation();
        let plan = before_admission.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            before_admission.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            before_admission.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let authority = before_admission.service_process_image();
        let image = before_admission
            .path
            .join("authenticated-tools/native-service");
        let bytes = fs::read(&image).unwrap();
        fs::rename(
            &image,
            before_admission
                .path
                .join("authenticated-tools/displaced-native-service"),
        )
        .unwrap();
        fs::write(&image, bytes).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
        let error = admit_linux_native_service_command(bootstrapped, authority).unwrap_err();
        assert_eq!(error.operation, "validate-native-service-process-image");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let live = Fixture::new();
        let expectation = live.bootstrap_expectation();
        let plan = live.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            live.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            live.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let admission = live.admit(bootstrapped);
        let image = live.path.join("authenticated-tools/native-service");
        let bytes = fs::read(&image).unwrap();
        fs::rename(
            &image,
            live.path
                .join("authenticated-tools/displaced-live-native-service"),
        )
        .unwrap();
        fs::write(&image, bytes).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
        let error = admission.revalidate_for_test().unwrap_err();
        assert_eq!(error.operation, "validate-native-service-process-image");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
    }

    #[test]
    fn native_service_admission_and_live_guard_reject_same_byte_executable_inode_replacement() {
        let before_admission = Fixture::new();
        let expectation = before_admission.bootstrap_expectation();
        let plan = before_admission.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            before_admission.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            before_admission.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let image = before_admission
            .path
            .join("authenticated-tools/inner-launcher");
        let bytes = fs::read(&image).unwrap();
        fs::rename(
            &image,
            before_admission
                .path
                .join("authenticated-tools/displaced-inner-launcher"),
        )
        .unwrap();
        fs::write(&image, bytes).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
        let error = admit_linux_native_service_command(
            bootstrapped,
            before_admission.service_process_image(),
        )
        .unwrap_err();
        assert_eq!(error.operation, "validate-native-service-executable");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let live = Fixture::new();
        let expectation = live.bootstrap_expectation();
        let plan = live.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            live.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            live.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let admission = live.admit(bootstrapped);
        let image = live.path.join("authenticated-tools/inner-launcher");
        let bytes = fs::read(&image).unwrap();
        fs::rename(
            &image,
            live.path
                .join("authenticated-tools/displaced-live-inner-launcher"),
        )
        .unwrap();
        fs::write(&image, bytes).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
        let error = admission.revalidate_for_test().unwrap_err();
        assert_eq!(error.operation, "validate-native-service-executable");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
    }

    #[test]
    fn native_service_admission_rejects_preexisting_and_live_same_inode_hardlink_aliases() {
        let preexisting_service_alias = Fixture::new();
        let service_image = preexisting_service_alias
            .path
            .join("authenticated-tools/native-service");
        fs::hard_link(
            &service_image,
            preexisting_service_alias
                .path
                .join("authenticated-tools/native-service-alias"),
        )
        .unwrap();
        let error = LinuxNativeServiceProcessImageAuthority::open_test_absolute(
            service_image.to_str().unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.operation, "validate-native-service-process-image");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(error.detail.contains("singly linked"));

        let preexisting_command_alias = Fixture::new();
        fs::hard_link(
            preexisting_command_alias
                .path
                .join("authenticated-tools/target"),
            preexisting_command_alias
                .path
                .join("authenticated-tools/target-alias"),
        )
        .unwrap();
        let expectation = preexisting_command_alias.bootstrap_expectation();
        let plan = preexisting_command_alias.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            preexisting_command_alias.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            preexisting_command_alias.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let error = admit_linux_native_service_command(
            bootstrapped,
            preexisting_command_alias.service_process_image(),
        )
        .unwrap_err();
        assert_eq!(error.operation, "validate-native-service-executable");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let live_command_alias = Fixture::new();
        let expectation = live_command_alias.bootstrap_expectation();
        let plan = live_command_alias.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            live_command_alias.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            live_command_alias.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let admission = live_command_alias.admit(bootstrapped);
        fs::hard_link(
            live_command_alias
                .path
                .join("authenticated-tools/inner-launcher"),
            live_command_alias
                .path
                .join("authenticated-tools/inner-launcher-alias"),
        )
        .unwrap();
        let error = admission.revalidate_for_test().unwrap_err();
        assert_eq!(error.operation, "validate-native-service-executable");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let live_service_alias = Fixture::new();
        let expectation = live_service_alias.bootstrap_expectation();
        let plan = live_service_alias.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            live_service_alias.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            live_service_alias.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let admission = live_service_alias.admit(bootstrapped);
        fs::hard_link(
            live_service_alias
                .path
                .join("authenticated-tools/native-service"),
            live_service_alias
                .path
                .join("authenticated-tools/native-service-live-alias"),
        )
        .unwrap();
        let error = admission.revalidate_for_test().unwrap_err();
        assert_eq!(error.operation, "validate-native-service-process-image");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
    }

    #[test]
    fn native_service_admission_rejects_parent_rename_replacement_and_crossed_mount_evidence() {
        let before_admission = Fixture::new();
        let expectation = before_admission.bootstrap_expectation();
        let plan = before_admission.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            before_admission.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            before_admission.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let service_image = before_admission.service_process_image();
        replace_authenticated_tool_parent_with_exact_bytes(&before_admission, "before-admission");
        let error = admit_linux_native_service_command(bootstrapped, service_image).unwrap_err();
        assert_eq!(error.operation, "validate-native-service-process-image");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(error.detail.contains("parent"));

        let live = Fixture::new();
        let expectation = live.bootstrap_expectation();
        let plan = live.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            live.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            live.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let admission = live.admit(bootstrapped);
        replace_authenticated_tool_parent_with_exact_bytes(&live, "live");
        let error = admission.revalidate_for_test().unwrap_err();
        assert_eq!(error.operation, "validate-native-service-executable");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(error.detail.contains("parent"));

        let mount_crossed = Fixture::new();
        let expectation = mount_crossed.bootstrap_expectation();
        let plan = mount_crossed.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            mount_crossed.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            mount_crossed.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let mut admission = mount_crossed.admit(bootstrapped);
        let parent = admission.executables.descriptors[0]
            .provenance
            .parents
            .last_mut()
            .expect("test executable has a retained parent chain");
        parent.observation.mount_id = parent.observation.mount_id.checked_add(1).unwrap();
        let error = admission.revalidate_for_test().unwrap_err();
        assert_eq!(error.operation, "validate-native-service-executable");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(error.detail.contains("parent"));
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
    }

    #[test]
    fn native_service_path_provenance_rejects_a_symlinked_parent_component() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            fixture.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let service_image = fixture.service_process_image();
        let live = fixture.path.join("authenticated-tools");
        let displaced = fixture.path.join("displaced-authenticated-tools-symlink");
        fs::rename(&live, &displaced).unwrap();
        symlink(&displaced, &live).unwrap();

        let error = admit_linux_native_service_command(bootstrapped, service_image).unwrap_err();
        assert_eq!(error.operation, "validate-native-service-process-image");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
    }

    #[test]
    fn tokened_and_tokenless_runtime_boundaries_revalidate_the_service_lifetime_guard() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            fixture.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let launch_images = Fixture::select_launch_images(fixture.admit(bootstrapped));
        let setup = fixture.bind_setup_descriptors(&plan, launch_images);
        let child = Fixture::bind_child_launch_closure(setup);
        let mechanics = retain_linux_native_service_mechanics_authority(child).unwrap();
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
        // The residual the runtime guard re-validates against, split from the
        // same single authority `into_journal` consumes.
        let (journal_store, residual) = journal_authority
            .into_journal(expectation)
            .expect("split the journal authority at consumption");
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
        mechanics_guard.validate_retained(&journal_store).unwrap();

        let service_parent = fixture.parent();
        let metadata = service_parent.dir_metadata().unwrap();
        let identity = cgroup_identity(object_identity(&metadata));
        let mut backend = LinuxCgroupIo {
            service_parent: service_parent.try_clone().unwrap(),
            delegation_name: "unused-runtime-guard-test".into(),
            delegation: service_parent,
            expectation: DelegationRootExpectation {
                service_parent_identity: identity,
                delegation_identity: identity,
                owner_uid: fixture.expected_uid,
                delegation_mode: OsMetadataExt::mode(&metadata) & 0o7777,
            },
            journal: fixture.open_store(),
            mechanics_guard: Some(mechanics_guard),
            helper_image_override: None,
            leaves: BTreeMap::new(),
            active_probe: None,
            probe_reconciliation_required: false,
            #[cfg(target_os = "linux")]
            procfs: LinuxProcfs::open_authenticated().unwrap(),
            #[cfg(target_os = "linux")]
            held_launchers: HeldLauncherRegistry::default(),
        };
        let raw_token = backend.journal.acquire_lock().unwrap();
        let token = DelegationLockToken::new(raw_token);

        let lock_path = fixture.path.join(SERVICE_LIFETIME_LOCK_NAME);
        fs::rename(
            &lock_path,
            fixture
                .path
                .join("displaced-runtime-boundary-lifetime-lock"),
        )
        .unwrap();
        fs::write(&lock_path, b"").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();

        let error = backend
            .write_leaf_file(
                &token,
                "unreachable-leaf",
                identity,
                LeafWriteFile::PidsMax,
                b"1\n",
            )
            .unwrap_err();
        assert_eq!(error.operation, "validate-linux-native-service-lifetime");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        let error = backend.poll_barrier().unwrap_err();
        assert_eq!(error.operation, "validate-linux-native-service-lifetime");
        backend.journal.release_lock(raw_token).unwrap();
    }

    #[test]
    fn native_service_lifetime_lock_is_singleton_and_replacement_sensitive() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let binding = plan.journal_binding().unwrap();
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            fixture.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let admission = fixture.admit(bootstrapped);

        let error = LinuxNativeServiceLifetimeLock::acquire(
            &fixture.parent(),
            binding.service_state_root_identity,
            binding.owner_uid,
        )
        .unwrap_err();
        assert_eq!(error.operation, "lock-linux-native-service-lifetime");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let lock_path = fixture.path.join(SERVICE_LIFETIME_LOCK_NAME);
        fs::rename(
            &lock_path,
            fixture.path.join("displaced-native-service-lifetime-lock"),
        )
        .unwrap();
        fs::write(&lock_path, b"").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = admission.revalidate_for_test().unwrap_err();
        assert_eq!(error.operation, "validate-linux-native-service-lifetime");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        drop(admission);

        fs::remove_file(&lock_path).unwrap();
        fs::rename(
            fixture.path.join("displaced-native-service-lifetime-lock"),
            &lock_path,
        )
        .unwrap();
        let reacquired = LinuxNativeServiceLifetimeLock::acquire(
            &fixture.parent(),
            binding.service_state_root_identity,
            binding.owner_uid,
        )
        .unwrap();
        reacquired
            .validate_for(&fixture.parent(), binding.service_state_root_identity)
            .unwrap();
    }

    #[test]
    fn dropped_native_service_admission_cannot_replay_the_effect_after_restart() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            fixture.open_bootstrap_authority(&plan),
        )
        .unwrap();
        let admission = fixture.admit(bootstrapped);
        admission.revalidate_for_test().unwrap();
        drop(admission);

        let error = journal_linux_production_command_plan(
            plan,
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap_err();
        assert_eq!(error.certainty, EffectCertainty::PriorEffectCommitted);
        assert!(error.detail.contains("already committed"));
    }

    #[test]
    fn retained_mechanics_revalidation_rejects_exact_bytes_on_a_replacement_plan_inode() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = fixture.open_bootstrap_authority(&plan);
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped =
            bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap).unwrap();
        let launch_images = Fixture::select_launch_images(fixture.admit(bootstrapped));
        let setup = fixture.bind_setup_descriptors(&plan, launch_images);
        let child = Fixture::bind_child_launch_closure(setup);
        let mechanics = retain_linux_native_service_mechanics_authority(child).unwrap();
        let published_identity = mechanics.receipt.artifact_identity;

        let replacement_identity = replace_command_plan_artifact_with_exact_bytes(&fixture, &plan);
        assert_ne!(replacement_identity, published_identity);

        let error = mechanics.revalidate_for_test().unwrap_err();
        assert_eq!(error.operation, "authenticate-command-plan-artifact");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(!LinuxNativeServiceMechanicsAuthority::permits_execution());
    }

    #[test]
    fn locked_refresh_admits_new_plan_but_rejects_replacement_of_retained_plan_inode() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let first_plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let mut first = journal_linux_production_command_plan(
            first_plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let retained_identity = first.receipt.artifact_identity;

        let new_plan = fixture.bootstrap_plan(crate::wire::RunnerRole::FinalVerifier);
        let second = journal_linux_production_command_plan(
            new_plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        drop(second);
        let token = first.journal_authority.journal.acquire_lock().unwrap();
        assert!(
            first
                .journal_authority
                .journal
                .command_plans
                .contains_key(new_plan.effect_id())
        );
        first.journal_authority.journal.release_lock(token).unwrap();

        let replacement_identity =
            replace_command_plan_artifact_with_exact_bytes(&fixture, &first_plan);
        assert_ne!(replacement_identity, retained_identity);
        let error = first.journal_authority.journal.acquire_lock().unwrap_err();
        assert_eq!(error.operation, "command-plan-artifact-continuity");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert_eq!(
            first
                .journal_authority
                .journal
                .command_plans
                .get(first_plan.effect_id())
                .unwrap()
                .identity,
            retained_identity
        );
        assert!(first.journal_authority.journal.held_token.is_none());
    }

    #[test]
    fn service_restart_accepts_exact_bootstrap_bytes_on_a_new_unanchored_inode() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let evidence = fixture.bootstrap_evidence(&plan);
        let authority = fixture
            .open_bootstrap_authority_with_evidence(evidence.clone())
            .unwrap();
        let artifact = fixture.path.join(SERVICE_BOOTSTRAP_FINAL_NAME);
        let original_identity = object_identity(
            &fixture
                .parent()
                .symlink_metadata(SERVICE_BOOTSTRAP_FINAL_NAME)
                .unwrap(),
        );
        let exact_bytes = fs::read(&artifact).unwrap();
        drop(authority);

        fs::rename(
            &artifact,
            fixture.path.join("displaced-bootstrap-from-prior-service"),
        )
        .unwrap();
        write_new_private_file(
            &fixture.parent(),
            SERVICE_BOOTSTRAP_FINAL_NAME,
            &exact_bytes,
            fixture.expected_uid,
        )
        .unwrap();
        let replacement_identity = object_identity(
            &fixture
                .parent()
                .symlink_metadata(SERVICE_BOOTSTRAP_FINAL_NAME)
                .unwrap(),
        );
        assert_ne!(replacement_identity, original_identity);

        let restarted = fixture
            .open_bootstrap_authority_with_evidence(evidence)
            .unwrap();
        let journaled = journal_linux_production_command_plan(
            plan.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped =
            bind_journaled_plan_to_linux_native_service_bootstrap(journaled, restarted).unwrap();
        let launch_images = Fixture::select_launch_images(fixture.admit(bootstrapped));
        let setup = fixture.bind_setup_descriptors(&plan, launch_images);
        let child = Fixture::bind_child_launch_closure(setup);
        let mechanics = retain_linux_native_service_mechanics_authority(child).unwrap();
        mechanics.revalidate_for_test().unwrap();
        assert!(!LinuxNativeServiceMechanicsAuthority::permits_execution());
    }

    #[test]
    fn service_bootstrap_restart_digest_excludes_transient_probe_pid() {
        let measurement = |pid| LinuxDelegatedCgroupActiveProbeMeasurement {
            leaf_name: format!("gbd-bootstrap-probe-{pid}"),
            leaf_controllers: b"memory pids\n".to_vec(),
            pids_max_readback: b"7\n".to_vec(),
            memory_max_readback: b"max\n".to_vec(),
        };
        let first = measurement(44_310);
        let mut restarted = measurement(44_367);
        assert_ne!(first.leaf_name, restarted.leaf_name);
        assert_eq!(
            cgroup_bootstrap_probe_result_digest(&first),
            cgroup_bootstrap_probe_result_digest(&restarted)
        );
        restarted.pids_max_readback = b"8\n".to_vec();
        assert_ne!(
            cgroup_bootstrap_probe_result_digest(&first),
            cgroup_bootstrap_probe_result_digest(&restarted)
        );
    }

    #[test]
    fn service_restart_accepts_new_command_landlock_evidence_but_not_service_drift() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let first = fixture.bootstrap_evidence(&plan);
        let mut next = first.clone();
        let LinuxLandlockBootstrapBindingV1::InstalledRulesetProvenByLiveBootstrapProbe {
            ruleset,
            ..
        } = &mut next.plan_binding.landlock;
        ruleset.scopes[0].resolved_path.push_str("-next-command");
        ruleset.scopes[0].inode += 1;
        ruleset.ruleset_sha256 = ruleset.canonical_digest();
        next.landlock.active_probe_result_digest =
            landlock_bootstrap_probe_result_digest(ruleset, next.landlock.observed_kernel_abi);
        validate_service_bootstrap_evidence(&next).expect("validate next command evidence");
        assert!(same_service_bootstrap_identity(&first, &next));
        let state = fixture.parent();
        let (first_bytes, first_identity) =
            persist_or_read_service_bootstrap_evidence(&state, fixture.expected_uid, &first)
                .expect("persist first command bootstrap");
        let (next_bytes, next_identity) =
            persist_or_read_service_bootstrap_evidence(&state, fixture.expected_uid, &next)
                .expect("reopen stable service for next command");
        assert_eq!((first_bytes, first_identity), (next_bytes, next_identity));

        next.plan_binding.journal.delegation_identity.inode += 1;
        assert!(!same_service_bootstrap_identity(&first, &next));
    }

    #[test]
    fn service_bootstrap_rejects_bubblewrap_version_and_kernel_control_window_substitution() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let original = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = fixture.open_bootstrap_authority(&original);
        let crossed_version = original.clone().substitute_test_same_effect_plan().unwrap();
        let journaled = journal_linux_production_command_plan(
            crossed_version,
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let error = bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)
            .unwrap_err();
        assert_eq!(error.operation, "bind-linux-service-bootstrap-plan");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let original = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = fixture.open_bootstrap_authority(&original);
        let crossed_probes = original.substitute_test_kernel_control_window().unwrap();
        let journaled = journal_linux_production_command_plan(
            crossed_probes,
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let error = bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)
            .unwrap_err();
        assert_eq!(error.operation, "bind-linux-service-bootstrap-plan");
        assert!(error.detail.contains("Landlock"));
        assert!(error.detail.contains("seccomp"));
    }

    #[test]
    fn service_bootstrap_restart_rejects_evidence_and_format_version_substitution() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let evidence = fixture.bootstrap_evidence(&plan);
        drop(
            fixture
                .open_bootstrap_authority_with_evidence(evidence.clone())
                .unwrap(),
        );

        let mut crossed_probe = evidence;
        crossed_probe.cgroup.active_probe_result_digest =
            Digest::sha256(b"crossed-cgroup-bootstrap-probe-result");
        let error = fixture
            .open_bootstrap_authority_with_evidence(crossed_probe)
            .unwrap_err();
        assert_eq!(
            error.operation,
            "authenticate-linux-service-bootstrap-restart"
        );
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let artifact = fixture.path.join(SERVICE_BOOTSTRAP_FINAL_NAME);
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&artifact).unwrap()).unwrap();
        envelope["format_version"] = serde_json::json!(2);
        fs::write(&artifact, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let error = fixture
            .open_bootstrap_authority_with_evidence(fixture.bootstrap_evidence(&plan))
            .unwrap_err();
        assert_eq!(error.operation, "classify-linux-service-bootstrap-envelope");
        assert!(error.detail.contains("unsupported"));
    }

    #[test]
    fn service_bootstrap_capability_failure_is_prepublication_and_restartable() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let evidence = fixture.bootstrap_evidence(&plan);
        fs::write(
            fixture
                .path
                .join("service-cgroup/delegation/cgroup.subtree_control"),
            b"memory\n",
        )
        .unwrap();

        let error = fixture
            .open_bootstrap_authority_with_evidence(evidence)
            .unwrap_err();
        assert_eq!(error.operation, "validate-bootstrap-subtree-control");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(!fixture.path.join(SERVICE_BOOTSTRAP_FINAL_NAME).exists());
        assert!(!fixture.path.join(SERVICE_BOOTSTRAP_TEMP_NAME).exists());

        fs::write(
            fixture
                .path
                .join("service-cgroup/delegation/cgroup.subtree_control"),
            b"memory pids\n",
        )
        .unwrap();
        fixture.open_bootstrap_authority(&plan);
        assert!(fixture.path.join(SERVICE_BOOTSTRAP_FINAL_NAME).is_file());
    }

    #[test]
    fn service_bootstrap_temporary_crash_cuts_recover_only_exact_publication() {
        let unpublished = Fixture::new();
        let plan = unpublished.bootstrap_plan(crate::wire::RunnerRole::Worker);
        write_new_private_file(
            &unpublished.parent(),
            SERVICE_BOOTSTRAP_TEMP_NAME,
            b"{",
            unpublished.expected_uid,
        )
        .unwrap();
        unpublished.open_bootstrap_authority(&plan);
        assert!(!unpublished.path.join(SERVICE_BOOTSTRAP_TEMP_NAME).exists());
        assert!(
            unpublished
                .path
                .join(SERVICE_BOOTSTRAP_FINAL_NAME)
                .is_file()
        );

        let exact = Fixture::new();
        let plan = exact.bootstrap_plan(crate::wire::RunnerRole::Worker);
        drop(exact.open_bootstrap_authority(&plan));
        let final_bytes = fs::read(exact.path.join(SERVICE_BOOTSTRAP_FINAL_NAME)).unwrap();
        write_new_private_file(
            &exact.parent(),
            SERVICE_BOOTSTRAP_TEMP_NAME,
            &final_bytes,
            exact.expected_uid,
        )
        .unwrap();
        exact.open_bootstrap_authority(&plan);
        assert!(!exact.path.join(SERVICE_BOOTSTRAP_TEMP_NAME).exists());

        let crossed = Fixture::new();
        let plan = crossed.bootstrap_plan(crate::wire::RunnerRole::Worker);
        drop(crossed.open_bootstrap_authority(&plan));
        write_new_private_file(
            &crossed.parent(),
            SERVICE_BOOTSTRAP_TEMP_NAME,
            b"crossed-bootstrap-evidence",
            crossed.expected_uid,
        )
        .unwrap();
        let error = crossed
            .open_bootstrap_authority_with_evidence(crossed.bootstrap_evidence(&plan))
            .unwrap_err();
        assert_eq!(error.operation, "recover-linux-service-bootstrap-temporary");
        assert_eq!(error.certainty, EffectCertainty::Ambiguous);
        assert!(crossed.path.join(SERVICE_BOOTSTRAP_TEMP_NAME).is_file());
        assert!(crossed.path.join(SERVICE_BOOTSTRAP_FINAL_NAME).is_file());
    }

    #[test]
    fn retained_service_bootstrap_artifact_descriptor_rejects_named_replacement() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let (authority, journal_authority) = fixture
            .open_bootstrap_authority_and_journal(fixture.bootstrap_evidence(&plan))
            .expect("open test-only retained Linux service bootstrap authority");
        let final_path = fixture.path.join(SERVICE_BOOTSTRAP_FINAL_NAME);
        let final_bytes = fs::read(&final_path).unwrap();
        fs::rename(
            &final_path,
            fixture.path.join("displaced-service-bootstrap-artifact"),
        )
        .unwrap();
        write_new_private_file(
            &fixture.parent(),
            SERVICE_BOOTSTRAP_FINAL_NAME,
            &final_bytes,
            fixture.expected_uid,
        )
        .unwrap();

        let error = authority
            .validate_retained(&journal_authority.residual, &journal_authority.journal)
            .unwrap_err();
        assert_eq!(error.operation, "validate-linux-service-bootstrap-artifact");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
    }

    #[test]
    fn service_bootstrap_rejects_delegation_controller_and_probe_crossing_before_mint() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);

        let mut crossed_delegation = fixture.bootstrap_evidence(&plan);
        crossed_delegation
            .plan_binding
            .journal
            .delegation_identity
            .inode += 1;
        let error = fixture
            .open_bootstrap_authority_with_evidence(crossed_delegation)
            .unwrap_err();
        assert_eq!(error.operation, "bind-linux-service-bootstrap");

        let other_state_root = Fixture::new();
        let error = LinuxNativeServiceBootstrapAuthority::open_test_authenticated(
            other_state_root.parent(),
            fixture.service_journal_binding(fixture.bootstrap_expectation()),
            fixture.bootstrap_service_parent(),
            "delegation",
            fixture.bootstrap_bubblewrap_parent(),
            "bwrap",
            fixture.bootstrap_evidence(&plan),
        )
        .unwrap_err();
        assert_eq!(error.operation, "bind-service-command-journal");
        assert!(error.detail.contains("service-state"));

        let mut crossed_controller = fixture.bootstrap_evidence(&plan);
        crossed_controller.cgroup.subtree_control_readback = "memory\n".into();
        crossed_controller.cgroup.subtree_control_readback_sha256 = Digest::sha256(b"memory\n");
        let error = fixture
            .open_bootstrap_authority_with_evidence(crossed_controller)
            .unwrap_err();
        assert_eq!(error.operation, "validate-linux-service-bootstrap-evidence");
        assert!(error.detail.contains("memory+pids"));

        let mut failed_landlock_probe = fixture.bootstrap_evidence(&plan);
        failed_landlock_probe.landlock.full_enforcement_passed = false;
        let error = fixture
            .open_bootstrap_authority_with_evidence(failed_landlock_probe)
            .unwrap_err();
        assert!(error.detail.contains("Landlock"));

        let mut failed_seccomp_probe = fixture.bootstrap_evidence(&plan);
        failed_seccomp_probe.seccomp.forbidden_syscall_killed = false;
        let error = fixture
            .open_bootstrap_authority_with_evidence(failed_seccomp_probe)
            .unwrap_err();
        assert!(error.detail.contains("seccomp"));

        let mut unsupported = fixture.bootstrap_evidence(&plan);
        unsupported.authority_version += 1;
        let error = fixture
            .open_bootstrap_authority_with_evidence(unsupported)
            .unwrap_err();
        assert!(error.detail.contains("version"));
        assert!(!fixture.path.join(SERVICE_BOOTSTRAP_FINAL_NAME).exists());
        assert!(!fixture.path.join(SERVICE_BOOTSTRAP_TEMP_NAME).exists());
    }

    /// The version-4 binding clause refuses exactly what version 3 admitted,
    /// and admits nothing version 3 refused.
    ///
    /// This is the enforced form of the claim the unfreeze was granted for.
    /// The two probe-result digests used to be checked only by
    /// `digest_is_zero`, so **any** non-zero value bound any plan, and the
    /// value this repository's own fixture carried was a literal
    /// `Digest::sha256(b"test-only-complete-…")`. It is submitted here
    /// unchanged, and it is refused. Every version-3 refusal is then re-driven
    /// on the same evidence, so the new clause is an addition rather than a
    /// replacement.
    #[allow(
        clippy::too_many_lines,
        reason = "the version-3 refusals and the version-4 additions belong in one place, because the claim is about the relationship between them"
    )]
    #[test]
    fn an_invented_kernel_control_probe_result_is_refused_where_version_3_admitted_it() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let evidence = fixture.bootstrap_evidence(&plan);
        validate_service_bootstrap_evidence(&evidence)
            .expect("the unvaried evidence is admissible, so each refusal below is attributable");

        // The two digests the version-3 fixture actually carried. Non-zero, so
        // `digest_is_zero` admitted them, and unrelated to any ruleset or
        // filter, because version 3 had none to be related to.
        let mut invented_landlock = fixture.bootstrap_evidence(&plan);
        invented_landlock.landlock.active_probe_result_digest =
            Digest::sha256(b"test-only-complete-landlock-bootstrap-probe-result");
        assert!(!digest_is_zero(
            &invented_landlock.landlock.active_probe_result_digest
        ));
        let refusal = validate_service_bootstrap_evidence(&invented_landlock)
            .expect_err("an invented Landlock probe result must not bind a committed ruleset");
        assert_eq!(refusal.operation, "validate-linux-service-bootstrap-evidence");
        assert!(
            refusal
                .detail
                .contains("installed the exact ruleset this plan commits"),
            "the refusal is not the version-4 Landlock binding clause: {refusal:?}"
        );

        let mut invented_seccomp = fixture.bootstrap_evidence(&plan);
        invented_seccomp.seccomp.active_probe_result_digest =
            Digest::sha256(b"test-only-complete-seccomp-bootstrap-probe-result");
        assert!(!digest_is_zero(
            &invented_seccomp.seccomp.active_probe_result_digest
        ));
        let refusal = validate_service_bootstrap_evidence(&invented_seccomp)
            .expect_err("an invented seccomp probe result must not bind a committed filter");
        assert!(
            refusal
                .detail
                .contains("installed the exact filter this plan commits"),
            "the refusal is not the version-4 seccomp binding clause: {refusal:?}"
        );

        // A probe result for a real but *different* ruleset: the same evidence
        // with one committed scope identity moved. Version 3 could not express
        // this case at all; version 4 refuses it.
        let mut other_ruleset = fixture.bootstrap_evidence(&plan);
        let LinuxLandlockBootstrapBindingV1::InstalledRulesetProvenByLiveBootstrapProbe {
            ruleset,
            ..
        } = &mut other_ruleset.plan_binding.landlock;
        ruleset.scopes[0].inode += 1;
        ruleset.ruleset_sha256 = ruleset.canonical_digest();
        let refusal = validate_service_bootstrap_evidence(&other_ruleset)
            .expect_err("a probe result minted for another ruleset must not bind this plan");
        assert!(
            refusal
                .detail
                .contains("installed the exact ruleset this plan commits"),
            "the refusal is not the version-4 Landlock binding clause: {refusal:?}"
        );

        // A committed artefact whose own digest is stale is refused before the
        // probe result is even consulted.
        let mut stale_digest = fixture.bootstrap_evidence(&plan);
        let LinuxLandlockBootstrapBindingV1::InstalledRulesetProvenByLiveBootstrapProbe {
            ruleset,
            ..
        } = &mut stale_digest.plan_binding.landlock;
        ruleset.handled_access_bits += 1;
        let refusal = validate_service_bootstrap_evidence(&stale_digest)
            .expect_err("a ruleset digest that is not the ruleset's own must be refused");
        assert!(
            refusal
                .detail
                .contains("not the digest of the ruleset beside it"),
            "the refusal is not the ruleset self-consistency clause: {refusal:?}"
        );

        // Every version-3 refusal, re-driven unchanged on version-4 evidence.
        // None of them became admissible.
        for (label, mutate) in [
            (
                "an all-zero Landlock probe result",
                Box::new(|evidence: &mut LinuxNativeServiceBootstrapEvidenceV1| {
                    evidence.landlock.active_probe_result_digest = Digest::parse("0".repeat(64)).expect("the zero digest is canonical");
                }) as Box<dyn Fn(&mut LinuxNativeServiceBootstrapEvidenceV1)>,
            ),
            (
                "a Landlock ABI below the committed window",
                Box::new(|evidence: &mut LinuxNativeServiceBootstrapEvidenceV1| {
                    evidence.landlock.observed_kernel_abi = 1;
                }),
            ),
            (
                "a Landlock ABI above the committed window",
                Box::new(|evidence: &mut LinuxNativeServiceBootstrapEvidenceV1| {
                    evidence.landlock.observed_kernel_abi = 99;
                }),
            ),
            (
                "a Landlock ruleset that was not fully enforced",
                Box::new(|evidence: &mut LinuxNativeServiceBootstrapEvidenceV1| {
                    evidence.landlock.full_enforcement_passed = false;
                }),
            ),
            (
                "an all-zero seccomp probe result",
                Box::new(|evidence: &mut LinuxNativeServiceBootstrapEvidenceV1| {
                    evidence.seccomp.active_probe_result_digest = Digest::parse("0".repeat(64)).expect("the zero digest is canonical");
                }),
            ),
            (
                "a seccomp probe that did not read back no-new-privileges",
                Box::new(|evidence: &mut LinuxNativeServiceBootstrapEvidenceV1| {
                    evidence.seccomp.no_new_privileges_read_back = false;
                }),
            ),
            (
                "a seccomp probe whose child survived",
                Box::new(|evidence: &mut LinuxNativeServiceBootstrapEvidenceV1| {
                    evidence.seccomp.forbidden_syscall_killed = false;
                }),
            ),
        ] {
            let mut varied = fixture.bootstrap_evidence(&plan);
            mutate(&mut varied);
            assert!(
                validate_service_bootstrap_evidence(&varied).is_err(),
                "{label} was admitted by the version-4 validator"
            );
        }
    }
