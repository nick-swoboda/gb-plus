    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use cap_std::{ambient_authority, fs::OpenOptions as CapOpenOptions};
    use grok_build_core::{CONTRACT_VERSION, Digest};

    use crate::linux_command_plan::{
        LinuxServiceChildDescriptorLifecycleV1, LinuxServiceLaunchImageUseV1,
        LinuxServiceTargetLoaderClosureV1,
    };
    #[cfg(target_os = "linux")]
    use crate::linux_command_plan::{LinuxMachineArchitectureV1, ValidatedLinuxProductionCommandPlanV1};
    use crate::linux_containment::{ReadBackDomainLimits, RequestedDomainLimits};
    use crate::linux_held_launcher::{HeldExecObservation, HeldExecReleaseBinding};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);
    static NEXT_SETUP_ENDPOINT: AtomicU64 = AtomicU64::new(1);

    const TEST_SETUP_REQUEST_BYTES: &[u8; 64] =
        b"grok-build-test-setup-request-v1...............................\n";

    #[cfg(target_os = "linux")]
    fn create_test_setup_request(_fixture_path: &Path) -> File {
        let descriptor = rustix::fs::memfd_create(
            "grok-build-test-setup-request-v1",
            rustix::fs::MemfdFlags::CLOEXEC
                | rustix::fs::MemfdFlags::ALLOW_SEALING
                | rustix::fs::MemfdFlags::EXEC,
        )
        .unwrap();
        let mut file = std::fs::File::from(descriptor);
        file.write_all(TEST_SETUP_REQUEST_BYTES).unwrap();
        file.flush().unwrap();
        rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(0o500)).unwrap();
        let seals = rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::FUTURE_WRITE
            | rustix::fs::SealFlags::EXEC;
        rustix::fs::fcntl_add_seals(&file, seals).unwrap();
        File::from_std(file)
    }

    #[cfg(not(target_os = "linux"))]
    fn create_test_setup_request(fixture_path: &Path) -> File {
        let path = fixture_path.join("portable-test-setup-request");
        fs::write(&path, TEST_SETUP_REQUEST_BYTES).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        fs::remove_file(path).unwrap();
        File::from_std(file)
    }

    fn setup_directory_binding(
        object_id: &str,
        directory: &Dir,
    ) -> LinuxServiceSetupObjectIdentityV1 {
        let metadata = directory.dir_metadata().unwrap();
        LinuxServiceSetupObjectIdentityV1 {
            object_id: object_id.into(),
            kind: crate::linux_command_plan::LinuxRetainedObjectKindV1::Directory,
            device_id: PortableMetadataExt::dev(&metadata),
            inode: PortableMetadataExt::ino(&metadata),
            mount_id: retained_directory_mount_id(directory, "test-setup-directory-mount").unwrap(),
            mode: OsMetadataExt::mode(&metadata),
            owner_uid: OsMetadataExt::uid(&metadata),
            owner_gid: OsMetadataExt::gid(&metadata),
            link_count: PortableMetadataExt::nlink(&metadata),
            byte_length: None,
        }
    }

    fn setup_request_binding(file: &File) -> LinuxServiceSetupObjectIdentityV1 {
        let metadata = file.metadata().unwrap();
        LinuxServiceSetupObjectIdentityV1 {
            object_id: "setup".into(),
            kind: crate::linux_command_plan::LinuxRetainedObjectKindV1::SealedMemfd,
            device_id: PortableMetadataExt::dev(&metadata),
            inode: PortableMetadataExt::ino(&metadata),
            mount_id: retained_file_mount_id(file, "test-setup-request-mount").unwrap(),
            mode: OsMetadataExt::mode(&metadata),
            owner_uid: OsMetadataExt::uid(&metadata),
            owner_gid: OsMetadataExt::gid(&metadata),
            link_count: PortableMetadataExt::nlink(&metadata),
            byte_length: Some(metadata.len()),
        }
    }

    fn test_pipe_endpoint(
        fixture_path: &Path,
        access: LinuxServiceSetupDescriptorAccessV1,
    ) -> File {
        use std::os::unix::fs::OpenOptionsExt as _;

        let sequence = NEXT_SETUP_ENDPOINT.fetch_add(1, Ordering::Relaxed);
        let path = fixture_path.join(format!("test-setup-endpoint-{sequence}"));
        let status = Command::new("/usr/bin/mkfifo")
            .arg(&path)
            .status()
            .expect("create test-only setup FIFO");
        assert!(status.success(), "create test-only setup FIFO");
        let nonblocking = i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).unwrap();
        let selected = match access {
            LinuxServiceSetupDescriptorAccessV1::ReadOnly => std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nonblocking)
                .open(&path)
                .unwrap(),
            LinuxServiceSetupDescriptorAccessV1::WriteOnly => {
                let reader = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nonblocking)
                    .open(&path)
                    .unwrap();
                let writer = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(nonblocking)
                    .open(&path)
                    .unwrap();
                drop(reader);
                writer
            }
            LinuxServiceSetupDescriptorAccessV1::ReadWrite => {
                panic!("test pipe endpoints never require read-write access")
            }
        };
        fs::remove_file(path).unwrap();
        File::from_std(selected)
    }

    fn retained_file_offset(file: &File) -> u64 {
        let mut observation = file.try_clone().unwrap();
        observation
            .stream_position()
            .expect("observe retained file offset")
    }

    #[cfg(target_os = "linux")]
    struct BindMountGuard(Option<PathBuf>);

    #[cfg(target_os = "linux")]
    impl BindMountGuard {
        fn unmount(mut self) {
            let target = self.0.take().expect("bind mount guard is active");
            let status = Command::new("umount")
                .arg(&target)
                .status()
                .expect("run umount for bind-alias fixture");
            assert!(status.success(), "unmount bind-alias fixture");
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for BindMountGuard {
        fn drop(&mut self) {
            if let Some(target) = self.0.take() {
                let _ = Command::new("umount").arg(target).status();
            }
        }
    }

    pub(crate) struct Fixture {
        path: PathBuf,
        journal_name: String,
        expected_uid: u32,
        setup_request: File,
        /// Where the service parent cgroup lives.
        ///
        /// Normally this fixture's own simulated `service-cgroup` directory,
        /// whose control files are ordinary files. A live run overrides it with
        /// a **real** delegated subtree, so the service-mechanics chain can be
        /// composed against the cgroup a command would actually run in rather
        /// than against a temp-directory imitation of one.
        service_cgroup: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("gb-cgroup-journal-{}-{unique}", std::process::id()));
            fs::create_dir(&path).unwrap();
            let path = fs::canonicalize(path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            let journal_name = SERVICE_COMMAND_JOURNAL_DIRECTORY.to_owned();
            let journal_path = path.join(&journal_name);
            fs::create_dir(&journal_path).unwrap();
            fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700)).unwrap();
            let service_parent = path.join("service-cgroup");
            let delegation = service_parent.join("delegation");
            fs::create_dir(&service_parent).unwrap();
            fs::set_permissions(&service_parent, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(&delegation).unwrap();
            fs::set_permissions(&delegation, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(delegation.join("cgroup.controllers"), b"cpu memory pids\n").unwrap();
            fs::write(delegation.join("cgroup.subtree_control"), b"memory pids\n").unwrap();
            fs::write(delegation.join("cgroup.procs"), b"").unwrap();
            for name in [
                "cgroup.controllers",
                "cgroup.subtree_control",
                "cgroup.procs",
            ] {
                fs::set_permissions(delegation.join(name), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            let tool_root = path.join("authenticated-tools");
            fs::create_dir(&tool_root).unwrap();
            fs::set_permissions(&tool_root, fs::Permissions::from_mode(0o700)).unwrap();
            for (name, bytes) in [
                (
                    "native-service",
                    b"test-only-native-service-image-v1\n".as_slice(),
                ),
                ("bwrap", b"test-only-bubblewrap-image-v1\n".as_slice()),
                (
                    "inner-launcher",
                    b"test-only-inner-launcher-image-v1\n".as_slice(),
                ),
                ("target", b"test-only-target-image-v1\n".as_slice()),
                (
                    "ld-linux-x86-64.so.2",
                    b"test-only-elf-interpreter-image-v1\n".as_slice(),
                ),
                ("libc.so.6", b"test-only-runtime-libc-image-v1\n".as_slice()),
            ] {
                fs::write(tool_root.join(name), bytes).unwrap();
                fs::set_permissions(tool_root.join(name), fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            for relative in ["workspace/fixture", "execution/fixture", "git-mask"] {
                let directory = path.join(relative);
                fs::create_dir_all(&directory).unwrap();
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let setup_request = create_test_setup_request(&path);
            Self {
                service_cgroup: path.join("service-cgroup"),
                path,
                journal_name,
                expected_uid: rustix::process::geteuid().as_raw(),
                setup_request,
            }
        }

        fn parent(&self) -> Dir {
            Dir::open_ambient_dir(&self.path, ambient_authority()).unwrap()
        }

        fn setup_directory(&self, object_id: &str) -> Dir {
            match object_id {
                "workspace" => {
                    Dir::open_ambient_dir(self.path.join("workspace"), ambient_authority()).unwrap()
                }
                "execution" => {
                    Dir::open_ambient_dir(self.path.join("execution"), ambient_authority()).unwrap()
                }
                "git-mask" => {
                    Dir::open_ambient_dir(self.path.join("git-mask"), ambient_authority()).unwrap()
                }
                "private-state" => self.parent(),
                "journal-index" => self
                    .parent()
                    .open_dir_nofollow(SERVICE_COMMAND_JOURNAL_DIRECTORY)
                    .unwrap(),
                other => panic!("no test setup directory for object {other}"),
            }
        }

        fn open_store(&self) -> CanonicalCgroupJournalStore {
            CanonicalCgroupJournalStore::open_test_retained(
                self.parent(),
                &self.journal_name,
                self.expected_uid,
            )
            .unwrap()
        }

        fn service_journal_binding(
            &self,
            delegation: DelegationRootExpectation,
        ) -> LinuxServiceCommandJournalBinding {
            let parent = self.parent();
            let state_identity = cgroup_identity(object_identity(
                &parent.dir_metadata().expect("inspect service-state root"),
            ));
            let journal = parent
                .open_dir_nofollow(SERVICE_COMMAND_JOURNAL_DIRECTORY)
                .expect("open singleton journal root");
            let journal_identity = cgroup_identity(object_identity(
                &journal
                    .dir_metadata()
                    .expect("inspect singleton journal root"),
            ));
            LinuxServiceCommandJournalBinding {
                authority_version: SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION,
                authenticated_platform_service_digest: self
                    .executable_file_binding("native-service")
                    .content_sha256,
                service_state_root_identity: state_identity,
                singleton_journal_root_identity: journal_identity,
                delegation,
            }
        }

        fn open_service_journal_authority(
            &self,
            delegation: DelegationRootExpectation,
        ) -> LinuxServiceCommandJournalAuthority {
            LinuxServiceCommandJournalAuthority::open_test_service_singleton(
                self.parent(),
                self.service_journal_binding(delegation),
            )
            .expect("open test-only service singleton authority")
        }

        fn command_plan_binding(
            &self,
            delegation: DelegationRootExpectation,
        ) -> LinuxProductionCommandPlanJournalBindingV1 {
            let binding = self.service_journal_binding(delegation);
            LinuxProductionCommandPlanJournalBindingV1 {
                authenticated_platform_service_digest: binding
                    .authenticated_platform_service_digest
                    .clone(),
                service_state_root_identity: binding.service_state_root_identity,
                singleton_journal_root_identity: binding.singleton_journal_root_identity,
                service_parent_identity: binding.delegation.service_parent_identity,
                delegation_identity: binding.delegation.delegation_identity,
                owner_uid: binding.delegation.owner_uid,
                delegation_mode: binding.delegation.delegation_mode,
            }
        }

        fn command_plan(
            &self,
            role: crate::wire::RunnerRole,
            delegation: DelegationRootExpectation,
        ) -> ValidatedLinuxProductionCommandPlanV1 {
            let mut plan = crate::linux_command_plan::tests::fixture_at_workspace(
                role,
                &self.path.join("workspace"),
            )
            .rebind_test_service_journal(&self.command_plan_binding(delegation))
            .expect("rebind complete test command plan to service journal");
            for object_id in [
                "workspace",
                "execution",
                "git-mask",
                "private-state",
                "journal-index",
            ] {
                let binding = setup_directory_binding(object_id, &self.setup_directory(object_id));
                plan = plan
                    .rebind_test_setup_object(&binding, None)
                    .expect("rebind test plan setup directory");
            }
            let setup_binding = setup_request_binding(&self.setup_request);
            plan.rebind_test_setup_object(
                &setup_binding,
                Some(&Digest::sha256(TEST_SETUP_REQUEST_BYTES)),
            )
            .expect("rebind test plan setup request")
        }

        fn bootstrap_service_parent(&self) -> Dir {
            Dir::open_ambient_dir(&self.service_cgroup, ambient_authority()).unwrap()
        }

        /// Repoints this fixture's service parent at a **real** delegated
        /// cgroup subtree, leaving every other part of the harness alone.
        ///
        /// Only the delegation identities change: the plan, the images, the
        /// setup descriptors and the child-launch closure never touch a cgroup,
        /// which is why this is the whole of what a live composition needs.
        #[cfg(target_os = "linux")]
        pub(crate) fn with_live_service_cgroup(mut self, service_parent: &std::path::Path) -> Self {
            self.service_cgroup = service_parent.to_path_buf();
            self
        }

        fn bootstrap_bubblewrap_parent(&self) -> Dir {
            self.parent()
                .open_dir_nofollow("authenticated-tools")
                .unwrap()
        }

        fn bootstrap_expectation(&self) -> DelegationRootExpectation {
            let parent = self.bootstrap_service_parent();
            let delegation = parent.open_dir_nofollow("delegation").unwrap();
            let delegation_metadata = delegation.dir_metadata().unwrap();
            DelegationRootExpectation {
                service_parent_identity: cgroup_identity(object_identity(
                    &parent.dir_metadata().unwrap(),
                )),
                delegation_identity: cgroup_identity(object_identity(&delegation_metadata)),
                owner_uid: self.expected_uid,
                // Read, not asserted. Every other field here comes from the
                // directory itself; the mode was the one that was written in as
                // a constant, which happened to be true of this fixture's own
                // simulated tree (`new` creates it `0o700`) and false of a real
                // delegated subtree. `validate-bootstrap-delegation` compares
                // this against the live mode, so a constant here is a
                // expectation that describes something other than what exists.
                delegation_mode: OsMetadataExt::mode(&delegation_metadata) & 0o7777,
            }
        }

        fn executable_file_binding(&self, name: &str) -> LinuxBootstrapFileIdentityV1 {
            let parent = self.bootstrap_bubblewrap_parent();
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            let file = parent.open_with(name, &options).unwrap();
            let metadata = file.metadata().unwrap();
            let bytes = read_retained_bootstrap_file(
                &file,
                MAX_BOOTSTRAP_READBACK_BYTES,
                "read-test-executable",
            )
            .unwrap();
            LinuxBootstrapFileIdentityV1 {
                device_id: PortableMetadataExt::dev(&metadata),
                inode: PortableMetadataExt::ino(&metadata),
                mount_id: retained_file_mount_id(&file, "read-test-executable-mount").unwrap(),
                mode: OsMetadataExt::mode(&metadata),
                owner_uid: OsMetadataExt::uid(&metadata),
                owner_gid: OsMetadataExt::gid(&metadata),
                link_count: PortableMetadataExt::nlink(&metadata),
                byte_length: metadata.len(),
                content_sha256: Digest::sha256(&bytes),
            }
        }

        fn bootstrap_plan(
            &self,
            role: crate::wire::RunnerRole,
        ) -> ValidatedLinuxProductionCommandPlanV1 {
            let expectation = self.bootstrap_expectation();
            let mut plan = self.command_plan(role, expectation);
            for (object_id, name) in [
                ("bwrap", "bwrap"),
                ("inner", "inner-launcher"),
                ("target", "target"),
                ("interpreter", "ld-linux-x86-64.so.2"),
                ("runtime-libc", "libc.so.6"),
            ] {
                let resolved_path = self
                    .path
                    .join("authenticated-tools")
                    .join(name)
                    .to_str()
                    .expect("test executable path is UTF-8")
                    .to_owned();
                plan = plan
                    .rebind_test_executable_file(
                        object_id,
                        &resolved_path,
                        &self.executable_file_binding(name),
                    )
                    .expect("rebind complete test plan to retained executable descriptor");
            }
            plan
        }

        fn service_process_image(&self) -> LinuxNativeServiceProcessImageAuthority {
            let path = self.path.join("authenticated-tools/native-service");
            LinuxNativeServiceProcessImageAuthority::open_test_absolute(
                path.to_str().expect("test service image path is UTF-8"),
            )
            .expect("open retained test native-service process image")
        }

        fn pending_authenticated_handoff(
            &self,
            expected: &LinuxProductionCommandPlanJournalBindingV1,
        ) -> PendingLinuxNativeServiceAuthenticatedHandoff {
            PendingLinuxNativeServiceAuthenticatedHandoff::from_test_descriptors(
                self.service_process_image(),
                self.parent(),
                self.bootstrap_service_parent(),
                "delegation",
                LinuxNativeServiceHandoffCommitmentV1 {
                    installer_uid: 0,
                    journal: expected.clone(),
                },
            )
        }

        fn open_test_authenticated_handoff_journal(
            &self,
            plan: &ValidatedLinuxProductionCommandPlanV1,
        ) -> Result<LinuxServiceCommandJournalAuthority, CgroupIoFailure> {
            let expected = plan.journal_binding().unwrap();
            let (capability, host_roots) = self
                .pending_authenticated_handoff(&expected)
                .into_state_root_capability(&expected)?;
            let parent_metadata = host_roots.service_parent.dir_metadata().unwrap();
            assert_eq!(
                cgroup_identity(object_identity(&parent_metadata)),
                expected.service_parent_identity
            );
            assert_eq!(host_roots.delegation_name, "delegation");
            LinuxServiceCommandJournalAuthority::open_authenticated_service_singleton(
                capability,
                service_journal_binding_from_plan(&expected),
            )
        }

        fn admit(
            &self,
            bootstrapped: BootstrappedLinuxProductionCommandPlanV1,
        ) -> LinuxNativeServiceAdmissionAuthority {
            admit_linux_native_service_command(bootstrapped, self.service_process_image())
                .expect("admit exact retained Linux native-service command")
        }

        fn select_launch_images(
            admission: LinuxNativeServiceAdmissionAuthority,
        ) -> LinuxNativeServiceLaunchImageAuthority {
            select_linux_native_service_launch_images(admission)
                .expect("select exact immutable Linux launch-image closure")
        }

        fn launch_image_authority(
            &self,
            role: crate::wire::RunnerRole,
        ) -> (
            ValidatedLinuxProductionCommandPlanV1,
            LinuxNativeServiceLaunchImageAuthority,
        ) {
            let expectation = self.bootstrap_expectation();
            let plan = self.bootstrap_plan(role);
            let journaled = journal_linux_production_command_plan(
                plan.clone(),
                self.open_service_journal_authority(expectation),
            )
            .unwrap();
            let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
                journaled,
                self.open_bootstrap_authority(&plan),
            )
            .unwrap();
            let authority = Self::select_launch_images(self.admit(bootstrapped));
            (plan, authority)
        }

        fn setup_descriptor_inputs(
            &self,
            plan: &ValidatedLinuxProductionCommandPlanV1,
        ) -> LinuxTestNativeServiceSetupDescriptorInputs {
            let binding = plan.service_setup_descriptor_binding().unwrap();
            let read_only_mount_sources = binding
                .read_only_mount_sources
                .iter()
                .map(|source| self.setup_directory(&source.object.object_id))
                .collect();
            let endpoints = binding
                .endpoints
                .iter()
                .map(|endpoint| {
                    let file = if endpoint.role == LinuxServiceSetupEndpointRoleV1::SetupRequest {
                        self.setup_request.try_clone().unwrap()
                    } else {
                        test_pipe_endpoint(&self.path, endpoint.access)
                    };
                    (endpoint.role, file)
                })
                .collect();
            LinuxTestNativeServiceSetupDescriptorInputs {
                execution_root: self.setup_directory(&binding.cwd.execution_root.object_id),
                private_state_root: self.setup_directory(&binding.private_state_root.object_id),
                singleton_journal_root: self
                    .setup_directory(&binding.singleton_journal_root.object_id),
                read_only_mount_sources,
                endpoints,
            }
        }

        fn setup_descriptor_capability(
            &self,
            plan: &ValidatedLinuxProductionCommandPlanV1,
        ) -> LinuxNativeServiceSetupDescriptorCapability {
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(
                plan,
                self.setup_descriptor_inputs(plan),
            )
            .expect("mint exact test-only native-service setup descriptor capability")
        }

        fn bind_setup_descriptors(
            &self,
            plan: &ValidatedLinuxProductionCommandPlanV1,
            launch_images: LinuxNativeServiceLaunchImageAuthority,
        ) -> LinuxNativeServiceSetupDescriptorAuthority {
            bind_linux_native_service_setup_descriptors(
                launch_images,
                self.setup_descriptor_capability(plan),
            )
            .expect("bind exact setup descriptor closure")
        }

        fn setup_descriptor_authority(
            &self,
            role: crate::wire::RunnerRole,
        ) -> (
            ValidatedLinuxProductionCommandPlanV1,
            LinuxNativeServiceSetupDescriptorAuthority,
        ) {
            let (plan, launch_images) = self.launch_image_authority(role);
            let authority = self.bind_setup_descriptors(&plan, launch_images);
            (plan, authority)
        }

        fn child_launch_closure_capability(
            setup: &LinuxNativeServiceSetupDescriptorAuthority,
        ) -> LinuxNativeServiceChildLaunchClosureCapability {
            LinuxNativeServiceChildLaunchClosureCapability::open_test_authenticated(setup)
                .expect("mint exact test-only child descriptor-table and loader closure")
        }

        fn bind_child_launch_closure(
            setup: LinuxNativeServiceSetupDescriptorAuthority,
        ) -> LinuxNativeServiceChildLaunchClosureAuthority {
            let capability = Self::child_launch_closure_capability(&setup);
            bind_linux_native_service_child_launch_closure(setup, capability)
                .expect("bind exact child descriptor-table and loader closure")
        }

        fn child_launch_closure_authority(
            &self,
            role: crate::wire::RunnerRole,
        ) -> (
            ValidatedLinuxProductionCommandPlanV1,
            LinuxNativeServiceChildLaunchClosureAuthority,
        ) {
            let (plan, setup) = self.setup_descriptor_authority(role);
            let authority = Self::bind_child_launch_closure(setup);
            (plan, authority)
        }

        fn bootstrap_evidence(
            &self,
            plan: &ValidatedLinuxProductionCommandPlanV1,
        ) -> LinuxNativeServiceBootstrapEvidenceV1 {
            let plan_binding = plan.service_bootstrap_binding().unwrap();
            let delegation = self
                .bootstrap_service_parent()
                .open_dir_nofollow("delegation")
                .unwrap();
            let control_identity = |name: &str| {
                let mut options = OpenOptions::new();
                options.read(true).follow(FollowSymlinks::No);
                let file = delegation.open_with(name, &options).unwrap();
                cgroup_identity(object_identity(&file.metadata().unwrap()))
            };
            // Read, not asserted, for the same reason the delegation mode is.
            // These were constants describing this fixture's own simulated
            // control files, which `new` writes with exactly these bytes. A
            // real delegated subtree reports whatever the kernel and the
            // parent's delegation actually produced, and
            // `validate-bootstrap-cgroup-controllers` compares the evidence
            // against a live readback -- so a constant here is evidence about a
            // different cgroup than the one being validated.
            let read_control = |name: &str| {
                let mut options = OpenOptions::new();
                options.read(true).follow(FollowSymlinks::No);
                let mut file = delegation.open_with(name, &options).unwrap();
                let mut contents = String::new();
                std::io::Read::read_to_string(&mut file, &mut contents).unwrap();
                contents
            };
            let controllers_readback = read_control("cgroup.controllers");
            let subtree_control_readback = read_control("cgroup.subtree_control");
            let cgroup_procs_readback = read_control("cgroup.procs");
            // The image's own `--version` line, which is a different fact from
            // the plan's package version and is pinned separately in the
            // admission. Deriving it from `plan_binding.bubblewrap.version`
            // here is what made both operands of the validator's version clause
            // one invented value.
            let version_stdout = format!(
                "{}\n",
                crate::linux_command_plan::ADMITTED_BUBBLEWRAP_IMAGE_V1.self_reported_version
            );
            let LinuxLandlockBootstrapBindingV1::InstalledRulesetProvenByLiveBootstrapProbe {
                minimum_kernel_abi,
                ref ruleset,
                ..
            } = plan_binding.landlock;
            let landlock_ruleset = ruleset;
            // The lowest ABI the plan's own window admits, so the fixture
            // measures the window rather than assuming a host.
            let landlock_observed_abi = minimum_kernel_abi;
            let LinuxSeccompBootstrapBindingV1::CompiledFilterProvenByLiveBootstrapProbe {
                filter: ref seccomp_filter,
                ..
            } = plan_binding.seccomp;
            LinuxNativeServiceBootstrapEvidenceV1 {
                authority_version: SERVICE_BOOTSTRAP_AUTHORITY_VERSION,
                plan_binding: plan_binding.clone(),
                cgroup: LinuxCgroupBootstrapReadbackV1 {
                    delegation_component: "delegation".into(),
                    controllers_file_identity: control_identity("cgroup.controllers"),
                    subtree_control_file_identity: control_identity("cgroup.subtree_control"),
                    cgroup_procs_file_identity: control_identity("cgroup.procs"),
                    controllers_readback_sha256: Digest::sha256(controllers_readback.as_bytes()),
                    controllers_readback,
                    subtree_control_readback_sha256: Digest::sha256(
                        subtree_control_readback.as_bytes(),
                    ),
                    subtree_control_readback,
                    cgroup_procs_readback_sha256: Digest::sha256(cgroup_procs_readback.as_bytes()),
                    cgroup_procs_readback,
                    active_probe_contract_digest: Digest::sha256(CGROUP_BOOTSTRAP_PROBE_CONTRACT),
                    active_probe_result_digest: Digest::sha256(
                        b"test-only-complete-cgroup-bootstrap-probe-result",
                    ),
                    active_probe_passed: true,
                },
                bubblewrap: LinuxBubblewrapBootstrapProbeV1 {
                    version_stdout_sha256: Digest::sha256(version_stdout.as_bytes()),
                    version_stdout,
                    active_probe_contract_digest: Digest::sha256(
                        BUBBLEWRAP_BOOTSTRAP_PROBE_CONTRACT,
                    ),
                    active_probe_result_digest: Digest::sha256(
                        b"test-only-complete-bubblewrap-bootstrap-probe-result",
                    ),
                    active_probe_passed: true,
                },
                landlock: LinuxLandlockBootstrapProbeV1 {
                    observed_kernel_abi: landlock_observed_abi,
                    // Not an invented value any more, and it could not be: with
                    // plan schema version 4 the validator requires this to be
                    // the digest a probe that installed *this plan's* ruleset
                    // produces, so the fixture computes it the way the probe
                    // controller does. The version-3 fixture carried
                    // `Digest::sha256(b"test-only-complete-…")`, which the
                    // version-3 validator admitted and this one refuses —
                    // `an_invented_kernel_control_probe_result_is_refused`
                    // is that refusal.
                    active_probe_result_digest: landlock_bootstrap_probe_result_digest(
                        landlock_ruleset,
                        landlock_observed_abi,
                    ),
                    full_enforcement_passed: true,
                },
                seccomp: LinuxSeccompBootstrapProbeV1 {
                    active_probe_result_digest: seccomp_bootstrap_probe_result_digest(
                        seccomp_filter,
                    ),
                    no_new_privileges_read_back: true,
                    forbidden_syscall_killed: true,
                },
            }
        }

        fn open_bootstrap_authority(
            &self,
            plan: &ValidatedLinuxProductionCommandPlanV1,
        ) -> LinuxNativeServiceBootstrapAuthority {
            self.open_bootstrap_authority_with_evidence(self.bootstrap_evidence(plan))
                .expect("open test-only retained Linux service bootstrap authority")
        }

        fn open_bootstrap_authority_with_evidence(
            &self,
            evidence: LinuxNativeServiceBootstrapEvidenceV1,
        ) -> Result<LinuxNativeServiceBootstrapAuthority, CgroupIoFailure> {
            self.open_bootstrap_authority_and_journal(evidence)
                .map(|(authority, _)| authority)
        }

        /// The tuple form, for the tests that must keep the journal store live
        /// so the bootstrap authority can be revalidated against it.
        fn open_bootstrap_authority_and_journal(
            &self,
            evidence: LinuxNativeServiceBootstrapEvidenceV1,
        ) -> Result<
            (
                LinuxNativeServiceBootstrapAuthority,
                LinuxServiceCommandJournalAuthority,
            ),
            CgroupIoFailure,
        > {
            let expectation = self.bootstrap_expectation();
            LinuxNativeServiceBootstrapAuthority::open_test_authenticated(
                self.parent(),
                self.service_journal_binding(expectation),
                self.bootstrap_service_parent(),
                "delegation",
                self.bootstrap_bubblewrap_parent(),
                "bwrap",
                evidence,
            )
        }

        fn journal_path(&self) -> PathBuf {
            self.path.join(&self.journal_name)
        }

        fn probe_journal_path(&self) -> PathBuf {
            self.journal_path().join(PROBE_JOURNAL_DIRECTORY)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn replace_authenticated_tool_parent_with_exact_bytes(fixture: &Fixture, marker: &str) {
        let live = fixture.path.join("authenticated-tools");
        let displaced = fixture
            .path
            .join(format!("displaced-authenticated-tools-{marker}"));
        fs::rename(&live, &displaced).unwrap();
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        for entry in fs::read_dir(&displaced).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let destination = live.join(entry.file_name());
                fs::write(&destination, fs::read(entry.path()).unwrap()).unwrap();
                fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
    }

    fn replace_command_plan_artifact_with_exact_bytes(
        fixture: &Fixture,
        plan: &ValidatedLinuxProductionCommandPlanV1,
    ) -> ObjectIdentity {
        let name = command_plan_name(plan.plan_digest());
        let artifact = fixture.journal_path().join(&name);
        let exact_bytes = fs::read(&artifact).expect("read exact command-plan artifact");
        fs::rename(
            &artifact,
            fixture.path.join("displaced-command-plan-artifact"),
        )
        .expect("displace retained command-plan inode");
        let journal = fixture
            .parent()
            .open_dir_nofollow(SERVICE_COMMAND_JOURNAL_DIRECTORY)
            .expect("open retained singleton journal");
        write_new_private_file(&journal, &name, &exact_bytes, fixture.expected_uid)
            .expect("publish digest-equivalent replacement command-plan inode")
    }

    fn create_intent() -> DomainJournalRecord {
        let grant_hash = Digest::sha256(b"journal-test-grant");
        let policy_hash = Digest::sha256(b"journal-test-policy");
        DomainJournalRecord {
            state: DomainJournalState::CreateIntended,
            native_launch: crate::linux_containment::LinuxNativeLaunchIdentity {
                contract_version: CONTRACT_VERSION,
                attempt_id: "attempt-1".into(),
                native_journal_id: "native-journal-1".into(),
                expected_platform_binding_digest: Digest::sha256(b"journal-test-binding"),
                sprint_id: "sprint-1".into(),
                launch_id: "launch-1".into(),
                session_id: "session-1".into(),
                cleanup_effect_id: "cleanup-effect-1".into(),
                input_snapshot: Digest::sha256(b"journal-test-input-snapshot"),
                grant_hash: grant_hash.clone(),
                policy_hash: policy_hash.clone(),
                claimed_at_unix_ms: 10,
            },
            runner_session_id: "session-1".into(),
            effect_id: "effect-1".into(),
            grant_hash: grant_hash.to_string(),
            policy_hash: policy_hash.to_string(),
            command_hash: "command-hash".into(),
            request_digest: "d".repeat(64),
            leaf_name: format!("gb-{}", "a".repeat(64)),
            expected_delegation_identity: CgroupObjectIdentity {
                device: 7,
                inode: 11,
            },
            expected_owner_uid: rustix::process::geteuid().as_raw(),
            leaf_identity: None,
            requested_limits: RequestedDomainLimits::derive(4, Some(1_048_576)).unwrap(),
            read_back_limits: None,
            staged_launcher: None,
            release_authorization: None,
            release_binding: None,
            release_intent_recorded: false,
            release_observation: None,
            cleanup_observations: Vec::new(),
            kill_value: None,
        }
    }

    fn configuring(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::Configuring;
        record.leaf_identity = Some(CgroupObjectIdentity {
            device: 7,
            inode: 12,
        });
        record
    }

    fn prepared(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::Prepared;
        record.read_back_limits = Some(ReadBackDomainLimits {
            pids_max: record.requested_limits.pids_max,
            memory_max: record.requested_limits.memory_max,
            memory_swap_max: record.requested_limits.memory_swap_max,
            memory_oom_group: true,
        });
        record
    }

    fn attach_intended(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::AttachIntended;
        record.staged_launcher = Some(StagedLauncherIdentity {
            pid: 42,
            process_start_time_ticks: 99,
            launch_request_hash: record
                .native_launch
                .expected_platform_binding_digest
                .to_string(),
            held_before_exec: true,
        });
        record
    }

    fn attached(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::Attached;
        record
    }

    fn held(mut record: DomainJournalRecord) -> DomainJournalRecord {
        let release_authorization =
            crate::linux_containment::LinuxHeldChildReleaseAuthorization::test_for_record(&record)
                .into_record();
        record.state = DomainJournalState::Held;
        record.release_authorization = Some(release_authorization);
        record.release_binding = Some(HeldExecReleaseBinding::inert_test_fixture());
        record
    }

    fn release_intended(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::ReleaseIntended;
        record.release_intent_recorded = true;
        record
    }

    fn released(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::Released;
        let launcher = record.staged_launcher.as_ref().unwrap();
        let binding = record.release_binding.as_ref().unwrap();
        record.release_observation = Some(HeldExecObservation {
            pid: launcher.pid,
            process_start_time_ticks: launcher.process_start_time_ticks,
            release_spec_hash: binding.release_spec_hash().to_owned(),
            executable_identity: binding.executable_identity(),
            same_pid_exec_observed: true,
            cgroup_membership_revalidated: true,
            target_continued: true,
        });
        record
    }

    fn killing(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::Killing;
        record
    }

    fn empty_proven(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::EmptyProven;
        record.kill_value = Some(b"1\n".to_vec());
        record.cleanup_observations = vec![
            crate::linux_containment::RawCleanupObservation {
                sequence: 1,
                attempt: 1,
                file: LeafFile::CgroupEvents,
                bytes: b"populated 0\nfrozen 0\n".to_vec(),
            },
            crate::linux_containment::RawCleanupObservation {
                sequence: 2,
                attempt: 1,
                file: LeafFile::CgroupProcs,
                bytes: Vec::new(),
            },
            crate::linux_containment::RawCleanupObservation {
                sequence: 3,
                attempt: 1,
                file: LeafFile::CgroupProcs,
                bytes: Vec::new(),
            },
        ];
        record
    }

    fn remove_intended(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::RemoveIntended;
        record
    }

    fn removed(mut record: DomainJournalRecord) -> DomainJournalRecord {
        record.state = DomainJournalState::Removed;
        record
    }

    fn request_for_record(record: &DomainJournalRecord) -> PrepareDomainRequest {
        PrepareDomainRequest {
            native_launch: record.native_launch.clone(),
            runner_session_id: record.runner_session_id.clone(),
            effect_id: record.effect_id.clone(),
            grant_hash: record.grant_hash.clone(),
            policy_hash: record.policy_hash.clone(),
            command_hash: record.command_hash.clone(),
            request_digest: record.request_digest.clone(),
            expected_delegation_identity: record.expected_delegation_identity,
            expected_owner_uid: record.expected_owner_uid,
            limits: record.requested_limits,
        }
    }

    fn create_intent_for_request(request: &PrepareDomainRequest) -> DomainJournalRecord {
        let mut record = create_intent();
        record.native_launch = request.native_launch.clone();
        record.runner_session_id = request.runner_session_id.clone();
        record.effect_id = request.effect_id.clone();
        record.grant_hash = request.grant_hash.clone();
        record.policy_hash = request.policy_hash.clone();
        record.command_hash = request.command_hash.clone();
        record.request_digest = request.request_digest.clone();
        record.expected_delegation_identity = request.expected_delegation_identity;
        record.expected_owner_uid = request.expected_owner_uid;
        record.requested_limits = request.limits;
        record
    }

    fn persist_removed_episode(
        store: &mut CanonicalCgroupJournalStore,
        create: &DomainJournalRecord,
    ) -> DomainJournalRecord {
        let configuring = configuring(create.clone());
        let prepared = prepared(configuring.clone());
        let killing = killing(prepared.clone());
        let empty = empty_proven(killing.clone());
        let remove_intended = remove_intended(empty.clone());
        let removed = removed(remove_intended.clone());
        for record in [
            create,
            &configuring,
            &prepared,
            &killing,
            &empty,
            &remove_intended,
            &removed,
        ] {
            store.persist(record).unwrap();
            store.sync().unwrap();
        }
        removed
    }

    fn probe_expectation(fixture: &Fixture) -> DelegationRootExpectation {
        DelegationRootExpectation {
            service_parent_identity: CgroupObjectIdentity {
                device: 7,
                inode: 10,
            },
            delegation_identity: CgroupObjectIdentity {
                device: 7,
                inode: 11,
            },
            owner_uid: fixture.expected_uid,
            delegation_mode: 0o700,
        }
    }

    fn default_probe_shape(expectation: DelegationRootExpectation) -> ProbeDefaultShape {
        ProbeDefaultShape {
            owner_uid: expectation.owner_uid,
            mode: expectation.delegation_mode,
            events: b"populated 0\nfrozen 0\n".to_vec(),
            procs: Vec::new(),
            pids_max: b"max\n".to_vec(),
            memory_max: b"max\n".to_vec(),
            memory_swap_max: b"max\n".to_vec(),
            memory_oom_group: b"0\n".to_vec(),
            children: Vec::new(),
        }
    }

    #[derive(Debug)]
    struct MockProbeEffects {
        identity: CgroupObjectIdentity,
        present_identity: Option<CgroupObjectIdentity>,
        shape: ProbeDefaultShape,
        fail_once: Option<&'static str>,
        failed: bool,
        fail_observe_after_create: bool,
        create_calls: usize,
        configure_calls: usize,
        kill_calls: usize,
        remove_calls: usize,
    }

    impl MockProbeEffects {
        fn new(expectation: DelegationRootExpectation) -> Self {
            Self {
                identity: CgroupObjectIdentity {
                    device: expectation.delegation_identity.device,
                    inode: 12,
                },
                present_identity: None,
                shape: default_probe_shape(expectation),
                fail_once: None,
                failed: false,
                fail_observe_after_create: false,
                create_calls: 0,
                configure_calls: 0,
                kill_calls: 0,
                remove_calls: 0,
            }
        }

        fn inject(&mut self, operation: &'static str) -> Result<(), CgroupIoFailure> {
            if self.fail_once == Some(operation) && !self.failed {
                self.failed = true;
                Err(failure(
                    operation,
                    EffectCertainty::Ambiguous,
                    "injected durable probe crash boundary",
                ))
            } else {
                Ok(())
            }
        }

        fn require_exact_identity(
            &self,
            record: &ProbeJournalRecord,
        ) -> Result<bool, CgroupIoFailure> {
            match self.present_identity {
                None => Ok(false),
                Some(identity) if Some(identity) == record.observed_identity => Ok(true),
                Some(_) => Err(failure(
                    "mock-probe-identity-substitution",
                    EffectCertainty::Ambiguous,
                    "mock durable name was replaced",
                )),
            }
        }
    }

    impl DurableProbeEffects for MockProbeEffects {
        fn observe_identity(
            &mut self,
            _record: &ProbeJournalRecord,
        ) -> Result<Option<CgroupObjectIdentity>, CgroupIoFailure> {
            if self.fail_observe_after_create && self.create_calls > 0 && !self.failed {
                self.failed = true;
                return Err(failure(
                    "mock-observe-after-create",
                    EffectCertainty::Ambiguous,
                    "injected create-before-identity crash",
                ));
            }
            self.inject("observe")?;
            Ok(self.present_identity)
        }

        fn observe_shape(
            &mut self,
            _record: &ProbeJournalRecord,
            identity: CgroupObjectIdentity,
        ) -> Result<Option<ProbeDefaultShape>, CgroupIoFailure> {
            self.inject("shape")?;
            match self.present_identity {
                None => Ok(None),
                Some(current) if current == identity => Ok(Some(self.shape.clone())),
                Some(_) => Err(failure(
                    "mock-probe-identity-substitution",
                    EffectCertainty::Ambiguous,
                    "mock identity changed before shape read",
                )),
            }
        }

        fn create_no_replace(&mut self, _name: &str) -> Result<(), CgroupIoFailure> {
            self.create_calls += 1;
            self.inject("create")?;
            if self.present_identity.is_some() {
                return Err(failure(
                    "create",
                    EffectCertainty::Ambiguous,
                    "mock no-replace collision",
                ));
            }
            self.present_identity = Some(self.identity);
            self.inject("create-after")?;
            Ok(())
        }

        fn configure_exact(
            &mut self,
            record: &ProbeJournalRecord,
        ) -> Result<bool, CgroupIoFailure> {
            self.configure_calls += 1;
            self.inject("configure")?;
            if !self.require_exact_identity(record)? {
                return Ok(false);
            }
            self.shape.pids_max = b"1\n".to_vec();
            self.shape.memory_oom_group = b"1\n".to_vec();
            self.inject("configure-after")?;
            Ok(true)
        }

        fn kill_and_prove_empty(
            &mut self,
            record: &ProbeJournalRecord,
        ) -> Result<bool, CgroupIoFailure> {
            self.kill_calls += 1;
            self.inject("kill")?;
            if !self.require_exact_identity(record)? {
                return Ok(false);
            }
            self.shape.events = b"populated 0\nfrozen 0\n".to_vec();
            self.shape.procs.clear();
            self.inject("kill-after")?;
            Ok(true)
        }

        fn remove_exact_and_prove(
            &mut self,
            record: &ProbeJournalRecord,
        ) -> Result<(), CgroupIoFailure> {
            self.remove_calls += 1;
            self.inject("remove")?;
            if self.require_exact_identity(record)? {
                self.present_identity = None;
            }
            self.inject("remove-after")?;
            Ok(())
        }
    }

    #[test]
    fn canonical_generations_survive_reopen_and_bind_exact_request() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let create = create_intent();
        let configuring = configuring(create.clone());
        let prepared = prepared(configuring.clone());
        store.persist(&create).unwrap();
        store.sync().unwrap();
        assert!(store.persist(&create).is_err());
        store.persist(&configuring).unwrap();
        store.sync().unwrap();
        store.persist(&prepared).unwrap();
        store.sync().unwrap();
        store.release_lock(token).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        assert_eq!(reopened.read_latest().unwrap(), Some(prepared));
        assert_eq!(
            fs::read_dir(fixture.journal_path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
                .count(),
            3
        );
    }

    #[test]
    fn completed_command_effect_cannot_replay_or_cross_bind_before_publish_or_after_reopen() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let create = create_intent();
        persist_removed_episode(&mut store, &create);

        let exact_request = request_for_record(&create);
        let mut changed_request = create.clone();
        changed_request.request_digest = "e".repeat(64);
        changed_request.leaf_name = format!("gb-{}", "b".repeat(64));
        let mut changed_command = create.clone();
        changed_command.command_hash = "changed-command-hash".into();
        changed_command.leaf_name = format!("gb-{}", "c".repeat(64));
        let mut changed_native_input = create.clone();
        changed_native_input.native_launch.input_snapshot =
            Digest::sha256(b"crossed-journal-command-input");
        changed_native_input.leaf_name = format!("gb-{}", "d".repeat(64));
        let mut changed_runner_session = create.clone();
        changed_runner_session.runner_session_id = "session-2".into();
        changed_runner_session.native_launch.session_id = "session-2".into();
        changed_runner_session.leaf_name = format!("gb-{}", "f".repeat(64));
        let crossed = [
            changed_request,
            changed_command,
            changed_native_input,
            changed_runner_session,
        ];
        let published_before_replay = fs::read_dir(fixture.journal_path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
            .count();
        let exact_error = store
            .require_fresh_episode(token, &exact_request)
            .unwrap_err();
        assert_eq!(exact_error.certainty, EffectCertainty::PriorEffectCommitted);
        assert!(store.persist(&create).is_err());
        for record in &crossed {
            let crossed_error = store
                .require_fresh_episode(token, &request_for_record(record))
                .unwrap_err();
            assert_eq!(
                crossed_error.certainty,
                EffectCertainty::PriorEffectCommitted
            );
            assert!(store.persist(record).is_err());
        }
        assert_eq!(
            fs::read_dir(fixture.journal_path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
                .count(),
            published_before_replay
        );
        store.release_lock(token).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        let token = reopened.acquire_lock().unwrap();
        let reopened_exact_error = reopened
            .require_fresh_episode(token, &exact_request)
            .unwrap_err();
        assert_eq!(
            reopened_exact_error.certainty,
            EffectCertainty::PriorEffectCommitted
        );
        assert!(reopened.persist(&create).is_err());
        for record in &crossed {
            let reopened_crossed_error = reopened
                .require_fresh_episode(token, &request_for_record(record))
                .unwrap_err();
            assert_eq!(
                reopened_crossed_error.certainty,
                EffectCertainty::PriorEffectCommitted
            );
            assert!(reopened.persist(record).is_err());
        }

        let mut distinct = create;
        distinct.effect_id = "effect-2".into();
        distinct.leaf_name = format!("gb-{}", "e".repeat(64));
        let distinct_request = request_for_record(&distinct);
        reopened
            .require_fresh_episode(token, &distinct_request)
            .unwrap();
        reopened.persist(&distinct).unwrap();
        reopened.sync().unwrap();
        assert_eq!(distinct.native_launch.attempt_id, "attempt-1");
        assert_eq!(distinct.native_launch.native_journal_id, "native-journal-1");
        assert_eq!(distinct.request_digest, "d".repeat(64));
        assert_eq!(distinct.command_hash, "command-hash");
        reopened.release_lock(token).unwrap();
    }

    #[test]
    fn service_singleton_authority_rejects_parallel_root_and_crossed_delegation() {
        let fixture = Fixture::new();
        let expected = probe_expectation(&fixture);
        let binding = fixture.service_journal_binding(expected);

        let unsupported = LinuxServiceCommandJournalBinding {
            authority_version: SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION + 1,
            ..binding.clone()
        };
        let version_error = LinuxServiceCommandJournalAuthority::open_test_service_singleton(
            fixture.parent(),
            unsupported,
        )
        .unwrap_err();
        assert_eq!(version_error.operation, "bind-service-command-journal");

        let authority = fixture.open_service_journal_authority(expected);
        let mut crossed_delegation = expected;
        crossed_delegation.delegation_identity.inode += 1;
        let error = authority.into_journal(crossed_delegation).unwrap_err();
        assert_eq!(error.operation, "bind-service-command-journal");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let parallel_name = "caller-selected-parallel-command-journal";
        let parallel_path = fixture.path.join(parallel_name);
        fs::create_dir(&parallel_path).unwrap();
        fs::set_permissions(&parallel_path, fs::Permissions::from_mode(0o700)).unwrap();
        let parent = fixture.parent();
        let parallel = parent.open_dir_nofollow(parallel_name).unwrap();
        let parallel_identity = cgroup_identity(object_identity(&parallel.dir_metadata().unwrap()));
        let parallel_binding = LinuxServiceCommandJournalBinding {
            singleton_journal_root_identity: parallel_identity,
            ..binding.clone()
        };
        let error = LinuxServiceCommandJournalAuthority::open_test_service_singleton(
            fixture.parent(),
            parallel_binding,
        )
        .unwrap_err();
        assert_eq!(error.operation, "bind-service-command-journal");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let other_service_state = Fixture::new();
        let error = LinuxServiceCommandJournalAuthority::open_test_service_singleton(
            other_service_state.parent(),
            binding.clone(),
        )
        .unwrap_err();
        assert_eq!(error.operation, "bind-service-command-journal");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let mut crossed_owner = binding;
        crossed_owner.delegation.owner_uid = crossed_owner
            .delegation
            .owner_uid
            .checked_add(1)
            .expect("fixture UID has a distinct representable value");
        let owner_error = LinuxServiceCommandJournalAuthority::open_test_service_singleton(
            fixture.parent(),
            crossed_owner,
        )
        .unwrap_err();
        assert_eq!(owner_error.certainty, EffectCertainty::NotApplied);

        let replaced = Fixture::new();
        let replaced_expectation = probe_expectation(&replaced);
        let retained_authority = replaced.open_service_journal_authority(replaced_expectation);
        fs::rename(
            replaced.journal_path(),
            replaced.path.join("displaced-command-journal"),
        )
        .unwrap();
        fs::create_dir(replaced.journal_path()).unwrap();
        fs::set_permissions(replaced.journal_path(), fs::Permissions::from_mode(0o700)).unwrap();
        let replacement_error = retained_authority
            .into_journal(replaced_expectation)
            .unwrap_err();
        assert_eq!(replacement_error.operation, "journal-root-identity");
        assert_eq!(replacement_error.certainty, EffectCertainty::NotApplied);
    }

    #[test]
    fn authenticated_handoff_boundary_consumes_only_the_opaque_state_root_capability() {
        let derive: fn(
            PendingLinuxNativeServiceAuthenticatedHandoff,
            &LinuxProductionCommandPlanJournalBindingV1,
        ) -> Result<LinuxNativeServiceStateRootDerivation, CgroupIoFailure> =
            PendingLinuxNativeServiceAuthenticatedHandoff::into_state_root_capability;
        let open: fn(
            LinuxNativeServiceStateRootCapability,
            LinuxServiceCommandJournalBinding,
        ) -> Result<LinuxServiceCommandJournalAuthority, CgroupIoFailure> =
            LinuxServiceCommandJournalAuthority::open_authenticated_service_singleton;
        let _ = (derive, open);

        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let expected = plan.journal_binding().unwrap();
        let authority = fixture
            .open_test_authenticated_handoff_journal(&plan)
            .unwrap();
        authority.require_exact_plan_binding(&expected).unwrap();
        assert!(matches!(
            authority.residual.authentication,
            LinuxServiceCommandJournalAuthentication::AuthenticatedHandoff { .. }
        ));

        assert!(!JournaledLinuxProductionCommandPlanV1::permits_execution());
        assert!(!LinuxNativeServiceBootstrapAuthority::permits_execution());
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
        assert!(!LinuxNativeServiceMechanicsAuthority::permits_execution());
    }

    #[test]
    fn authenticated_handoff_rejects_crossed_plan_root_process_and_delegation() {
        let left = Fixture::new();
        let left_plan = left.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let left_expected = left_plan.journal_binding().unwrap();
        let right = Fixture::new();
        let right_plan = right.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let right_expected = right_plan.journal_binding().unwrap();

        let crossed_plan = left
            .pending_authenticated_handoff(&left_expected)
            .into_state_root_capability(&right_expected)
            .unwrap_err();
        assert_eq!(crossed_plan.operation, "bind-linux-native-service-handoff");
        assert_eq!(crossed_plan.certainty, EffectCertainty::NotApplied);

        let crossed_root = PendingLinuxNativeServiceAuthenticatedHandoff::from_test_descriptors(
            left.service_process_image(),
            right.parent(),
            left.bootstrap_service_parent(),
            "delegation",
            LinuxNativeServiceHandoffCommitmentV1 {
                installer_uid: 0,
                journal: left_expected.clone(),
            },
        )
        .into_state_root_capability(&left_expected)
        .unwrap_err();
        assert_eq!(
            crossed_root.operation,
            "bind-linux-native-service-state-root"
        );
        assert_eq!(crossed_root.certainty, EffectCertainty::NotApplied);

        fs::write(
            right.path.join("authenticated-tools/native-service"),
            b"different-test-only-native-service-image-v1\n",
        )
        .unwrap();
        let crossed_process = PendingLinuxNativeServiceAuthenticatedHandoff::from_test_descriptors(
            right.service_process_image(),
            left.parent(),
            left.bootstrap_service_parent(),
            "delegation",
            LinuxNativeServiceHandoffCommitmentV1 {
                installer_uid: 0,
                journal: left_expected.clone(),
            },
        )
        .into_state_root_capability(&left_expected)
        .unwrap_err();
        assert_eq!(
            crossed_process.operation,
            "bind-native-service-process-image"
        );
        assert_eq!(crossed_process.certainty, EffectCertainty::NotApplied);

        let crossed_delegation =
            PendingLinuxNativeServiceAuthenticatedHandoff::from_test_descriptors(
                left.service_process_image(),
                left.parent(),
                right.bootstrap_service_parent(),
                "delegation",
                LinuxNativeServiceHandoffCommitmentV1 {
                    installer_uid: 0,
                    journal: left_expected.clone(),
                },
            )
            .into_state_root_capability(&left_expected)
            .unwrap_err();
        assert_eq!(
            crossed_delegation.operation,
            "bind-linux-native-service-parent"
        );
        assert_eq!(crossed_delegation.certainty, EffectCertainty::NotApplied);
    }

    #[test]
    fn authenticated_handoff_rejects_process_delegation_and_journal_inode_replacement() {
        let process_fixture = Fixture::new();
        let process_plan = process_fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let process_expected = process_plan.journal_binding().unwrap();
        let process_handoff = process_fixture.pending_authenticated_handoff(&process_expected);
        let process_path = process_fixture
            .path
            .join("authenticated-tools/native-service");
        let original_bytes = fs::read(&process_path).unwrap();
        fs::rename(
            &process_path,
            process_fixture
                .path
                .join("authenticated-tools/displaced-native-service"),
        )
        .unwrap();
        fs::write(&process_path, original_bytes).unwrap();
        fs::set_permissions(&process_path, fs::Permissions::from_mode(0o700)).unwrap();
        let process_error = process_handoff
            .into_state_root_capability(&process_expected)
            .unwrap_err();
        assert_eq!(
            process_error.operation,
            "validate-native-service-process-image"
        );
        assert_eq!(process_error.certainty, EffectCertainty::NotApplied);

        let delegation_fixture = Fixture::new();
        let delegation_plan = delegation_fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let delegation_expected = delegation_plan.journal_binding().unwrap();
        let delegation_handoff =
            delegation_fixture.pending_authenticated_handoff(&delegation_expected);
        let delegation_path = delegation_fixture.path.join("service-cgroup/delegation");
        fs::rename(
            &delegation_path,
            delegation_fixture
                .path
                .join("service-cgroup/displaced-delegation"),
        )
        .unwrap();
        fs::create_dir(&delegation_path).unwrap();
        fs::set_permissions(&delegation_path, fs::Permissions::from_mode(0o700)).unwrap();
        let delegation_error = delegation_handoff
            .into_state_root_capability(&delegation_expected)
            .unwrap_err();
        assert_eq!(delegation_error.operation, "validate-delegation-cgroup");
        assert_eq!(delegation_error.certainty, EffectCertainty::NotApplied);

        let journal_fixture = Fixture::new();
        let journal_plan = journal_fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journal_expected = journal_plan.journal_binding().unwrap();
        let (capability, _) = journal_fixture
            .pending_authenticated_handoff(&journal_expected)
            .into_state_root_capability(&journal_expected)
            .unwrap();
        fs::rename(
            journal_fixture.journal_path(),
            journal_fixture.path.join("displaced-command-journal"),
        )
        .unwrap();
        fs::create_dir(journal_fixture.journal_path()).unwrap();
        fs::set_permissions(
            journal_fixture.journal_path(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let journal_error =
            LinuxServiceCommandJournalAuthority::open_authenticated_service_singleton(
                capability,
                service_journal_binding_from_plan(&journal_expected),
            )
            .unwrap_err();
        assert_eq!(journal_error.operation, "bind-service-command-journal");
        assert_eq!(journal_error.certainty, EffectCertainty::NotApplied);
    }

    #[test]
    fn authenticated_handoff_external_test_commitment_survives_exact_restart_but_rejects_parallel_root()
     {
        let anchored = Fixture::new();
        let plan = anchored.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let expected = plan.journal_binding().unwrap();
        drop(
            anchored
                .open_test_authenticated_handoff_journal(&plan)
                .unwrap(),
        );
        let restarted = anchored
            .open_test_authenticated_handoff_journal(&plan)
            .unwrap();
        restarted.require_exact_plan_binding(&expected).unwrap();
        drop(restarted);

        let parallel = Fixture::new();
        assert_eq!(
            fs::read(anchored.path.join("authenticated-tools/native-service")).unwrap(),
            fs::read(parallel.path.join("authenticated-tools/native-service")).unwrap()
        );
        let crossed = PendingLinuxNativeServiceAuthenticatedHandoff::from_test_descriptors(
            parallel.service_process_image(),
            parallel.parent(),
            parallel.bootstrap_service_parent(),
            "delegation",
            LinuxNativeServiceHandoffCommitmentV1 {
                installer_uid: 0,
                journal: expected.clone(),
            },
        )
        .into_state_root_capability(&expected)
        .unwrap_err();
        assert_eq!(crossed.operation, "bind-linux-native-service-state-root");
        assert_eq!(crossed.certainty, EffectCertainty::NotApplied);
    }

    #[test]
    fn service_singleton_history_is_cross_instance_restart_and_session_global() {
        let fixture = Fixture::new();
        let expected = probe_expectation(&fixture);
        let plan = fixture.command_plan(crate::wire::RunnerRole::Worker, expected);
        let plan_bytes = plan.canonical_bytes().to_vec();
        let plan_digest = plan.plan_digest().clone();
        let substituted = plan
            .clone()
            .substitute_test_same_effect_plan()
            .expect("construct valid same-effect full-plan substitution");
        let first_authority = fixture.open_service_journal_authority(expected);
        let second_authority = fixture.open_service_journal_authority(expected);
        let bridge = journal_linux_production_command_plan(plan.clone(), first_authority)
            .expect("durably journal exact complete plan");
        assert!(!JournaledLinuxProductionCommandPlanV1::permits_execution());
        bridge.with_private_mechanics(|request, mut authority| {
            let token = authority.journal.acquire_lock().unwrap();
            authority
                .journal
                .require_fresh_episode(token, request)
                .unwrap();
            let create = create_intent_for_request(request);
            persist_removed_episode(&mut authority.journal, &create);
            authority.journal.release_lock(token).unwrap();
        });
        assert_eq!(
            fs::read(fixture.journal_path().join(command_plan_name(&plan_digest))).unwrap(),
            plan_bytes
        );

        let error =
            journal_linux_production_command_plan(plan.clone(), second_authority).unwrap_err();
        assert_eq!(error.certainty, EffectCertainty::PriorEffectCommitted);

        let substitution_authority = fixture.open_service_journal_authority(expected);
        let substitution_error =
            journal_linux_production_command_plan(substituted, substitution_authority).unwrap_err();
        assert_eq!(
            substitution_error.certainty,
            EffectCertainty::PriorEffectCommitted
        );
        assert!(substitution_error.detail.contains("different"));

        let restart_authority = fixture.open_service_journal_authority(expected);
        let restart_error =
            journal_linux_production_command_plan(plan, restart_authority).unwrap_err();
        assert_eq!(
            restart_error.certainty,
            EffectCertainty::PriorEffectCommitted
        );
    }

    #[test]
    fn plan_write_publish_sync_or_readback_failure_never_enters_private_host_mechanics() {
        use std::cell::Cell;

        for failure_point in ["write", "publish", "directory-sync", "readback"] {
            let fixture = Fixture::new();
            let expected = probe_expectation(&fixture);
            let plan = fixture.command_plan(crate::wire::RunnerRole::Worker, expected);
            let mut authority = fixture.open_service_journal_authority(expected);
            match failure_point {
                "write" => authority.journal.inject_next_command_plan_write_failure(),
                "publish" => authority.journal.inject_next_command_plan_publish_failure(),
                "directory-sync" => authority
                    .journal
                    .inject_next_command_plan_directory_sync_failure(),
                "readback" => authority
                    .journal
                    .inject_next_command_plan_readback_failure(),
                _ => unreachable!(),
            }
            let mechanics_called = Cell::new(false);
            let result =
                journal_linux_production_command_plan(plan.clone(), authority).map(|bridge| {
                    bridge.with_private_mechanics(|_, _| mechanics_called.set(true));
                });
            let error = result.unwrap_err();
            assert_eq!(
                error.operation,
                match failure_point {
                    "write" => "write-command-plan-temporary",
                    "publish" => "publish-command-plan",
                    "directory-sync" => "sync-command-plan-directory",
                    "readback" => "readback-command-plan",
                    _ => unreachable!(),
                }
            );
            assert_eq!(
                error.certainty,
                if matches!(failure_point, "write" | "publish") {
                    EffectCertainty::NotApplied
                } else {
                    EffectCertainty::Ambiguous
                }
            );
            assert!(!mechanics_called.get());

            let temporary_path = fixture
                .journal_path()
                .join(command_plan_temporary_name(plan.plan_digest()));
            let restart_authority = fixture.open_service_journal_authority(expected);
            let restart = journal_linux_production_command_plan(plan, restart_authority);
            if matches!(failure_point, "write" | "publish") {
                assert!(restart.is_ok());
                assert!(!temporary_path.exists());
            } else {
                assert_eq!(
                    restart.unwrap_err().certainty,
                    EffectCertainty::PriorEffectCommitted
                );
            }
        }
    }

    #[test]
    fn command_plan_temporary_recovery_discards_unpublished_partial_but_rejects_multiple() {
        let fixture = Fixture::new();
        let expected = probe_expectation(&fixture);
        let plan = fixture.command_plan(crate::wire::RunnerRole::Worker, expected);
        let temporary_name = command_plan_temporary_name(plan.plan_digest());
        let final_name = command_plan_name(plan.plan_digest());
        let authority = fixture.open_service_journal_authority(expected);
        write_new_private_file(
            &authority.journal.directory,
            &temporary_name,
            b"{",
            fixture.expected_uid,
        )
        .unwrap();
        drop(authority);
        let restart = fixture.open_service_journal_authority(expected);
        let bridge = journal_linux_production_command_plan(plan, restart).unwrap();
        assert!(!JournaledLinuxProductionCommandPlanV1::permits_execution());
        drop(bridge);
        assert!(!fixture.journal_path().join(temporary_name).exists());
        assert!(fixture.journal_path().join(final_name).is_file());

        let fixture = Fixture::new();
        let expected = probe_expectation(&fixture);
        let worker = fixture.command_plan(crate::wire::RunnerRole::Worker, expected);
        let verifier = fixture.command_plan(crate::wire::RunnerRole::FinalVerifier, expected);
        let authority = fixture.open_service_journal_authority(expected);
        for plan in [&worker, &verifier] {
            write_new_private_file(
                &authority.journal.directory,
                &command_plan_temporary_name(plan.plan_digest()),
                plan.canonical_bytes(),
                fixture.expected_uid,
            )
            .unwrap();
        }
        drop(authority);
        let restart = fixture.open_service_journal_authority(expected);
        let error = journal_linux_production_command_plan(worker, restart).unwrap_err();
        assert_eq!(error.operation, "recover-command-plan-temporary");
        assert_eq!(error.certainty, EffectCertainty::Ambiguous);
        assert!(error.detail.contains("multiple"));

        let fixture = Fixture::new();
        let expected = probe_expectation(&fixture);
        let plan = fixture.command_plan(crate::wire::RunnerRole::Worker, expected);
        let final_name = command_plan_name(plan.plan_digest());
        let temporary_name = command_plan_temporary_name(plan.plan_digest());
        let authority = fixture.open_service_journal_authority(expected);
        let bridge = journal_linux_production_command_plan(plan.clone(), authority).unwrap();
        drop(bridge);
        let directory = fixture
            .parent()
            .open_dir_nofollow(&fixture.journal_name)
            .unwrap();
        write_new_private_file(
            &directory,
            &temporary_name,
            plan.canonical_bytes(),
            fixture.expected_uid,
        )
        .unwrap();
        let restart = fixture.open_service_journal_authority(expected);
        let error = journal_linux_production_command_plan(plan, restart).unwrap_err();
        assert_eq!(error.certainty, EffectCertainty::PriorEffectCommitted);
        assert!(fixture.journal_path().join(final_name).is_file());
        assert!(!fixture.journal_path().join(temporary_name).exists());
    }

    #[test]
    fn legacy_v1_directory_and_envelope_are_explicitly_classified_and_rejected() {
        let fixture = Fixture::new();
        let legacy_path = fixture
            .path
            .join(LEGACY_SERVICE_COMMAND_JOURNAL_DIRECTORY_V1);
        fs::create_dir(&legacy_path).unwrap();
        fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o700)).unwrap();
        let error = LinuxServiceCommandJournalAuthority::open_test_service_singleton(
            fixture.parent(),
            fixture.service_journal_binding(probe_expectation(&fixture)),
        )
        .unwrap_err();
        assert_eq!(error.operation, "classify-service-command-journal");
        assert!(error.detail.contains("v1"));
        assert!(error.detail.contains("unsupported"));

        let record = create_intent();
        let record_bytes = serde_json::to_vec(&record).unwrap();
        let legacy = serde_json::json!({
            "format_version": 1,
            "sequence": 0,
            "record_sha256": sha256_hex(&record_bytes),
            "record": record,
        });
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        let error = decode_envelope(&legacy_bytes).unwrap_err();
        assert_eq!(error.operation, "classify-journal-envelope");
        assert!(error.detail.contains("v1"));
        assert!(error.detail.contains("unsupported"));
    }

    #[test]
    fn bridge_rejects_platform_service_and_delegation_authority_substitution() {
        let fixture = Fixture::new();
        let expected = probe_expectation(&fixture);
        let plan = fixture.command_plan(crate::wire::RunnerRole::Worker, expected);

        let mut service_binding = fixture.service_journal_binding(expected);
        service_binding.authenticated_platform_service_digest =
            Digest::sha256(b"crossed-platform-service");
        let service_authority = LinuxServiceCommandJournalAuthority::open_test_service_singleton(
            fixture.parent(),
            service_binding,
        )
        .unwrap();
        let error =
            journal_linux_production_command_plan(plan.clone(), service_authority).unwrap_err();
        assert_eq!(error.operation, "bind-complete-command-plan");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);

        let mut crossed = expected;
        crossed.delegation_identity.inode += 100;
        let crossed_authority = fixture.open_service_journal_authority(crossed);
        let error = journal_linux_production_command_plan(plan, crossed_authority).unwrap_err();
        assert_eq!(error.operation, "bind-complete-command-plan");
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
        assert!(
            fixture
                .journal_path()
                .join(PROBE_JOURNAL_DIRECTORY)
                .is_dir()
        );
    }

    #[test]
    fn retained_service_bootstrap_joins_only_after_exact_plan_journal_and_remains_inert() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let worker = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let journaled = journal_linux_production_command_plan(
            worker.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(
            journaled,
            fixture.open_bootstrap_authority(&worker),
        )
        .unwrap();
        assert!(!LinuxNativeServiceBootstrapAuthority::permits_execution());
        assert!(!BootstrappedLinuxProductionCommandPlanV1::permits_execution());
        bootstrapped.revalidate_for_test().unwrap();
        let admission = fixture.admit(bootstrapped);
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
        admission.revalidate_for_test().unwrap();
        let launch_images = Fixture::select_launch_images(admission);
        assert!(!LinuxNativeServiceLaunchImageAuthority::permits_execution());
        launch_images.revalidate_for_test().unwrap();
        let setup = fixture.bind_setup_descriptors(&worker, launch_images);
        assert!(!LinuxNativeServiceSetupDescriptorAuthority::permits_execution());
        setup.revalidate_for_test().unwrap();
        let child = Fixture::bind_child_launch_closure(setup);
        assert!(!LinuxNativeServiceChildLaunchClosureCapability::permits_execution());
        assert!(!LinuxNativeServiceChildLaunchClosureAuthority::permits_execution());
        child.revalidate_for_test().unwrap();
        let mechanics = retain_linux_native_service_mechanics_authority(child).unwrap();
        assert!(!LinuxNativeServiceMechanicsAuthority::permits_execution());
        mechanics.revalidate_for_test().unwrap();
        drop(mechanics);

        let verifier = fixture.bootstrap_plan(crate::wire::RunnerRole::FinalVerifier);
        let restart_journaled = journal_linux_production_command_plan(
            verifier.clone(),
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let restarted = bind_journaled_plan_to_linux_native_service_bootstrap(
            restart_journaled,
            fixture.open_bootstrap_authority(&verifier),
        )
        .unwrap();
        restarted.revalidate_for_test().unwrap();
        assert!(fixture.path.join(SERVICE_BOOTSTRAP_FINAL_NAME).is_file());
        assert!(!fixture.path.join(SERVICE_BOOTSTRAP_TEMP_NAME).exists());
    }

    #[test]
    fn launch_image_selection_consumes_the_exact_role_destination_set_without_side_effects() {
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
        let before = fs::read_dir(fixture.journal_path()).unwrap().count();
        let authority = select_linux_native_service_launch_images(admission).unwrap();
        let after = fs::read_dir(fixture.journal_path()).unwrap().count();

        assert_eq!(before, after);
        assert!(!LinuxNativeServiceLaunchImageAuthority::permits_execution());
        authority.revalidate_for_test().unwrap();
        assert_eq!(authority.launch_images.plan_digest, *plan.plan_digest());
        assert_eq!(
            authority
                .launch_images
                .images
                .iter()
                .map(|image| image.binding.clone())
                .collect::<Vec<_>>(),
            plan.service_launch_image_bindings().unwrap()
        );
        assert_eq!(
            authority.launch_images.images[0].binding.usage,
            LinuxServiceLaunchImageUseV1::HostExecutable
        );
    }

    #[test]
    fn launch_image_authority_rejects_object_role_destination_content_and_plan_crossing() {
        let fixture = Fixture::new();
        let (_, mut authority) = fixture.launch_image_authority(crate::wire::RunnerRole::Worker);

        let original = authority.launch_images.images[1].binding.clone();
        authority.launch_images.images[1].binding.object_id = "crossed-image".into();
        assert_eq!(
            authority.revalidate_for_test().unwrap_err().operation,
            "validate-native-service-launch-image"
        );
        authority.launch_images.images[1].binding = original.clone();

        authority.launch_images.images[1].binding.role = LinuxServiceExecutableRoleV1::Target;
        assert_eq!(
            authority.revalidate_for_test().unwrap_err().operation,
            "validate-native-service-launch-image"
        );
        authority.launch_images.images[1].binding = original.clone();

        authority.launch_images.images[1].binding.usage =
            LinuxServiceLaunchImageUseV1::ReadOnlyNamespaceMount {
                purpose: crate::linux_command_plan::LinuxMountPurposeV1::InnerLauncher,
                destination: "/crossed/inner-launcher".into(),
            };
        assert_eq!(
            authority.revalidate_for_test().unwrap_err().operation,
            "validate-native-service-launch-image"
        );
        authority.launch_images.images[1].binding = original.clone();

        authority.launch_images.images[1].binding.content_sha256 =
            Digest::sha256(b"crossed selected image");
        assert_eq!(
            authority.revalidate_for_test().unwrap_err().operation,
            "validate-native-service-launch-image"
        );
        authority.launch_images.images[1].binding = original;

        authority.launch_images.plan_digest = Digest::sha256(b"crossed selected plan");
        assert_eq!(
            authority.revalidate_for_test().unwrap_err().operation,
            "validate-native-service-launch-image-set"
        );
    }

    #[test]
    fn launch_image_authority_rejects_descriptor_cloexec_substitution() {
        use std::os::fd::AsFd as _;

        let fixture = Fixture::new();
        let (_, authority) = fixture.launch_image_authority(crate::wire::RunnerRole::Worker);
        let image = &authority.launch_images.images[0];
        #[cfg(target_os = "linux")]
        let descriptor = image.sealed_snapshot.file.as_fd();
        #[cfg(not(target_os = "linux"))]
        let descriptor = image.portable_test_descriptor.file.as_fd();
        rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::empty()).unwrap();

        let error = authority.revalidate_for_test().unwrap_err();
        assert!(matches!(
            error.operation,
            "validate-native-service-sealed-executable" | "validate-portable-test-launch-image"
        ));
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
    }

    #[test]
    fn launch_image_authority_revalidates_receipt_service_and_lifetime_bindings() {
        let fixture = Fixture::new();
        let (_, mut authority) =
            fixture.launch_image_authority(crate::wire::RunnerRole::FinalVerifier);

        authority
            .bootstrapped
            .journaled
            .receipt
            .artifact_identity
            .inode += 1;
        assert_eq!(
            authority.revalidate_for_test().unwrap_err().operation,
            "authenticate-command-plan-artifact"
        );
        authority
            .bootstrapped
            .journaled
            .receipt
            .artifact_identity
            .inode -= 1;

        authority.service_process_image.content_sha256 =
            Digest::sha256(b"crossed selected service image");
        assert_eq!(
            authority.revalidate_for_test().unwrap_err().operation,
            "validate-native-service-process-image"
        );
        authority.service_process_image.content_sha256 = authority
            .bootstrapped
            .journaled
            .plan
            .journal_binding()
            .unwrap()
            .authenticated_platform_service_digest;

        authority.lifetime_lock.identity.inode += 1;
        assert_eq!(
            authority.revalidate_for_test().unwrap_err().operation,
            "validate-linux-native-service-lifetime"
        );
    }

    #[test]
    fn setup_descriptor_join_is_one_shot_exact_and_side_effect_free() {
        let fixture = Fixture::new();
        let (plan, launch_images) = fixture.launch_image_authority(crate::wire::RunnerRole::Worker);
        let setup_capability = fixture.setup_descriptor_capability(&plan);
        let setup_request_offset_before = retained_file_offset(
            &setup_capability
                .endpoints
                .iter()
                .find(|endpoint| {
                    endpoint.binding.role == LinuxServiceSetupEndpointRoleV1::SetupRequest
                })
                .unwrap()
                .file,
        );
        let journal_entries_before = fs::read_dir(fixture.journal_path()).unwrap().count();
        let delegation_entries_before =
            fs::read_dir(fixture.path.join("service-cgroup/delegation"))
                .unwrap()
                .count();

        let setup =
            bind_linux_native_service_setup_descriptors(launch_images, setup_capability).unwrap();
        setup.revalidate_for_test().unwrap();
        assert!(!LinuxNativeServiceSetupDescriptorCapability::permits_execution());
        assert!(!LinuxNativeServiceSetupDescriptorAuthority::permits_execution());
        assert_eq!(
            retained_file_offset(
                &setup
                    .setup_descriptors
                    .endpoints
                    .iter()
                    .find(|endpoint| {
                        endpoint.binding.role == LinuxServiceSetupEndpointRoleV1::SetupRequest
                    })
                    .unwrap()
                    .file,
            ),
            setup_request_offset_before
        );
        assert_eq!(
            fs::read_dir(fixture.journal_path()).unwrap().count(),
            journal_entries_before
        );
        assert_eq!(
            fs::read_dir(fixture.path.join("service-cgroup/delegation"))
                .unwrap()
                .count(),
            delegation_entries_before
        );

        let child_capability = Fixture::child_launch_closure_capability(&setup);
        let child =
            bind_linux_native_service_child_launch_closure(setup, child_capability).unwrap();
        let retain: fn(
            LinuxNativeServiceChildLaunchClosureAuthority,
        ) -> Result<LinuxNativeServiceMechanicsAuthority, CgroupIoFailure> =
            retain_linux_native_service_mechanics_authority;
        let mechanics = retain(child).unwrap();
        mechanics.revalidate_for_test().unwrap();
        assert!(!LinuxNativeServiceMechanicsAuthority::permits_execution());
    }

    #[test]
    fn setup_descriptor_mint_rejects_missing_extra_and_crossed_sources() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::FinalVerifier);

        let mut missing = fixture.setup_descriptor_inputs(&plan);
        missing.read_only_mount_sources.pop();
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(&plan, missing)
                .unwrap_err()
                .operation,
            "mint-test-linux-native-service-setup-descriptors"
        );

        let mut extra = fixture.setup_descriptor_inputs(&plan);
        extra
            .read_only_mount_sources
            .push(fixture.setup_directory("workspace"));
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(&plan, extra)
                .unwrap_err()
                .operation,
            "mint-test-linux-native-service-setup-descriptors"
        );

        let mut crossed = fixture.setup_descriptor_inputs(&plan);
        crossed.read_only_mount_sources.swap(0, 1);
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(&plan, crossed)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-setup-mount-source"
        );

        let mut crossed_execution_root = fixture.setup_descriptor_inputs(&plan);
        crossed_execution_root.execution_root = fixture.setup_directory("workspace");
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(
                &plan,
                crossed_execution_root,
            )
            .unwrap_err()
            .operation,
            "validate-linux-native-service-setup-execution-root"
        );

        let mut crossed_private_roots = fixture.setup_descriptor_inputs(&plan);
        std::mem::swap(
            &mut crossed_private_roots.private_state_root,
            &mut crossed_private_roots.singleton_journal_root,
        );
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(
                &plan,
                crossed_private_roots,
            )
            .unwrap_err()
            .operation,
            "validate-linux-native-service-setup-private-root"
        );

        let mut missing_endpoint = fixture.setup_descriptor_inputs(&plan);
        missing_endpoint.endpoints.pop();
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(
                &plan,
                missing_endpoint,
            )
            .unwrap_err()
            .operation,
            "mint-test-linux-native-service-setup-descriptors"
        );

        let mut extra_endpoint = fixture.setup_descriptor_inputs(&plan);
        extra_endpoint.endpoints.push((
            LinuxServiceSetupEndpointRoleV1::TargetStderr,
            test_pipe_endpoint(
                &fixture.path,
                LinuxServiceSetupDescriptorAccessV1::WriteOnly,
            ),
        ));
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(
                &plan,
                extra_endpoint,
            )
            .unwrap_err()
            .operation,
            "mint-test-linux-native-service-setup-descriptors"
        );
    }

    #[test]
    fn setup_descriptor_mint_rejects_endpoint_role_access_and_alias_crossing() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);

        let mut crossed_role = fixture.setup_descriptor_inputs(&plan);
        crossed_role.endpoints[1].0 = LinuxServiceSetupEndpointRoleV1::SetupStatus;
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(
                &plan,
                crossed_role,
            )
            .unwrap_err()
            .operation,
            "mint-test-linux-native-service-setup-descriptors"
        );

        let mut crossed_access = fixture.setup_descriptor_inputs(&plan);
        let stdin = crossed_access
            .endpoints
            .iter()
            .position(|(role, _)| *role == LinuxServiceSetupEndpointRoleV1::TargetStdin)
            .unwrap();
        crossed_access.endpoints[stdin].1 = test_pipe_endpoint(
            &fixture.path,
            LinuxServiceSetupDescriptorAccessV1::WriteOnly,
        );
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(
                &plan,
                crossed_access,
            )
            .unwrap_err()
            .operation,
            "validate-linux-native-service-setup-endpoint"
        );

        let mut aliased = fixture.setup_descriptor_inputs(&plan);
        let stdout = aliased
            .endpoints
            .iter()
            .position(|(role, _)| *role == LinuxServiceSetupEndpointRoleV1::TargetStdout)
            .unwrap();
        let stderr = aliased
            .endpoints
            .iter()
            .position(|(role, _)| *role == LinuxServiceSetupEndpointRoleV1::TargetStderr)
            .unwrap();
        aliased.endpoints[stderr].1 = aliased.endpoints[stdout].1.try_clone().unwrap();
        assert_eq!(
            LinuxNativeServiceSetupDescriptorCapability::open_test_authenticated(&plan, aliased)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-setup-endpoint-aliases"
        );
    }

    #[test]
    fn setup_descriptor_authority_rejects_plan_phase_mount_and_crossed_capability() {
        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let mut capability = fixture.setup_descriptor_capability(&plan);
        let exact_binding = capability.binding.clone();
        capability
            .binding
            .close_after_setup_before_target_exec_roles
            .pop();
        assert_eq!(
            capability.revalidate_for_test(&plan).unwrap_err().operation,
            "validate-linux-native-service-setup-descriptors"
        );
        capability.binding = exact_binding.clone();
        capability.binding.target_exec_attempt_allowed_roles.pop();
        assert_eq!(
            capability.revalidate_for_test(&plan).unwrap_err().operation,
            "validate-linux-native-service-setup-descriptors"
        );
        capability.binding = exact_binding.clone();
        capability
            .binding
            .close_on_successful_target_exec_roles
            .pop();
        assert_eq!(
            capability.revalidate_for_test(&plan).unwrap_err().operation,
            "validate-linux-native-service-setup-descriptors"
        );
        capability.binding = exact_binding.clone();
        capability.binding.post_exec_target_allowed_roles.pop();
        assert_eq!(
            capability.revalidate_for_test(&plan).unwrap_err().operation,
            "validate-linux-native-service-setup-descriptors"
        );
        capability.binding = exact_binding;
        capability.read_only_mount_sources[0].directory = fixture.setup_directory("git-mask");
        assert_eq!(
            capability.revalidate_for_test(&plan).unwrap_err().operation,
            "validate-linux-native-service-setup-mount-source"
        );

        let crossed_fixture = Fixture::new();
        let crossed_plan = crossed_fixture.bootstrap_plan(crate::wire::RunnerRole::FinalVerifier);
        let crossed_capability = crossed_fixture.setup_descriptor_capability(&crossed_plan);
        let launch_fixture = Fixture::new();
        let (_, launch_images) =
            launch_fixture.launch_image_authority(crate::wire::RunnerRole::Worker);
        assert_eq!(
            bind_linux_native_service_setup_descriptors(launch_images, crossed_capability)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-setup-descriptors"
        );
    }

    #[test]
    fn setup_descriptor_authority_rejects_cwd_replacement_and_cloexec_loss() {
        use std::os::fd::AsFd as _;

        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let capability = fixture.setup_descriptor_capability(&plan);
        let cwd = fixture.path.join("execution/fixture");
        fs::rename(&cwd, fixture.path.join("displaced-setup-cwd")).unwrap();
        fs::create_dir(&cwd).unwrap();
        fs::set_permissions(&cwd, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            capability.revalidate_for_test(&plan).unwrap_err().operation,
            "validate-linux-native-service-setup-cwd"
        );

        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let capability = fixture.setup_descriptor_capability(&plan);
        let stderr = capability
            .endpoints
            .iter()
            .position(|endpoint| {
                endpoint.binding.role == LinuxServiceSetupEndpointRoleV1::TargetStderr
            })
            .unwrap();
        rustix::io::fcntl_setfd(
            capability.endpoints[stderr].file.as_fd(),
            rustix::io::FdFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            capability.revalidate_for_test(&plan).unwrap_err().operation,
            "validate-linux-native-service-setup-endpoint"
        );

        let fixture = Fixture::new();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let capability = fixture.setup_descriptor_capability(&plan);
        rustix::io::fcntl_setfd(
            capability.execution_root.directory.as_fd(),
            rustix::io::FdFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            capability.revalidate_for_test(&plan).unwrap_err().operation,
            "validate-linux-native-service-setup-execution-root"
        );
    }

    #[test]
    fn child_launch_closure_join_is_one_shot_complete_and_side_effect_free() {
        let fixture = Fixture::new();
        let (_, setup) = fixture.setup_descriptor_authority(crate::wire::RunnerRole::Worker);
        let setup_request_offset_before = retained_file_offset(
            &setup
                .setup_descriptors
                .endpoints
                .iter()
                .find(|endpoint| {
                    endpoint.binding.role == LinuxServiceSetupEndpointRoleV1::SetupRequest
                })
                .unwrap()
                .file,
        );
        let journal_entries_before = fs::read_dir(fixture.journal_path()).unwrap().count();
        let delegation_entries_before =
            fs::read_dir(fixture.path.join("service-cgroup/delegation"))
                .unwrap()
                .count();

        let capability = Fixture::child_launch_closure_capability(&setup);
        capability.revalidate_for_test(&setup).unwrap();
        assert!(!LinuxNativeServiceChildLaunchClosureCapability::permits_execution());
        let authority = bind_linux_native_service_child_launch_closure(setup, capability).unwrap();
        authority.revalidate_for_test().unwrap();
        assert!(!LinuxNativeServiceChildLaunchClosureAuthority::permits_execution());
        assert_eq!(
            retained_file_offset(
                &authority
                    .setup_authority
                    .setup_descriptors
                    .endpoints
                    .iter()
                    .find(|endpoint| {
                        endpoint.binding.role == LinuxServiceSetupEndpointRoleV1::SetupRequest
                    })
                    .unwrap()
                    .file,
            ),
            setup_request_offset_before
        );
        assert_eq!(
            fs::read_dir(fixture.journal_path()).unwrap().count(),
            journal_entries_before
        );
        assert_eq!(
            fs::read_dir(fixture.path.join("service-cgroup/delegation"))
                .unwrap()
                .count(),
            delegation_entries_before
        );

        let mechanics = retain_linux_native_service_mechanics_authority(authority).unwrap();
        mechanics.revalidate_for_test().unwrap();
        assert!(!LinuxNativeServiceMechanicsAuthority::permits_execution());
    }

    #[test]
    fn child_launch_closure_rejects_missing_extra_crossed_role_and_descriptor_aliases() {
        let fixture = Fixture::new();
        let (_, setup) = fixture.setup_descriptor_authority(crate::wire::RunnerRole::Worker);
        let mut capability = Fixture::child_launch_closure_capability(&setup);
        let exact_binding = capability.binding.clone();

        capability.binding.inner_launcher_descriptor_table.pop();
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        capability
            .binding
            .inner_launcher_descriptor_table
            .push(exact_binding.inner_launcher_descriptor_table[0].clone());
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        capability.binding.inner_launcher_descriptor_table[0].target_fd = 1;
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        capability.binding.inner_launcher_descriptor_table[0].source =
            LinuxServiceChildDescriptorSourceV1::Endpoint(
                LinuxServiceSetupEndpointRoleV1::TargetStdout,
            );
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding;

        let missing_observation = capability.descriptor_observations.pop().unwrap();
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability
            .descriptor_observations
            .push(missing_observation.clone());
        capability.descriptor_observations.push(missing_observation);
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.descriptor_observations.pop();

        let exact_identity = capability.descriptor_observations[1].identity;
        capability.descriptor_observations[1].identity =
            capability.descriptor_observations[0].identity;
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-descriptor-table"
        );
        capability.descriptor_observations[1].identity = exact_identity;
        capability.revalidate_for_test(&setup).unwrap();
    }

    #[test]
    fn child_launch_closure_rejects_access_cloexec_and_lifecycle_crossing() {
        use std::os::fd::AsFd as _;

        let fixture = Fixture::new();
        let (_, setup) = fixture.setup_descriptor_authority(crate::wire::RunnerRole::Worker);
        let mut capability = Fixture::child_launch_closure_capability(&setup);
        let exact_binding = capability.binding.clone();

        capability.binding.inner_launcher_descriptor_table[3].child_access =
            LinuxServiceSetupDescriptorAccessV1::ReadWrite;
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        capability.binding.inner_launcher_descriptor_table[0].child_close_on_exec = true;
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        capability.binding.inner_launcher_descriptor_table[4].lifecycle =
            LinuxServiceChildDescriptorLifecycleV1::CloseOnSuccessfulExec;
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        capability.binding.inner_launcher_descriptor_table[6].retained_source_close_on_exec = false;
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );

        capability.binding = exact_binding;
        let stderr = setup
            .setup_descriptors
            .endpoints
            .iter()
            .position(|endpoint| {
                endpoint.binding.role == LinuxServiceSetupEndpointRoleV1::TargetStderr
            })
            .unwrap();
        rustix::io::fcntl_setfd(
            setup.setup_descriptors.endpoints[stderr].file.as_fd(),
            rustix::io::FdFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-setup-endpoint"
        );
    }

    #[test]
    fn child_launch_closure_rejects_loader_mount_missing_extra_crossed_role_and_alias() {
        let fixture = Fixture::new();
        let (_, setup) = fixture.setup_descriptor_authority(crate::wire::RunnerRole::Worker);
        let mut capability = Fixture::child_launch_closure_capability(&setup);
        let exact_binding = capability.binding.clone();

        capability.binding.image_mounts.pop();
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        capability
            .binding
            .image_mounts
            .push(exact_binding.image_mounts[0].clone());
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        capability.binding.image_mounts[0].role = LinuxServiceExecutableRoleV1::Target;
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        capability.binding.image_mounts[1].destination =
            exact_binding.image_mounts[0].destination.clone();
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding.clone();
        let LinuxServiceTargetLoaderClosureV1::Dynamic {
            runtime_object_ids_in_order,
            ..
        } = &mut capability.binding.loader_closure
        else {
            panic!("worker fixture must retain its exact dynamic-loader closure")
        };
        runtime_object_ids_in_order.clear();
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.binding = exact_binding;

        let missing_observation = capability.image_mount_observations.pop().unwrap();
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability
            .image_mount_observations
            .push(missing_observation.clone());
        capability
            .image_mount_observations
            .push(missing_observation);
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );
        capability.image_mount_observations.pop();

        let exact_identity = capability.image_mount_observations[1].identity;
        capability.image_mount_observations[1].identity =
            capability.image_mount_observations[0].identity;
        assert_eq!(
            capability
                .revalidate_for_test(&setup)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-image-mounts"
        );
        capability.image_mount_observations[1].identity = exact_identity;
        capability.revalidate_for_test(&setup).unwrap();
    }

    #[test]
    fn child_launch_closure_rejects_cross_plan_and_image_source_cloexec_loss() {
        use std::os::fd::AsFd as _;

        let worker_fixture = Fixture::new();
        let (_, worker_setup) =
            worker_fixture.setup_descriptor_authority(crate::wire::RunnerRole::Worker);
        let worker_capability = Fixture::child_launch_closure_capability(&worker_setup);
        let verifier_fixture = Fixture::new();
        let (_, verifier_setup) =
            verifier_fixture.setup_descriptor_authority(crate::wire::RunnerRole::FinalVerifier);
        assert_eq!(
            bind_linux_native_service_child_launch_closure(verifier_setup, worker_capability,)
                .unwrap_err()
                .operation,
            "validate-linux-native-service-child-launch-closure"
        );

        let fixture = Fixture::new();
        let (_, setup) = fixture.setup_descriptor_authority(crate::wire::RunnerRole::Worker);
        let capability = Fixture::child_launch_closure_capability(&setup);
        let image = setup
            .launch_images
            .images
            .iter()
            .find(|image| image.binding.role == LinuxServiceExecutableRoleV1::InnerLauncher)
            .unwrap();
        #[cfg(target_os = "linux")]
        let descriptor = image.sealed_snapshot.file.as_fd();
        #[cfg(not(target_os = "linux"))]
        let descriptor = image.portable_test_descriptor.file.as_fd();
        rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::empty()).unwrap();
        let error = capability.revalidate_for_test(&setup).unwrap_err();
        assert!(matches!(
            error.operation,
            "validate-native-service-sealed-executable" | "validate-portable-test-launch-image"
        ));
        assert_eq!(error.certainty, EffectCertainty::NotApplied);
    }

    #[test]
    fn linux_cgroup_entry_signature_requires_the_exact_post_bootstrap_plan_capability() {
        let entry: fn(
            LinuxNativeServiceMechanicsAuthority,
        ) -> Result<LinuxCgroupIo, CgroupIoFailure> = LinuxCgroupIo::open_service_owned;
        let admit: fn(
            BootstrappedLinuxProductionCommandPlanV1,
            LinuxNativeServiceProcessImageAuthority,
        ) -> Result<LinuxNativeServiceAdmissionAuthority, CgroupIoFailure> =
            admit_linux_native_service_command;
        let select: fn(
            LinuxNativeServiceAdmissionAuthority,
        ) -> Result<LinuxNativeServiceLaunchImageAuthority, CgroupIoFailure> =
            select_linux_native_service_launch_images;
        let bind_setup: fn(
            LinuxNativeServiceLaunchImageAuthority,
            LinuxNativeServiceSetupDescriptorCapability,
        )
            -> Result<LinuxNativeServiceSetupDescriptorAuthority, CgroupIoFailure> =
            bind_linux_native_service_setup_descriptors;
        let bind_child: fn(
            LinuxNativeServiceSetupDescriptorAuthority,
            LinuxNativeServiceChildLaunchClosureCapability,
        ) -> Result<
            LinuxNativeServiceChildLaunchClosureAuthority,
            CgroupIoFailure,
        > = bind_linux_native_service_child_launch_closure;
        let retain: fn(
            LinuxNativeServiceChildLaunchClosureAuthority,
        ) -> Result<LinuxNativeServiceMechanicsAuthority, CgroupIoFailure> =
            retain_linux_native_service_mechanics_authority;
        let _ = (entry, admit, select, bind_setup, bind_child, retain);

        assert!(!JournaledLinuxProductionCommandPlanV1::permits_execution());
        assert!(!LinuxNativeServiceBootstrapAuthority::permits_execution());
        assert!(!LinuxNativeServiceAdmissionAuthority::permits_execution());
        assert!(!LinuxNativeServiceLaunchImageAuthority::permits_execution());
        assert!(!LinuxNativeServiceSetupDescriptorCapability::permits_execution());
        assert!(!LinuxNativeServiceSetupDescriptorAuthority::permits_execution());
        assert!(!LinuxNativeServiceChildLaunchClosureCapability::permits_execution());
        assert!(!LinuxNativeServiceChildLaunchClosureAuthority::permits_execution());
        assert!(!LinuxNativeServiceMechanicsAuthority::permits_execution());
    }
