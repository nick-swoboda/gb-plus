    // The live half of the per-command retained directories.
    //
    // Every directory below is a real directory on a real filesystem, created
    // through a descriptor the code under test holds and read back with real
    // `statx`, `fstatfs` and `getdents64`. The portable half in
    // `linux_command_plan::tests` varies kernel answers; this half produces
    // them.

    #[cfg(target_os = "linux")]
    static NEXT_PER_COMMAND_FIXTURE: AtomicU64 = AtomicU64::new(1);

    /// One anchored-service-state-root-shaped fixture: a `0700` state root and
    /// a `0755` workspace root, both owned by this process.
    #[cfg(target_os = "linux")]
    struct PerCommandFixture {
        path: PathBuf,
        state_root: Dir,
        workspace_root: Dir,
        owner_uid: u32,
    }

    #[cfg(target_os = "linux")]
    impl PerCommandFixture {
        fn new() -> Self {
            let unique = NEXT_PER_COMMAND_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("gb-per-command-{}-{unique}", std::process::id()));
            fs::create_dir(&path).unwrap();
            let path = fs::canonicalize(path).unwrap();
            let state = path.join("state");
            let workspace = path.join("workspace");
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(&workspace).unwrap();
            fs::set_permissions(&workspace, fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                state_root: Dir::open_ambient_dir(&state, ambient_authority()).unwrap(),
                workspace_root: Dir::open_ambient_dir(&workspace, ambient_authority()).unwrap(),
                owner_uid: rustix::process::geteuid().as_raw(),
                path,
            }
        }

        fn state_path(&self) -> PathBuf {
            self.path.join("state")
        }

        fn create(
            &self,
            name: &str,
        ) -> Result<LinuxRetainedPerCommandDirectories, CgroupIoFailure> {
            create_per_command_retained_directories(
                &self.state_root,
                &self.workspace_root,
                name,
                self.owner_uid,
            )
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for PerCommandFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// A name in the exact grammar `prepare_domain` mints leaf names with.
    #[cfg(target_os = "linux")]
    fn leaf_shaped_name(marker: u8) -> String {
        use crate::linux_containment::{DOMAIN_NAME_PREFIX, DOMAIN_NONCE_HEX_CHARS};
        let nonce = Digest::sha256(&[marker]).to_string();
        assert_eq!(nonce.len(), DOMAIN_NONCE_HEX_CHARS);
        let name = format!("{DOMAIN_NAME_PREFIX}{nonce}");
        assert!(crate::linux_containment::is_domain_leaf_name(&name));
        name
    }

    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear live run keeps every created directory, its independent path-based cross-check, and every refusal visible in the order they happen"
    )]
    #[test]
    fn the_per_command_retained_directories_are_created_and_observed_through_held_descriptors() {
        let fixture = PerCommandFixture::new();
        let name = leaf_shaped_name(1);

        // A name outside the grammar `prepare_domain` mints is refused before
        // anything at all is created.
        let refused = fixture
            .create("not-a-leaf-name")
            .expect_err("a name outside the leaf grammar must be refused");
        assert!(
            format!("{refused:?}").contains("name grammar prepare_domain mints"),
            "{refused:?}"
        );
        assert!(
            !fixture
                .state_path()
                .join(SERVICE_PER_COMMAND_RETAINED_ROOT)
                .exists(),
            "a refused name must not have created the container"
        );

        let created = fixture.create(&name).expect("the control creation mints");
        let identities = created.identities();
        assert_eq!(created.command_directory_name(), name);

        // Independent cross-check: the descriptor-based observation and a
        // path-based `std::fs` read of the same directories must agree. The
        // code under test never used a path; the test does, which is what makes
        // this a second opinion rather than a restatement.
        let root_path = fixture
            .state_path()
            .join(SERVICE_PER_COMMAND_RETAINED_ROOT)
            .join(&name);
        for (identity, relative) in [
            (identities.per_command_root(), None),
            (identities.execution_root(), Some(PER_COMMAND_EXECUTION_ROOT_NAME)),
            (identities.private_temp(), Some(PER_COMMAND_PRIVATE_TEMP_NAME)),
            (identities.output_spool(), Some(PER_COMMAND_OUTPUT_SPOOL_NAME)),
            (identities.git_mask(), Some(PER_COMMAND_GIT_MASK_NAME)),
        ] {
            let path = relative.map_or_else(|| root_path.clone(), |child| root_path.join(child));
            let metadata = fs::symlink_metadata(&path).expect("the directory exists by name");
            assert!(metadata.is_dir(), "{path:?}");
            let observed = identity.kernel_observation();
            assert_eq!(observed.inode, std::os::unix::fs::MetadataExt::ino(&metadata));
            assert_eq!(observed.device_id, std::os::unix::fs::MetadataExt::dev(&metadata));
            assert_eq!(
                observed.link_count,
                std::os::unix::fs::MetadataExt::nlink(&metadata)
            );
            assert_eq!(
                observed.mode & 0o7777,
                std::os::unix::fs::MetadataExt::mode(&metadata) & 0o7777
            );
            assert_eq!(observed.owner_uid, fixture.owner_uid);
            assert!(observed.mount_id != 0, "STATX_MNT_ID_UNIQUE is required");
        }

        // The exact modes and the exact link counts, measured rather than
        // assumed: a fresh directory has two links and the per-command root has
        // two plus its four children.
        assert_eq!(
            identities.per_command_root().kernel_observation().mode & 0o7777,
            LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE
        );
        assert_eq!(
            identities.per_command_root().kernel_observation().link_count,
            6
        );
        for identity in [
            identities.execution_root(),
            identities.private_temp(),
            identities.output_spool(),
        ] {
            assert_eq!(
                identity.kernel_observation().mode & 0o7777,
                LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE
            );
            assert_eq!(identity.kernel_observation().link_count, 2);
        }
        assert_eq!(
            identities.git_mask().kernel_observation().mode & 0o7777,
            LINUX_GIT_MASK_DIRECTORY_MODE
        );

        // The `.git` mask's filesystem magic is a live `fstatfs`, and an
        // independent path-based `statfs` must agree with it.
        let independent = rustix::fs::statfs(root_path.join(PER_COMMAND_GIT_MASK_NAME)).unwrap();
        #[expect(
            clippy::cast_sign_loss,
            reason = "statfs f_type is an unsigned filesystem magic typed i64 by the Linux ABI"
        )]
        let independent_magic = independent.f_type as u64;
        assert_eq!(
            identities.git_mask_observation().filesystem_magic,
            independent_magic
        );
        assert!(identities.git_mask_observation().entry_names.is_empty());

        // The same name a second time is a refusal: a per-command root that
        // already existed was not created for this command.
        let repeated = fixture
            .create(&name)
            .expect_err("a per-command root that already exists must be refused");
        assert!(
            format!("{repeated:?}").contains("already existed"),
            "{repeated:?}"
        );

        // A second command gets its own directories, and every identity
        // differs.
        let second = fixture
            .create(&leaf_shaped_name(2))
            .expect("a second command mints its own directories");
        assert_ne!(
            identities.git_mask().kernel_observation().inode,
            second.identities().git_mask().kernel_observation().inode
        );

        // Control: a state root that is not owner-private is refused, and the
        // same helper answers success for the private one above, so the
        // refusal is doing work rather than always being said.
        fs::set_permissions(fixture.state_path(), fs::Permissions::from_mode(0o755)).unwrap();
        let loose = fixture
            .create(&leaf_shaped_name(3))
            .expect_err("a state root that is not owner-private must be refused");
        assert!(
            format!("{loose:?}").contains("owner-private 0700 directory"),
            "{loose:?}"
        );
        fs::set_permissions(fixture.state_path(), fs::Permissions::from_mode(0o700)).unwrap();
        fixture
            .create(&leaf_shaped_name(4))
            .expect("the private state root still mints");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_git_mask_observation_is_a_live_measurement_of_emptiness_and_identity() {
        let fixture = PerCommandFixture::new();
        let name = leaf_shaped_name(11);
        let created = fixture.create(&name).expect("the control creation mints");
        let mask_path = fixture
            .state_path()
            .join(SERVICE_PER_COMMAND_RETAINED_ROOT)
            .join(&name)
            .join(PER_COMMAND_GIT_MASK_NAME);

        let destinations = BTreeSet::from(["/run/grok/live", "/work"]);
        let masks = created
            .mint_git_masks(&destinations)
            .expect("an empty mask mints for both project views");
        assert_eq!(masks.len(), 2);
        let committed = masks[0].expected_empty_observation_digest().clone();
        assert_eq!(masks[1].expected_empty_observation_digest(), &committed);

        // Enforced: a real file appears in the real directory. The mint refuses
        // rather than describing a mask that is no longer empty.
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(mask_path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o500)).unwrap();
        let populated = created
            .mint_git_masks(&destinations)
            .expect_err("a mask holding a real file must be refused");
        assert!(format!("{populated:?}").contains("is not empty"), "{populated:?}");

        // …and the observation names the entry it found, so the refusal is
        // about this directory rather than a generic one.
        let observed = observe_empty_git_mask_directory(
            &Dir::open_ambient_dir(&mask_path, ambient_authority()).unwrap(),
            "test-observe-populated-mask",
        )
        .expect("a populated directory still observes; it is the mint that refuses");
        assert_eq!(observed.entry_names, vec!["HEAD".to_owned()]);

        // Removing it restores the exact committed digest: the digest is a
        // function of the directory, not of when it was read.
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(mask_path.join("HEAD")).unwrap();
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o500)).unwrap();
        let restored = created
            .mint_git_masks(&destinations)
            .expect("an emptied mask mints again");
        assert_eq!(restored[0].expected_empty_observation_digest(), &committed);

        // Enforced: a subdirectory changes the kernel's own link count, which
        // refuses independently of the enumeration.
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(mask_path.join("objects")).unwrap();
        let subdirectory = created
            .mint_git_masks(&destinations)
            .expect_err("a mask holding a subdirectory must be refused");
        let text = format!("{subdirectory:?}");
        assert!(text.contains("is not empty"), "{text}");
        let with_subdirectory = observe_empty_git_mask_directory(
            &Dir::open_ambient_dir(&mask_path, ambient_authority()).unwrap(),
            "test-observe-mask-with-subdirectory",
        )
        .expect("the observation itself succeeds");
        assert_eq!(with_subdirectory.entry_names, vec!["objects".to_owned()]);
        assert_eq!(with_subdirectory.object.link_count, 3);

        // The kernel's own link count is the independent second answer: even
        // an enumeration that reported nothing is refused, because a directory
        // with a subdirectory does not have two links.
        let mut walk_says_empty = with_subdirectory.clone();
        walk_says_empty.entry_names.clear();
        assert!(
            walk_says_empty
                .require_empty()
                .expect_err("a real link count of 3 refuses on its own")
                .to_string()
                .contains("link count 3")
        );

        fs::remove_dir(mask_path.join("objects")).unwrap();
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o500)).unwrap();
        let final_masks = created
            .mint_git_masks(&destinations)
            .expect("the emptied mask mints once more");
        assert_eq!(final_masks[0].expected_empty_observation_digest(), &committed);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_per_command_root_link_count_states_which_children_it_holds() {
        let fixture = PerCommandFixture::new();
        let name = leaf_shaped_name(21);
        let created = fixture.create(&name).expect("the control creation mints");
        let root_path = fixture
            .state_path()
            .join(SERVICE_PER_COMMAND_RETAINED_ROOT)
            .join(&name);
        let root = Dir::open_ambient_dir(&root_path, ambient_authority()).unwrap();

        let control =
            observe_directory_kernel_facts(&root, "test-observe-per-command-root").unwrap();
        assert_eq!(control.link_count, 6);

        // A fifth directory appears. The mint refuses the observation set,
        // because the kernel's own count no longer states that the root holds
        // exactly the four directories the plan names.
        fs::create_dir(root_path.join("unexpected")).unwrap();
        let intruded =
            observe_directory_kernel_facts(&root, "test-observe-per-command-root").unwrap();
        assert_eq!(intruded.link_count, 7);

        let identities = created.identities();
        let observations = LinuxPerCommandDirectoryObservationsV1 {
            workspace_root: observe_directory_kernel_facts(
                &fixture.workspace_root,
                "test-observe-workspace",
            )
            .unwrap(),
            per_command_root: intruded,
            execution_root: identities.execution_root().kernel_observation(),
            private_temp: identities.private_temp().kernel_observation(),
            output_spool: identities.output_spool().kernel_observation(),
            git_mask: identities.git_mask_observation().clone(),
        };
        let refused = LinuxPerCommandRetainedDirectoriesV1::from_kernel_observations(
            &observations,
            fixture.owner_uid,
        )
        .expect_err("a per-command root holding a fifth directory must be refused");
        assert!(
            refused.to_string().contains("has link count 7"),
            "{refused:?}"
        );

        // Control again, with the intruder gone.
        fs::remove_dir(root_path.join("unexpected")).unwrap();
        let restored = LinuxPerCommandDirectoryObservationsV1 {
            per_command_root: observe_directory_kernel_facts(
                &root,
                "test-observe-per-command-root",
            )
            .unwrap(),
            ..observations
        };
        LinuxPerCommandRetainedDirectoriesV1::from_kernel_observations(
            &restored,
            fixture.owner_uid,
        )
        .expect("the restored observation set mints");
    }
