    // The live half of the descriptor-based `.git` mask mount.
    //
    // Every mount below is a real mount. `open_tree` clones the real `.git`
    // mask directory through the descriptor the code under test already holds
    // on it, `move_mount` attaches that descriptor over a real `.git` holding
    // real files, and the destination is read back out of the kernel with the
    // same five reads the mask observation uses.
    //
    // **The pinned image cannot reach the enforced half without
    // `CAP_SYS_ADMIN`.** `./scripts/linux-verify.sh` runs the suite in a
    // container with the default capability set, where `open_tree` answers
    // `EPERM`; the enforced arms below run under `--privileged`. That is not a
    // skipped test: the unprivileged arm is itself enforced, because it
    // requires the production code to **refuse** and requires the destination
    // to be untouched afterwards. Absence of the capability is never read as a
    // successful mount.

    /// A `.git` directory holding real content, so masking it is visible.
    #[cfg(target_os = "linux")]
    fn populated_git_directory(workspace: &Path) -> PathBuf {
        let git = workspace.join(GIT_MASK_DESTINATION_COMPONENT);
        fs::create_dir(&git).unwrap();
        fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::create_dir(git.join("objects")).unwrap();
        git
    }

    /// Path-based enumeration, independent of anything the code under test did.
    #[cfg(target_os = "linux")]
    fn names_at(path: &Path) -> Vec<String> {
        let mut names = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    /// Inode, device and link count of one name, read by path.
    ///
    /// Fully qualified rather than imported: `cap_fs_ext::MetadataExt` and
    /// `rustix::fs::MetadataExt` are both in scope in this module and both
    /// implement these methods for `std::fs::Metadata`.
    #[cfg(target_os = "linux")]
    fn path_identity(path: &Path) -> (u64, u64, u64) {
        use std::os::unix::fs::MetadataExt as UnixMetadataExt;
        let metadata = fs::symlink_metadata(path).unwrap();
        (
            UnixMetadataExt::ino(&metadata),
            UnixMetadataExt::dev(&metadata),
            UnixMetadataExt::nlink(&metadata),
        )
    }

    #[cfg(target_os = "linux")]
    fn detach(path: &Path) {
        rustix::mount::unmount(path, rustix::mount::UnmountFlags::DETACH).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_lines,
        reason = "one linear live run keeps the clone, the attach, every independent path-based cross-check and every refusal visible in the order they happen"
    )]
    #[test]
    fn the_git_mask_mount_is_cloned_and_attached_through_held_descriptors() {
        let fixture = PerCommandFixture::new();
        let workspace = fixture.path.join("workspace");
        let live_git = populated_git_directory(&workspace);
        assert_eq!(names_at(&live_git), vec!["HEAD", "objects"]);

        let name = leaf_shaped_name(31);
        let created = fixture.create(&name).expect("the control creation mints");
        let destinations = BTreeSet::from(["/work"]);
        let masks = created
            .mint_git_masks(&destinations)
            .expect("the empty mask mints for the project view");
        let mask = &masks[0];
        let per_command_root = fixture
            .state_path()
            .join(SERVICE_PER_COMMAND_RETAINED_ROOT)
            .join(&name);
        let mask_path = per_command_root.join(PER_COMMAND_GIT_MASK_NAME);

        // Link counts before anything is mounted, read by path so the numbers
        // are a second opinion rather than a restatement of the plan's own
        // observation.
        let mask_links_before = path_identity(&mask_path).2;
        let workspace_links_before = path_identity(&workspace).2;
        let root_links_before = path_identity(&per_command_root).2;
        assert_eq!(mask_links_before, 2);
        assert_eq!(root_links_before, 6);

        let cloned = match created.clone_git_mask_mount(mask) {
            Ok(cloned) => cloned,
            Err(refusal) => {
                // The gate's own container. `open_tree` is refused, the
                // production call reports it, and nothing was mounted: the
                // live `.git` still holds exactly what it held.
                let text = format!("{refusal:?}");
                assert!(
                    text.contains("open_tree could not clone the .git mask"),
                    "{text}"
                );
                assert_eq!(refusal.certainty, EffectCertainty::NotApplied);
                assert_eq!(names_at(&live_git), vec!["HEAD", "objects"]);
                assert_eq!(path_identity(&mask_path).2, mask_links_before);
                return;
            }
        };

        // The clone is a real, new mount rooted at the very directory the mask
        // digested: same inode, same device, same mode, same owner, same link
        // count, and a unique mount identity the kernel has not used before.
        let directory = created.identities().git_mask_observation().clone();
        let clone = cloned.observation().clone();
        assert_eq!(clone.object.inode, directory.object.inode);
        assert_eq!(clone.object.device_id, directory.object.device_id);
        assert_eq!(clone.object.mode, directory.object.mode);
        assert_eq!(clone.object.owner_uid, directory.object.owner_uid);
        assert_eq!(clone.object.link_count, directory.object.link_count);
        assert_eq!(clone.filesystem_magic, directory.filesystem_magic);
        assert!(clone.entry_names.is_empty());
        assert_ne!(clone.object.mount_id, directory.object.mount_id);
        assert!(clone.object.mount_id != 0 && directory.object.mount_id != 0);
        assert_eq!(
            cloned.binding().detached_mount_id(),
            clone.object.mount_id,
            "the binding commits to the clone's own mount identity"
        );
        assert_eq!(
            cloned.binding().source_mount_id(),
            directory.object.mount_id
        );

        // Enforced: the mount is attached over a real, populated `.git`
        // through the descriptor the caller holds on the workspace.
        let workspace_dir = Dir::open_ambient_dir(&workspace, ambient_authority()).unwrap();
        let attached = attach_git_mask_mount(cloned, &workspace_dir)
            .expect("the cloned mount attaches and is recognised at its destination");

        // The destination is the clone, measured again at the destination.
        assert_eq!(attached.destination().object.mount_id, clone.object.mount_id);
        assert_eq!(attached.destination().object.inode, clone.object.inode);
        assert!(attached.destination().entry_names.is_empty());

        // Independent, path-based: the project's real `.git` content is gone
        // from the namespace and the inode at that name is the mask's.
        assert!(names_at(&live_git).is_empty());
        assert!(!live_git.join("HEAD").exists());
        assert_eq!(path_identity(&live_git).0, directory.object.inode);

        // Link counts under mount, measured because `link_count == 2` is
        // load-bearing for the retained directories: mounting changes none of
        // them.
        assert_eq!(path_identity(&mask_path).2, mask_links_before);
        assert_eq!(path_identity(&workspace).2, workspace_links_before);
        assert_eq!(path_identity(&per_command_root).2, root_links_before);
        assert_eq!(attached.destination().object.link_count, 2);

        // Enforced, and the sharpest arm: a **second** clone of the very same
        // directory attached at a second destination. Every field agrees,
        // same inode, same device, same mode, still empty, and the first
        // binding still refuses it, because the kernel does not reuse a unique
        // mount identity.
        let second_workspace = fixture.path.join("second-workspace");
        fs::create_dir(&second_workspace).unwrap();
        fs::set_permissions(&second_workspace, fs::Permissions::from_mode(0o755)).unwrap();
        let second_git = populated_git_directory(&second_workspace);
        let second_clone = created
            .clone_git_mask_mount(mask)
            .expect("a second clone of the same directory is a second mount");
        assert_eq!(
            second_clone.observation().object.inode,
            clone.object.inode,
            "both clones are rooted at one directory"
        );
        assert_ne!(
            second_clone.observation().object.mount_id,
            clone.object.mount_id,
            "two clones are two mounts"
        );
        let second_dir = Dir::open_ambient_dir(&second_workspace, ambient_authority()).unwrap();
        let second_attached = attach_git_mask_mount(second_clone, &second_dir)
            .expect("the second clone attaches at its own destination");
        let crossed = attached
            .binding()
            .require_attached_mount(second_attached.destination())
            .expect_err("one mask mount's binding must refuse another mount of the same directory");
        assert!(
            crossed.to_string().contains("unique mount identity"),
            "{crossed}"
        );

        // Why `attach_git_mask_mount` consumes its mount, measured rather than
        // asserted: `move_mount` on an already-attached mount is a **move**.
        // Performed here with the raw syscall on a descriptor the test opens
        // itself, because the production API makes it inexpressible.
        let stolen = rustix::mount::open_tree(
            Dir::open_ambient_dir(&mask_path, ambient_authority()).unwrap(),
            "",
            rustix::mount::OpenTreeFlags::AT_EMPTY_PATH
                | rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
        )
        .unwrap();
        let third_workspace = fixture.path.join("third-workspace");
        fs::create_dir(&third_workspace).unwrap();
        let third_git = populated_git_directory(&third_workspace);
        let fourth_workspace = fixture.path.join("fourth-workspace");
        fs::create_dir(&fourth_workspace).unwrap();
        let fourth_git = populated_git_directory(&fourth_workspace);
        for destination in [&third_git, &fourth_git] {
            rustix::mount::move_mount(
                &stolen,
                "",
                rustix::fs::CWD,
                destination.as_path(),
                rustix::mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )
            .unwrap();
        }
        assert_eq!(
            names_at(&third_git),
            vec!["HEAD", "objects"],
            "the first destination was silently vacated, which is why the mount is consumed"
        );
        assert!(names_at(&fourth_git).is_empty());
        detach(&fourth_git);

        // Control after enforcement: detach, and the project's own `.git` is
        // back, and the binding refuses that observation, because it is a
        // different directory entirely.
        detach(&live_git);
        assert_eq!(names_at(&live_git), vec!["HEAD", "objects"]);
        let unmasked = observe_empty_git_mask_directory(
            &workspace_dir
                .open_dir_nofollow(GIT_MASK_DESTINATION_COMPONENT)
                .unwrap(),
            "test-observe-unmasked-git",
        )
        .expect("the project's own .git still observes; it is the binding that refuses");
        assert_eq!(unmasked.entry_names, vec!["HEAD", "objects"]);
        assert!(
            attached
                .binding()
                .require_attached_mount(&unmasked)
                .expect_err("the project's own .git is not this mount")
                .to_string()
                .contains("is not empty")
        );

        detach(&second_git);
    }

    /// The mask's own emptiness proof survives being mounted, and the binding
    /// is what carries it across.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_mounted_object_is_the_directory_the_mask_digested() {
        let fixture = PerCommandFixture::new();
        let workspace = fixture.path.join("workspace");
        let live_git = populated_git_directory(&workspace);
        let name = leaf_shaped_name(41);
        let created = fixture.create(&name).expect("the control creation mints");
        let destinations = BTreeSet::from(["/work"]);
        let masks = created.mint_git_masks(&destinations).expect("the mask mints");
        let mask = &masks[0];

        let Ok(cloned) = created.clone_git_mask_mount(mask) else {
            // Unprivileged: there is no mount, so there is nothing to bind and
            // the production call said so. That arm is enforced above.
            return;
        };

        // The binding carries the mask's own committed digest unchanged, so
        // the two are provably about one directory rather than two.
        assert_eq!(
            cloned.binding().directory_observation_digest(),
            mask.expected_empty_observation_digest()
        );
        assert_eq!(
            cloned.binding().masked_destination(),
            mask.masked_destination()
        );

        // Enforced: a real file appears in the real mask directory *after* the
        // clone. The clone's own root is that same inode, so reading the mount
        // at its destination refuses, the emptiness proof is not a snapshot
        // the mount can outlive.
        let mask_path = fixture
            .state_path()
            .join(SERVICE_PER_COMMAND_RETAINED_ROOT)
            .join(&name)
            .join(PER_COMMAND_GIT_MASK_NAME);
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(mask_path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o500)).unwrap();

        let workspace_dir = Dir::open_ambient_dir(&workspace, ambient_authority()).unwrap();
        let populated = attach_git_mask_mount(cloned, &workspace_dir)
            .expect_err("a mount whose root gained an entry must be refused at its destination");
        assert!(format!("{populated:?}").contains("is not empty"), "{populated:?}");

        // The mount was performed, `move_mount` returned before the
        // destination was read, so the refusal is `Ambiguous` and the
        // detached content really is at the destination. That is the honest
        // report: the call refuses to say the destination is the empty
        // directory it committed to, and does not pretend nothing happened.
        assert_eq!(populated.certainty, EffectCertainty::Ambiguous);
        assert_eq!(names_at(&live_git), vec!["HEAD"]);
        detach(&live_git);
        assert_eq!(names_at(&live_git), vec!["HEAD", "objects"]);

        // Control again: emptied, a fresh clone attaches and is recognised.
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(mask_path.join("HEAD")).unwrap();
        fs::set_permissions(&mask_path, fs::Permissions::from_mode(0o500)).unwrap();
        let restored = created
            .clone_git_mask_mount(mask)
            .expect("the emptied mask clones again");
        let attached = attach_git_mask_mount(restored, &workspace_dir)
            .expect("the restored mount is recognised at its destination");
        assert!(attached.destination().entry_names.is_empty());
        assert!(names_at(&live_git).is_empty());
        detach(&live_git);
    }
