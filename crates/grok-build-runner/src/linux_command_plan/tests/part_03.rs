    // The portable half of the per-command retained directories.
    //
    // The same split the setup-channel mint and the linkage prover use: this
    // file varies one kernel answer at a time and requires a named refusal, and
    // the live half in `linux_cgroup_io::tests` creates real directories and
    // reads them with real syscalls. Nothing here performs I/O, which is the
    // point, the crossing and collapse refusals stay provable on a host with
    // no Linux kernel in front of them.

    /// `overlayfs`, measured with `stat -f` inside `gbd-linux:1.97.0`, which is
    /// what `/tmp` is in the pinned image and therefore what the live half
    /// reads.
    const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

    /// The uid every fixture object below is owned by.
    const FIXTURE_OWNER_UID: u32 = 1_000;

    fn directory_observation(
        device_id: u64,
        inode: u64,
        mount_id: u64,
        mode: u32,
        link_count: u64,
    ) -> LinuxKernelObjectObservationV1 {
        LinuxKernelObjectObservationV1 {
            device_id,
            inode,
            mount_id,
            mode: DIRECTORY_MODE | mode,
            owner_uid: FIXTURE_OWNER_UID,
            owner_gid: FIXTURE_OWNER_UID,
            link_count,
            byte_length: None,
        }
    }

    /// The control `.git`-mask observation: one empty directory, `0500`, two
    /// links, on overlayfs.
    fn mask_observation() -> LinuxGitMaskEmptyDirectoryObservationV1 {
        LinuxGitMaskEmptyDirectoryObservationV1 {
            object: directory_observation(77, 5_004, 7, LINUX_GIT_MASK_DIRECTORY_MODE, 2),
            filesystem_magic: OVERLAYFS_SUPER_MAGIC,
            entry_names: Vec::new(),
        }
    }

    fn mask_identity(
        observation: &LinuxGitMaskEmptyDirectoryObservationV1,
    ) -> LinuxRetainedObjectIdentityV1 {
        LinuxRetainedObjectIdentityV1::from_kernel_observation(
            GIT_MASK_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            observation.object,
        )
        .expect("the control mask observation is an admissible retained identity")
    }

    /// The control per-command observation set: a workspace root on one
    /// filesystem and five service-created directories on another.
    fn per_command_observations() -> LinuxPerCommandDirectoryObservationsV1 {
        LinuxPerCommandDirectoryObservationsV1 {
            workspace_root: directory_observation(55, 9_001, 5, 0o755, 9),
            per_command_root: directory_observation(
                77,
                5_000,
                7,
                LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
                6,
            ),
            execution_root: directory_observation(
                77,
                5_001,
                7,
                LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
                2,
            ),
            private_temp: directory_observation(
                77,
                5_002,
                7,
                LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
                2,
            ),
            output_spool: directory_observation(
                77,
                5_003,
                7,
                LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
                2,
            ),
            git_mask: mask_observation(),
        }
    }

    fn mint_per_command() -> LinuxPerCommandRetainedDirectoriesV1 {
        LinuxPerCommandRetainedDirectoriesV1::from_kernel_observations(
            &per_command_observations(),
            FIXTURE_OWNER_UID,
        )
        .expect("the control per-command observation set mints")
    }

    #[test]
    fn the_git_mask_observation_descriptor_is_one_ascii_line() {
        let descriptor = LINUX_GIT_MASK_EMPTY_OBSERVATION_DESCRIPTOR_V1;
        assert!(
            !descriptor.contains('\n'),
            "line 0 of every observation is this text verbatim, so it may not contain a line feed"
        );
        assert!(
            descriptor
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' '),
            "the descriptor must be printable ASCII"
        );
        assert!(descriptor.starts_with("grok-build.linux-git-mask-empty-observation.v1"));
        // The day someone compares the wrong two protocol digests is the day
        // this assertion earns its place.
        assert_ne!(
            linux_git_mask_empty_observation_protocol_digest(),
            linux_setup_channel_protocol_digest()
        );
        // The digest is taken over the descriptor bytes, not over a compiled
        // copy of a number.
        assert_eq!(
            linux_git_mask_empty_observation_protocol_digest(),
            Digest::sha256(descriptor.as_bytes())
        );
        // Pinned, so a change to the framing or the read set fails a test
        // rather than quietly minting a different protocol under the same name.
        assert_eq!(descriptor.len(), 689);
        assert_eq!(
            linux_git_mask_empty_observation_protocol_digest().to_string(),
            "ff5c820267e28ad4899b05001a1d74827c3c15680bb26ea3667208cd79538ddb"
        );
    }

    #[test]
    fn the_retained_object_line_encoder_is_shared_with_the_setup_channel() {
        // One spelling of the nine-field object line in the workspace. If the
        // two ever diverged, a digest taken under one contract could be
        // compared under the other.
        let observation = mask_observation();
        let identity = mask_identity(&observation);
        let line = encode_retained_object_line(&identity);
        assert_eq!(
            line,
            format!(
                "{GIT_MASK_OBJECT_ID}:directory:77:5004:7:{:o}:{FIXTURE_OWNER_UID}:{FIXTURE_OWNER_UID}:2",
                DIRECTORY_MODE | LINUX_GIT_MASK_DIRECTORY_MODE
            )
        );
        let encoded = observation
            .encode(&identity)
            .expect("the control observation encodes");
        let text = String::from_utf8(encoded).expect("the observation is ASCII");
        assert!(text.contains(&format!("\n{line}\n")));
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some(LINUX_GIT_MASK_EMPTY_OBSERVATION_DESCRIPTOR_V1)
        );
        assert_eq!(lines.next(), Some("format=1"));
        assert_eq!(lines.next(), Some(line.as_str()));
        assert_eq!(lines.next(), Some("filesystem-magic=0x794c7630"));
        assert_eq!(lines.next(), Some("entry-count=0"));
        assert_eq!(lines.next(), Some("end"));
        assert_eq!(lines.next(), None);
        assert!(text.ends_with("end\n"));
        // Pinned for the same reason the setup channel's encoding is: a change
        // to the field order or the framing fails here rather than silently
        // producing a different digest under the same descriptor.
        assert_eq!(text.len(), 792);
        assert_eq!(
            observation
                .digest(&identity)
                .expect("the control observation digests")
                .to_string(),
            "c7889355ef5c92ee3136ad70f53f43528288fa80c5bd28e4bf394fcc9994cf19"
        );
    }

    #[test]
    fn the_git_mask_digest_binds_the_directory_identity_and_not_only_its_emptiness() {
        // If the digest were a function of "empty" alone it would be a
        // constant, and a constant in a `Digest` field is the fabricated-digest
        // shape schema v3 removed. Every one of these varies exactly one field
        // of the identity, keeps the directory empty, and must produce a
        // different digest.
        let control = mask_observation();
        let control_digest = control
            .digest(&mask_identity(&control))
            .expect("the control observation digests");

        let mut digests = BTreeSet::from([control_digest.to_string()]);
        for mutate in [
            (|observed: &mut LinuxKernelObjectObservationV1| observed.inode += 1)
                as fn(&mut LinuxKernelObjectObservationV1),
            |observed| observed.device_id += 1,
            |observed| observed.mount_id += 1,
            |observed| observed.owner_uid += 1,
            |observed| observed.owner_gid += 1,
            |observed| observed.mode = DIRECTORY_MODE | 0o700,
        ] {
            let mut varied = control.clone();
            mutate(&mut varied.object);
            let digest = varied
                .digest(&mask_identity(&varied))
                .expect("a varied identity still encodes");
            assert!(
                digests.insert(digest.to_string()),
                "varying one identity field must change the observation digest"
            );
        }
        assert_eq!(digests.len(), 7);

        // The names are in the digest, not only the count: two directories
        // holding one entry each must not digest alike.
        let mut head = control.clone();
        head.entry_names = vec!["HEAD".to_owned()];
        let mut config = control.clone();
        config.entry_names = vec!["config".to_owned()];
        let identity = mask_identity(&control);
        assert_ne!(
            head.digest(&identity).expect("HEAD encodes"),
            config.digest(&identity).expect("config encodes")
        );
        // …and both are refused before they can become a mask.
        for populated in [&head, &config] {
            assert!(
                populated
                    .require_empty()
                    .expect_err("a populated directory is not an empty one")
                    .to_string()
                    .contains("is not empty")
            );
        }

        // The filesystem the mask sits on is in the digest too, so a mask on
        // the same inode number of another filesystem is a different answer.
        let mut other_filesystem = control.clone();
        other_filesystem.filesystem_magic = 0x0102_0304;
        assert_ne!(
            other_filesystem
                .digest(&identity)
                .expect("another filesystem encodes"),
            control_digest
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one linear refusal set keeps every varied kernel answer and its named refusal visible together"
    )]
    #[test]
    fn the_git_mask_mint_refuses_every_substitution_of_its_observation() {
        let control = mask_observation();
        let control_mask = LinuxGitMaskV1::from_empty_directory_observation(
            "/run/grok/live",
            &mask_identity(&control),
            &control,
        )
        .expect("the control mask mints");
        assert_eq!(control_mask.masked_destination, "/run/grok/live/.git");
        assert_eq!(control_mask.empty_directory_object_id, GIT_MASK_OBJECT_ID);

        let mut refusals = BTreeSet::new();
        let mut refuse = |destination: &str,
                          identity: &LinuxRetainedObjectIdentityV1,
                          observation: &LinuxGitMaskEmptyDirectoryObservationV1,
                          fragment: &str| {
            let error =
                LinuxGitMaskV1::from_empty_directory_observation(destination, identity, observation)
                    .expect_err("the varied input must be refused")
                    .to_string();
            assert!(
                error.contains(fragment),
                "refusal {error:?} does not name {fragment:?}"
            );
            assert!(
                refusals.insert(error),
                "two arms are being served by one catch-all refusal"
            );
        };

        let identity = mask_identity(&control);

        let mut populated = control.clone();
        populated.entry_names = vec!["HEAD".to_owned()];
        refuse("/run/grok/live", &identity, &populated, "is not empty");

        for (links, fragment) in [(1_u64, "link count 1"), (3, "link count 3")] {
            let mut varied = control.clone();
            varied.object.link_count = links;
            let varied_identity = LinuxRetainedObjectIdentityV1::from_kernel_observation(
                GIT_MASK_OBJECT_ID,
                LinuxRetainedObjectKindV1::Directory,
                varied.object,
            );
            match varied_identity {
                Ok(minted) => refuse("/run/grok/live", &minted, &varied, fragment),
                Err(error) => {
                    // `link_count == 0` is refused by the object table itself;
                    // 1 and 3 reach the mask mint, which is what this arm
                    // requires.
                    panic!("link count {links} must reach the mask mint, not {error}");
                }
            }
        }

        let mut group_writable = control.clone();
        group_writable.object.mode = DIRECTORY_MODE | 0o520;
        refuse(
            "/run/grok/live",
            &mask_identity(&group_writable),
            &group_writable,
            "group-writable",
        );

        let mut setgid = control.clone();
        setgid.object.mode = DIRECTORY_MODE | 0o2500;
        refuse(
            "/run/grok/live",
            &mask_identity(&setgid),
            &setgid,
            "setuid or setgid",
        );

        let mut no_magic = control.clone();
        no_magic.filesystem_magic = 0;
        refuse(
            "/run/grok/live",
            &mask_identity(&no_magic),
            &no_magic,
            "no filesystem magic",
        );

        // The identity and the observation describe two different directories.
        let mut crossed = control.clone();
        crossed.object.inode += 1;
        refuse(
            "/run/grok/live",
            &identity,
            &crossed,
            "describes a different kernel object",
        );

        // A mask replacement that is not a plain directory.
        let sealed = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            GIT_MASK_OBJECT_ID,
            LinuxRetainedObjectKindV1::SealedMemfd,
            LinuxKernelObjectObservationV1 {
                link_count: 0,
                byte_length: Some(64),
                mode: REGULAR_FILE_MODE | 0o400,
                ..control.object
            },
        )
        .expect("a sealed memfd identity is admissible on its own");
        refuse(
            "/run/grok/live",
            &sealed,
            &control,
            "plain retained directory",
        );

        for (destination, fragment) in [
            ("run/grok/live", "normalized absolute"),
            ("", "normalized absolute"),
            ("/run/grok/live/", "normalized absolute"),
            ("/run/grok/../live", "normalized absolute"),
        ] {
            let error = LinuxGitMaskV1::from_empty_directory_observation(
                destination,
                &identity,
                &control,
            )
            .expect_err("a destination outside the bound must be refused")
            .to_string();
            assert!(error.contains(fragment), "refusal {error:?}");
        }
        let already_masked = LinuxGitMaskV1::from_empty_directory_observation(
            "/run/grok/live/.git",
            &identity,
            &control,
        )
        .expect_err("a destination already inside .git must be refused")
        .to_string();
        assert!(already_masked.contains("already enter .git"));

        let mut unsorted = control.clone();
        unsorted.entry_names = vec!["b".to_owned(), "a".to_owned()];
        assert!(
            unsorted
                .encode(&identity)
                .expect_err("an unsorted enumeration cannot be encoded")
                .to_string()
                .contains("unsorted or carries a duplicate")
        );

        let mut at_bound = control.clone();
        at_bound.entry_names = (0..MAX_LINUX_GIT_MASK_OBSERVATION_ENTRIES)
            .map(|index| format!("entry-{index:04}"))
            .collect();
        assert!(
            at_bound
                .encode(&identity)
                .expect_err("reaching the hard bound is a refusal, not a truncation")
                .to_string()
                .contains("hard bound")
        );

        let mut unprintable = control.clone();
        unprintable.entry_names = vec!["with space".to_owned()];
        assert!(
            unprintable
                .encode(&identity)
                .expect_err("a name that cannot be framed is a refusal")
                .to_string()
                .contains("printable ASCII component")
        );

        // Control again, so every refusal above is attributable to the value
        // that was varied rather than to drift in the fixture.
        let repeated = LinuxGitMaskV1::from_empty_directory_observation(
            "/run/grok/live",
            &mask_identity(&control),
            &control,
        )
        .expect("the control mask still mints");
        assert_eq!(repeated, control_mask);
        assert!(refusals.len() >= 8);
    }

    #[test]
    fn the_git_mask_requires_a_second_observation_to_reproduce_its_digest() {
        let first = mask_observation();
        let identity = mask_identity(&first);
        let mask =
            LinuxGitMaskV1::from_empty_directory_observation("/run/grok/live", &identity, &first)
                .expect("the control mask mints");

        // Two independent reads of an unchanged directory agree, which is what
        // makes the comparison a check rather than a tautology about one read.
        mask.require_empty_directory_observation(&identity, &mask_observation())
            .expect("an unchanged directory re-observes identically");

        let mut gained_an_entry = first.clone();
        gained_an_entry.entry_names = vec!["HEAD".to_owned()];
        gained_an_entry.object.link_count = 2;
        assert!(
            mask.require_empty_directory_observation(&identity, &gained_an_entry)
                .expect_err("a directory that gained an entry must refuse")
                .to_string()
                .contains("is not empty")
        );

        let mut replaced = first.clone();
        replaced.object.inode += 1;
        let replaced_identity = mask_identity(&replaced);
        assert!(
            mask.require_empty_directory_observation(&replaced_identity, &replaced)
                .expect_err("a replaced directory must refuse")
                .to_string()
                .contains("now observes as")
        );

        let mut remounted = first.clone();
        remounted.object.mount_id += 1;
        assert!(
            mask.require_empty_directory_observation(&mask_identity(&remounted), &remounted)
                .expect_err("a directory that crossed a mount must refuse")
                .to_string()
                .contains("now observes as")
        );

        let renamed = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            "another-role",
            LinuxRetainedObjectKindV1::Directory,
            first.object,
        )
        .expect("a directory identity under another role is admissible on its own");
        assert!(
            mask.require_empty_directory_observation(&renamed, &first)
                .expect_err("a mask cannot be re-observed through another role")
                .to_string()
                .contains("re-observed through another-role")
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one linear refusal set keeps every varied kernel answer and its named refusal visible together"
    )]
    #[test]
    fn the_per_command_retained_directory_mint_refuses_every_crossed_observation() {
        let control = mint_per_command();
        assert_eq!(control.workspace_root().object_id(), WORKSPACE_ROOT_OBJECT_ID);
        assert_eq!(
            control.per_command_root().object_id(),
            PER_COMMAND_RETAINED_ROOT_OBJECT_ID
        );

        let mut refusals = BTreeSet::new();
        let mut refuse = |mutate: &dyn Fn(&mut LinuxPerCommandDirectoryObservationsV1),
                          fragment: &str| {
            let mut varied = per_command_observations();
            mutate(&mut varied);
            let error = LinuxPerCommandRetainedDirectoriesV1::from_kernel_observations(
                &varied,
                FIXTURE_OWNER_UID,
            )
            .expect_err("the varied observation set must be refused")
            .to_string();
            assert!(
                error.contains(fragment),
                "refusal {error:?} does not name {fragment:?}"
            );
            assert!(
                refusals.insert(error),
                "two arms are being served by one catch-all refusal"
            );
        };

        refuse(
            &|observations| observations.execution_root.mode = DIRECTORY_MODE | 0o755,
            "carries mode 755",
        );
        refuse(
            &|observations| observations.private_temp.owner_uid = FIXTURE_OWNER_UID + 1,
            "rather than the anchored service uid",
        );
        refuse(
            &|observations| observations.per_command_root.link_count = 5,
            "has link count 5",
        );
        refuse(
            &|observations| observations.output_spool.link_count = 3,
            "has link count 3",
        );
        refuse(
            &|observations| observations.execution_root.device_id += 1,
            "not on the per-command root's device and mount",
        );
        refuse(
            &|observations| {
                observations.git_mask.object.mount_id += 1;
            },
            "not on the per-command root's device and mount",
        );
        refuse(
            &|observations| {
                observations.output_spool.inode = observations.private_temp.inode;
            },
            "roles private-temp and output-spool resolved to one kernel inode",
        );
        refuse(
            &|observations| {
                observations.git_mask.object.mode =
                    DIRECTORY_MODE | LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE;
            },
            "the plan requires exactly 500",
        );
        refuse(
            &|observations| observations.git_mask.entry_names = vec!["HEAD".to_owned()],
            "is not empty",
        );
        refuse(
            &|observations| observations.git_mask.object.link_count = 3,
            "link count 3",
        );
        refuse(
            &|observations| observations.workspace_root.mode = DIRECTORY_MODE | 0o777,
            "workspace root is group-writable or world-writable",
        );
        refuse(
            &|observations| observations.workspace_root.owner_uid = FIXTURE_OWNER_UID + 1,
            "workspace root is owned by uid 1001",
        );
        refuse(
            &|observations| {
                observations.workspace_root.device_id = observations.per_command_root.device_id;
                observations.workspace_root.inode = observations.per_command_root.inode;
            },
            "roles workspace-root and per-command-root resolved to one kernel inode",
        );
        refuse(
            &|observations| observations.per_command_root.device_id = 0,
            "zero device, inode, or mount identity",
        );

        // Control again.
        let repeated = mint_per_command();
        assert_eq!(repeated, control);
        assert!(refusals.len() >= 10);
    }

    #[test]
    fn the_per_command_retained_directories_bind_their_plan_roles() {
        let directories = mint_per_command();

        // A read-only worker executes in the live workspace; the shadow and
        // snapshot views execute in the directory the service created. This is
        // the rule `validate_mounts` enforces, stated once here.
        assert_eq!(
            directories
                .execution_root_for(LinuxExecutionViewV1::WorkerReadOnly)
                .object_id(),
            WORKSPACE_ROOT_OBJECT_ID
        );
        for view in [
            LinuxExecutionViewV1::WorkerShadow,
            LinuxExecutionViewV1::FinalVerifierSnapshot,
        ] {
            assert_eq!(
                directories.execution_root_for(view).object_id(),
                EXECUTION_ROOT_OBJECT_ID
            );
        }

        let objects = directories.retained_objects();
        assert_eq!(objects.len(), 6);
        let ids = objects
            .iter()
            .map(|object| object.object_id().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), 6);
        assert!(ids.contains(PRIVATE_TEMP_OBJECT_ID));
        assert!(ids.contains(OUTPUT_SPOOL_OBJECT_ID));
        assert!(ids.contains(GIT_MASK_OBJECT_ID));
        assert!(objects.windows(2).all(|pair| pair[0].object_id() < pair[1].object_id()));
        for object in &objects {
            object
                .validate()
                .expect("every minted object satisfies the plan's own object-table validator");
        }

        // One empty directory serves every project view, so the digests are
        // equal by construction, and that is a measurement of one inode, not
        // a constant: another command's mask digests differently.
        let destinations = BTreeSet::from(["/run/grok/live", "/work"]);
        let masks = directories
            .git_masks_for(&destinations)
            .expect("two project views produce two masks");
        assert_eq!(masks.len(), 2);
        assert_eq!(masks[0].workspace_destination, "/run/grok/live");
        assert_eq!(masks[1].workspace_destination, "/work");
        assert_eq!(masks[0].masked_destination, "/run/grok/live/.git");
        assert_eq!(
            masks[0].expected_empty_observation_digest,
            masks[1].expected_empty_observation_digest
        );

        let mut other_command = per_command_observations();
        other_command.git_mask.object.inode += 100;
        let other = LinuxPerCommandRetainedDirectoriesV1::from_kernel_observations(
            &other_command,
            FIXTURE_OWNER_UID,
        )
        .expect("a second command's directory set mints");
        let other_masks = other
            .git_masks_for(&destinations)
            .expect("the second command's masks mint");
        assert_ne!(
            masks[0].expected_empty_observation_digest,
            other_masks[0].expected_empty_observation_digest,
            "two commands' masks are two inodes and must not digest alike"
        );

        directories
            .require_masks_still_observe(&masks, &mask_observation())
            .expect("an unchanged mask re-observes identically");
        let mut changed = mask_observation();
        changed.entry_names = vec!["HEAD".to_owned()];
        assert!(
            directories
                .require_masks_still_observe(&masks, &changed)
                .expect_err("a mask that gained an entry must refuse")
                .to_string()
                .contains("is not empty")
        );
        assert!(
            directories
                .require_masks_still_observe(&[], &mask_observation())
                .expect_err("an empty mask set proves nothing")
                .to_string()
                .contains("proves nothing")
        );
        assert!(
            directories
                .git_masks_for(&BTreeSet::new())
                .expect_err("a mount plan with no project view has no mask set")
                .to_string()
                .contains("at least one")
        );
    }
