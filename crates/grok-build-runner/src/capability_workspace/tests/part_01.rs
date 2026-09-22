    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-capability-workspace-{label}-{}-{sequence}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn issue_grant(root: &Path) -> IssuedWorkspaceGrant {
        WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "capability-workspace-test-grant".into(),
            workspace_root: root.to_path_buf(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .unwrap()
    }

    fn private_directory(path: &Path) {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn retained_capabilities_capture_copy_and_stage_nested_changes() {
        let top = TestDirectory::new("pipeline");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::create_dir(live.join("src")).unwrap();
        fs::write(live.join("src/lib.rs"), b"before\n").unwrap();
        let store_path = top.0.join("store");
        private_directory(&store_path);
        let live = fs::canonicalize(live).unwrap();
        let grant = issue_grant(&live);
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let mut shadow = workspace
            .create_shadow(&grant, &base, &store, "sprint-one")
            .unwrap();

        fs::write(shadow.root().join("src/lib.rs"), b"after\n").unwrap();
        fs::create_dir(shadow.root().join("docs")).unwrap();
        fs::write(shadow.root().join("docs/report.txt"), b"report\n").unwrap();
        let staged = shadow.stage_changes(&grant, "capability-stage", 2).unwrap();

        assert_eq!(staged.change_set().operations.len(), 2);
        assert_eq!(
            staged.change_set().base_snapshot,
            base.snapshot().snapshot_id
        );
        assert_eq!(
            staged.change_set().result_snapshot,
            shadow.capture(&grant, 2).unwrap().snapshot().snapshot_id
        );
        assert_eq!(fs::read(live.join("src/lib.rs")).unwrap(), b"before\n");
        assert!(!live.join("docs/report.txt").exists());
    }

    #[test]
    fn verified_noop_staging_emits_the_exact_empty_contract() {
        let top = TestDirectory::new("verified-noop");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("input.txt"), b"unchanged\n").unwrap();
        let store_path = top.0.join("store");
        private_directory(&store_path);
        let live = fs::canonicalize(live).unwrap();
        let grant = issue_grant(&live);
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let base_snapshot = base.snapshot().snapshot_id.clone();
        let mut shadow = workspace
            .create_shadow(&grant, &base, &store, "verified-noop")
            .unwrap();

        let staged = shadow
            .stage_changes_or_verified_noop(&grant, "no-op-change-set", 2)
            .unwrap();

        assert_eq!(staged.change_set().change_set_id, "no-op-change-set");
        assert_eq!(staged.change_set().base_snapshot, base_snapshot);
        assert_eq!(
            staged.change_set().result_snapshot,
            staged.change_set().base_snapshot
        );
        assert!(staged.change_set().operations.is_empty());
        assert!(staged.blobs().is_empty());

        let deterministic = shadow
            .stage_changes_or_verified_noop(&grant, "", 3)
            .unwrap();
        assert_eq!(
            deterministic.change_set().change_set_id,
            deterministic_change_set_id(&base_snapshot, &base_snapshot, &[])
        );
    }

    #[test]
    fn verified_noop_staging_never_collapses_a_changed_shadow() {
        let top = TestDirectory::new("verified-change");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("input.txt"), b"before\n").unwrap();
        let store_path = top.0.join("store");
        private_directory(&store_path);
        let live = fs::canonicalize(live).unwrap();
        let grant = issue_grant(&live);
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let mut shadow = workspace
            .create_shadow(&grant, &base, &store, "verified-change")
            .unwrap();
        fs::write(shadow.root().join("input.txt"), b"after\n").unwrap();

        let staged = shadow
            .stage_changes_or_verified_noop(&grant, "changed-change-set", 2)
            .unwrap();

        assert_ne!(
            staged.change_set().base_snapshot,
            staged.change_set().result_snapshot
        );
        assert_eq!(staged.change_set().operations.len(), 1);
        assert!(matches!(
            &staged.change_set().operations[0],
            FileOperation::Modify { path, .. } if path == Path::new("input.txt")
        ));
        assert_eq!(staged.blobs().len(), 1);
    }

    #[test]
    fn verifier_reopens_only_the_exact_complete_shadow_snapshot() {
        let top = TestDirectory::new("verifier-shadow");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("input.txt"), b"base\n").unwrap();
        let store_path = top.0.join("store");
        private_directory(&store_path);
        let live = fs::canonicalize(live).unwrap();
        let grant = issue_grant(&live);
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let shadow = workspace
            .create_shadow(&grant, &base, &store, "verified-result")
            .unwrap();
        fs::write(shadow.root().join("input.txt"), b"candidate\n").unwrap();
        let expected = shadow
            .capture(&grant, 2)
            .unwrap()
            .snapshot()
            .snapshot_id
            .clone();
        drop(shadow);

        let verifier = workspace
            .open_verifier_shadow(&grant, &store, "verified-result", expected.clone(), 3)
            .unwrap();
        assert_eq!(
            verifier.capture(&grant, 4).unwrap().snapshot().snapshot_id,
            expected
        );

        fs::write(verifier.root().join("unexpected.txt"), b"raced\n").unwrap();
        assert!(matches!(
            verifier.capture(&grant, 5),
            Err(CapabilityWorkspaceError::SnapshotMismatch { .. })
        ));
    }

    #[test]
    fn capture_accepts_the_exact_file_limit_and_rejects_one_byte_more() {
        let top = TestDirectory::new("limit");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        let file_path = live.join("bounded.bin");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
            .unwrap();
        file.set_len(MAX_APPLY_FILE_BYTES).unwrap();
        file.sync_all().unwrap();
        let live = fs::canonicalize(live).unwrap();
        let grant = issue_grant(&live);
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();

        let exact = workspace.capture(&grant, 1).unwrap();
        assert_eq!(
            exact.entry("bounded.bin").unwrap().length(),
            MAX_APPLY_FILE_BYTES
        );
        let file = fs::OpenOptions::new().write(true).open(&file_path).unwrap();
        file.set_len(MAX_APPLY_FILE_BYTES + 1).unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            workspace.capture(&grant, 2),
            Err(CapabilityWorkspaceError::FileTooLarge { path, limit })
                if path == Path::new("bounded.bin") && limit == MAX_APPLY_FILE_BYTES
        ));
    }

    #[test]
    fn shadow_store_parent_swap_and_live_overlap_fail_before_creation() {
        let top = TestDirectory::new("state-root");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("anchor"), b"base").unwrap();
        let state_parent = top.0.join("state-parent");
        fs::create_dir(&state_parent).unwrap();
        let store_path = state_parent.join("store");
        private_directory(&store_path);
        let live = fs::canonicalize(live).unwrap();
        let grant = issue_grant(&live);
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();

        fs::rename(&state_parent, top.0.join("moved-state-parent")).unwrap();
        fs::create_dir(&state_parent).unwrap();
        private_directory(&store_path);
        assert!(matches!(
            workspace.create_shadow(&grant, &base, &store, "must-not-exist"),
            Err(CapabilityWorkspaceError::Root(_))
        ));
        assert!(
            !top.0
                .join("moved-state-parent/store/must-not-exist")
                .exists()
        );
        assert!(!store_path.join("must-not-exist").exists());

        let overlapping_store_path = live.join("private-store");
        private_directory(&overlapping_store_path);
        let overlapping_store = CapabilityShadowStore::open(&overlapping_store_path).unwrap();
        assert!(matches!(
            workspace.create_shadow(&grant, &base, &overlapping_store, "must-not-exist",),
            Err(CapabilityWorkspaceError::Destination(_))
        ));
        assert!(!overlapping_store_path.join("must-not-exist").exists());
    }

    #[test]
    fn shadow_names_cannot_alias_git_metadata() {
        for name in [
            ".git",
            ".GIT",
            ".Git",
            ".discard-intent-v1-forged",
            ".DISCARD-tombstone",
        ] {
            assert!(matches!(
                normalize_shadow_child(Path::new(name)),
                Err(CapabilityWorkspaceError::Destination(_))
            ));
        }
    }

    #[test]
    fn consuming_shadow_discard_returns_bounded_evidence_and_removes_all_state() {
        let top = TestDirectory::new("discard-success");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("input.txt"), b"base\n").unwrap();
        let store_path = top.0.join("store");
        private_directory(&store_path);
        let live = fs::canonicalize(live).unwrap();
        let grant = issue_grant(&live);
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let shadow = workspace
            .create_shadow(&grant, &base, &store, "discard-me")
            .unwrap();
        fs::create_dir(shadow.root().join("nested")).unwrap();
        fs::write(shadow.root().join("nested/output.txt"), b"result\n").unwrap();

        let evidence = shadow.discard(&grant).unwrap();
        assert_eq!(evidence.grant_hash(), &grant.contract().grant_hash);
        assert_eq!(evidence.regular_file_count(), 2);
        assert_eq!(evidence.directory_count(), 2);
        assert_eq!(evidence.total_file_bytes(), 12);
        assert!(!store_path.join("discard-me").exists());
        assert!(store.recover_discards().unwrap().is_empty());
        assert!(fs::read_dir(&store_path).unwrap().next().is_none());
    }

    #[test]
    fn every_discard_crash_boundary_recovers_old_tombstone_partial_and_removed_states() {
        let faults = [
            DiscardFaultPoint::IntentSynced,
            DiscardFaultPoint::RenameBeforeSync,
            DiscardFaultPoint::RenameSynced,
            DiscardFaultPoint::DeletionStarted,
            DiscardFaultPoint::RemovedNode(1),
            DiscardFaultPoint::RootRemoved,
        ];
        for (index, fault) in faults.into_iter().enumerate() {
            let top = TestDirectory::new(&format!("discard-fault-{index}"));
            let live = top.0.join("live");
            fs::create_dir(&live).unwrap();
            fs::write(live.join("input.txt"), b"base\n").unwrap();
            let store_path = top.0.join("store");
            private_directory(&store_path);
            let live = fs::canonicalize(live).unwrap();
            let grant = issue_grant(&live);
            let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
            let store = CapabilityShadowStore::open(&store_path).unwrap();
            let base = workspace.capture(&grant, 1).unwrap();
            let child = format!("discard-fault-child-{index}");
            let shadow = workspace
                .create_shadow(&grant, &base, &store, &child)
                .unwrap();
            fs::create_dir(shadow.root().join("nested")).unwrap();
            fs::write(shadow.root().join("nested/output"), b"output").unwrap();

            assert!(matches!(
                shadow.discard_internal(&grant, Some(fault)),
                Err(CapabilityWorkspaceError::InjectedDiscardCrash { .. })
            ));
            drop(store);
            drop(workspace);

            let reopened = CapabilityShadowStore::open(&store_path).unwrap();
            let report = reopened.recover_discards().unwrap();
            assert_eq!(report.completed().len(), 1, "fault {fault:?}");
            assert!(!store_path.join(&child).exists());
            assert!(reopened.recover_discards().unwrap().is_empty());
            assert!(fs::read_dir(&store_path).unwrap().next().is_none());
        }
    }

    #[test]
    fn discard_rejects_git_symlink_hardlink_and_special_entries_before_intent() {
        for unsafe_kind in ["git", "symlink", "hardlink", "special"] {
            let top = TestDirectory::new(&format!("discard-unsafe-{unsafe_kind}"));
            let live = top.0.join("live");
            fs::create_dir(&live).unwrap();
            fs::write(live.join("input.txt"), b"base\n").unwrap();
            let store_path = top.0.join("store");
            private_directory(&store_path);
            let live = fs::canonicalize(live).unwrap();
            let grant = issue_grant(&live);
            let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
            let store = CapabilityShadowStore::open(&store_path).unwrap();
            let base = workspace.capture(&grant, 1).unwrap();
            let child = format!("unsafe-{unsafe_kind}");
            let shadow = workspace
                .create_shadow(&grant, &base, &store, &child)
                .unwrap();
            match unsafe_kind {
                "git" => fs::create_dir(shadow.root().join(".git")).unwrap(),
                "symlink" => {
                    let outside = top.0.join("outside");
                    fs::write(&outside, b"outside").unwrap();
                    symlink(&outside, shadow.root().join("unsafe-object")).unwrap();
                }
                "hardlink" => {
                    fs::hard_link(
                        shadow.root().join("input.txt"),
                        shadow.root().join("linked-input"),
                    )
                    .unwrap();
                }
                "special" => {
                    let socket = std::env::temp_dir().join(format!(
                        "gbs-socket-{}-{}",
                        std::process::id(),
                        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
                    ));
                    let listener = UnixListener::bind(&socket).unwrap();
                    fs::rename(&socket, shadow.root().join("socket")).unwrap();
                    drop(listener);
                }
                _ => unreachable!(),
            }
            assert!(shadow.discard(&grant).is_err());
            assert!(store_path.join(&child).exists());
            assert!(fs::read_dir(&store_path).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".discard-")
            }));
            if unsafe_kind == "symlink" {
                assert_eq!(fs::read(top.0.join("outside")).unwrap(), b"outside");
            }
        }
    }

    #[test]
    fn post_intent_original_move_cannot_be_misreported_as_discarded() {
        let top = TestDirectory::new("discard-moved-after-intent");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("input.txt"), b"base\n").unwrap();
        let store_path = top.0.join("store");
        private_directory(&store_path);
        let live = fs::canonicalize(live).unwrap();
        let grant = issue_grant(&live);
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let shadow = workspace
            .create_shadow(&grant, &base, &store, "move-after-intent")
            .unwrap();
        assert!(matches!(
            shadow.discard_internal(&grant, Some(DiscardFaultPoint::IntentSynced)),
            Err(CapabilityWorkspaceError::InjectedDiscardCrash { .. })
        ));
        fs::rename(
            store_path.join("move-after-intent"),
            store_path.join("attacker-moved-original"),
        )
        .unwrap();

        let error = store.recover_discards().unwrap_err();
        assert!(matches!(
            error,
            CapabilityWorkspaceError::DiscardConflict { reason, .. }
                if reason.contains("absent without exact deletion-started")
        ));
        assert!(store_path.join("attacker-moved-original").exists());
        assert!(fs::read_dir(&store_path).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(DISCARD_INTENT_PREFIX)
        }));
    }

    #[test]
    fn forged_started_record_cannot_authorize_a_both_absent_discard() {
        let top = TestDirectory::new("discard-forged-started");
        let live = top.0.join("live");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("input.txt"), b"base\n").unwrap();
        let store_path = top.0.join("store");
        private_directory(&store_path);
        let live = fs::canonicalize(live).unwrap();
        let grant = issue_grant(&live);
        let workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();
        let base = workspace.capture(&grant, 1).unwrap();
        let shadow = workspace
            .create_shadow(&grant, &base, &store, "forged-started")
            .unwrap();
        assert!(matches!(
            shadow.discard_internal(&grant, Some(DiscardFaultPoint::IntentSynced)),
            Err(CapabilityWorkspaceError::InjectedDiscardCrash { .. })
        ));
        let intent_name = fs::read_dir(&store_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .find(|name| name.starts_with(DISCARD_INTENT_PREFIX))
            .unwrap();
        let intent = read_discard_intent(&store.root, &intent_name).unwrap();
        let mut forged = discard_started_record(&intent);
        forged.intent_digest = Digest::sha256(b"forged-intent");
        write_private_file_new(
            &store.root,
            &discard_started_name(&intent.evidence.discard_id),
            &encode_discard_started(&forged),
        )
        .unwrap();
        fs::rename(
            store_path.join("forged-started"),
            store_path.join("attacker-moved-forged-started"),
        )
        .unwrap();

        assert!(matches!(
            store.recover_discards(),
            Err(CapabilityWorkspaceError::DiscardConflict { reason, .. })
                if reason.contains("differs from exact durable intent")
        ));
        assert!(store_path.join("attacker-moved-forged-started").exists());
    }

    #[test]
    fn orphan_identity_tombstone_is_never_discard_authority() {
        let top = TestDirectory::new("orphan-tombstone");
        let store_path = top.0.join("store");
        private_directory(&store_path);
        let orphan = store_path.join(format!(
            "{DISCARD_TOMBSTONE_PREFIX}{}-0000000000000001-0000000000000002",
            "0".repeat(64)
        ));
        private_directory(&orphan);
        fs::write(orphan.join("preserved"), b"preserved").unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();

        assert!(matches!(
            store.recover_discards(),
            Err(CapabilityWorkspaceError::DiscardConflict { .. })
        ));
        assert_eq!(fs::read(orphan.join("preserved")).unwrap(), b"preserved");
    }
