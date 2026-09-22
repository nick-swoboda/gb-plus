    use super::*;
    use crate::{
        CapabilityShadowStore, CapabilityStageBundleStore, CapabilityWorkspace, ShadowWorkspace,
        WorkspaceManifest,
    };
    use grok_build_core::{
        WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-capability-apply-{label}-{}-{number}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
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
            grant_id: "capability-apply-test-grant".into(),
            workspace_root: root.to_path_buf(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .unwrap()
    }

    fn staged_three_file_change(
        workspace: &TestDirectory,
        private: &TestDirectory,
        id: &str,
    ) -> (IssuedWorkspaceGrant, WorkspaceManifest, StagedChangeSet) {
        fs::write(workspace.0.join("modify"), b"before").unwrap();
        fs::set_permissions(
            workspace.0.join("modify"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        fs::write(workspace.0.join("delete"), b"delete me").unwrap();
        let grant = issue_grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::write(shadow.root().join("modify"), b"after").unwrap();
        fs::remove_file(shadow.root().join("delete")).unwrap();
        fs::write(shadow.root().join("create"), b"created").unwrap();
        let staged = shadow.stage_changes(id, 2).unwrap();
        (grant, base, staged)
    }

    fn staged_single_modify(
        workspace: &TestDirectory,
        private: &TestDirectory,
        id: &str,
    ) -> (IssuedWorkspaceGrant, WorkspaceManifest, StagedChangeSet) {
        fs::write(workspace.0.join("modified"), b"before").unwrap();
        fs::set_permissions(
            workspace.0.join("modified"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let grant = issue_grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::write(shadow.root().join("modified"), b"after").unwrap();
        let staged = shadow.stage_changes(id, 2).unwrap();
        (grant, base, staged)
    }

    fn staged_single_create(
        workspace: &TestDirectory,
        private: &TestDirectory,
        id: &str,
    ) -> (IssuedWorkspaceGrant, WorkspaceManifest, StagedChangeSet) {
        fs::write(workspace.0.join("anchor"), b"base").unwrap();
        let grant = issue_grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::write(shadow.root().join("created"), b"new bytes").unwrap();
        let staged = shadow.stage_changes(id, 2).unwrap();
        (grant, base, staged)
    }

    fn staged_nested_creates(
        workspace: &TestDirectory,
        private: &TestDirectory,
        id: &str,
    ) -> (IssuedWorkspaceGrant, WorkspaceManifest, StagedChangeSet) {
        fs::write(workspace.0.join("anchor"), b"base").unwrap();
        let grant = issue_grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::create_dir_all(shadow.root().join("shared/deep")).unwrap();
        fs::write(shadow.root().join("shared/first"), b"first").unwrap();
        fs::write(shadow.root().join("shared/deep/second"), b"second").unwrap();
        let staged = shadow.stage_changes(id, 2).unwrap();
        (grant, base, staged)
    }

    fn applied_rollback_fixture(
        workspace: &TestDirectory,
        private: &TestDirectory,
        id: &str,
    ) -> (
        IssuedWorkspaceGrant,
        StagedChangeSet,
        StageBundleReference,
        CapabilitySafeApplier,
        CapabilityRollbackArtifactReference,
    ) {
        let (grant, _, staged) = staged_three_file_change(workspace, private, id);
        let bundle = CapabilityStageBundleStore::preview(&staged).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        applier.apply(&grant, &staged).unwrap();
        let rollback = applier
            .reopen_rollback_artifacts(&grant, &bundle.change_set_id)
            .unwrap();
        (grant, staged, bundle, applier, rollback)
    }

    #[test]
    fn evidence_bearing_rollback_captures_every_pre_and_post_endpoint() {
        let workspace = TestDirectory::new("rollback-evidence-workspace");
        let private = TestDirectory::new("rollback-evidence-private");
        let (grant, staged, bundle, mut applier, rollback) =
            applied_rollback_fixture(&workspace, &private, "rollback-evidence-complete");
        fs::write(workspace.0.join("unrelated"), b"preserved").unwrap();

        let CapabilityRollbackAttempt::Completed(evidence) = applier
            .rollback_with_evidence(&grant, &bundle, &rollback)
            .unwrap()
        else {
            panic!("exact application endpoints must permit rollback")
        };
        let canonical =
            serde_json::to_vec(&CapabilityRollbackAttempt::Completed(evidence.clone())).unwrap();
        assert_eq!(
            serde_json::from_slice::<CapabilityRollbackAttempt>(&canonical).unwrap(),
            CapabilityRollbackAttempt::Completed(evidence.clone())
        );
        let mut unknown: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        unknown
            .get_mut("evidence")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<CapabilityRollbackAttempt>(unknown).is_err());
        assert_eq!(evidence.bundle(), &bundle);
        assert_eq!(evidence.rollback(), &rollback);
        assert_eq!(
            evidence.target_contract().len(),
            staged.change_set().operations.len()
        );
        assert_eq!(
            evidence
                .target_contract()
                .iter()
                .map(CapabilityRollbackTargetContract::path)
                .collect::<Vec<_>>(),
            staged
                .change_set()
                .operations
                .iter()
                .map(FileOperation::path)
                .collect::<Vec<_>>()
        );
        assert!(
            evidence
                .target_contract()
                .iter()
                .zip(evidence.pre_effect_observations())
                .all(|(target, observed)| observed
                    .endpoint()
                    .matches_expected(target.application()))
        );
        assert!(
            evidence
                .target_contract()
                .iter()
                .zip(evidence.post_restore_observations())
                .all(|(target, observed)| observed
                    .endpoint()
                    .matches_expected(target.restored_base()))
        );
        assert_eq!(
            evidence.final_live_manifest_digest(),
            &WorkspaceManifest::capture(&grant, 9)
                .unwrap()
                .snapshot()
                .snapshot_id
        );
        assert_eq!(
            fs::read(workspace.0.join("unrelated")).unwrap(),
            b"preserved"
        );
        let observed_manifest = evidence.final_live_manifest_digest().clone();
        fs::write(workspace.0.join("unrelated"), b"later unrelated edit").unwrap();
        assert_ne!(
            observed_manifest,
            WorkspaceManifest::capture(&grant, 10)
                .unwrap()
                .snapshot()
                .snapshot_id,
            "manifest evidence is the exact earlier observation, not a later-current claim"
        );
        let transaction = applier
            .open_transaction(
                &transaction_name(&bundle.change_set_id),
                &bundle.change_set_id,
            )
            .unwrap();
        assert!(
            transaction
                .symlink_metadata(ROLLBACK_PRECONDITION_NAME)
                .is_ok()
        );
    }

    #[test]
    fn stale_regular_and_absent_endpoints_are_typed_before_effect_conflicts() {
        let workspace = TestDirectory::new("rollback-conflict-workspace");
        let private = TestDirectory::new("rollback-conflict-private");
        let (grant, _, bundle, mut applier, rollback) =
            applied_rollback_fixture(&workspace, &private, "rollback-content-conflict");
        fs::write(workspace.0.join("modify"), b"external").unwrap();
        fs::write(workspace.0.join("delete"), b"externally recreated").unwrap();

        let CapabilityRollbackAttempt::LiveConflict(conflict) = applier
            .rollback_with_evidence(&grant, &bundle, &rollback)
            .unwrap()
        else {
            panic!("stable stale endpoints must return typed conflict")
        };
        assert!(!conflict.rollback_mutation_started());
        assert_eq!(conflict.observations().len(), 3);
        assert_eq!(conflict.conflicts().len(), 2);
        assert!(
            conflict
                .conflicts()
                .iter()
                .all(|item| item.expected_endpoint_digest() != item.observed_endpoint_digest())
        );
        let transaction = applier
            .open_transaction(
                &transaction_name(&bundle.change_set_id),
                &bundle.change_set_id,
            )
            .unwrap();
        assert_eq!(read_phase(&transaction).unwrap(), JournalPhase::Committed);
        assert!(read_rollback_precondition(&transaction).unwrap().is_none());
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"external");
        assert_eq!(
            fs::read(workspace.0.join("delete")).unwrap(),
            b"externally recreated"
        );
    }

    #[test]
    fn missing_expected_regular_endpoint_is_a_typed_absence_conflict() {
        let workspace = TestDirectory::new("rollback-absence-workspace");
        let private = TestDirectory::new("rollback-absence-private");
        let (grant, _, bundle, mut applier, rollback) =
            applied_rollback_fixture(&workspace, &private, "rollback-absence-conflict");
        fs::remove_file(workspace.0.join("modify")).unwrap();

        let CapabilityRollbackAttempt::LiveConflict(conflict) = applier
            .rollback_with_evidence(&grant, &bundle, &rollback)
            .unwrap()
        else {
            panic!("absent result target must be a typed content conflict")
        };
        let item = conflict
            .conflicts()
            .iter()
            .find(|item| item.path() == Path::new("modify"))
            .unwrap();
        assert_eq!(
            item.observed_endpoint_digest(),
            &Digest::sha256(ABSENT_ENDPOINT_DOMAIN)
        );
        assert!(!conflict.rollback_mutation_started());
    }

    #[test]
    fn unsafe_mode_drift_and_observation_race_are_generic_non_authority() {
        let workspace = TestDirectory::new("rollback-generic-workspace");
        let private = TestDirectory::new("rollback-generic-private");
        let (grant, _, bundle, mut applier, rollback) =
            applied_rollback_fixture(&workspace, &private, "rollback-generic-refusal");
        fs::set_permissions(
            workspace.0.join("modify"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            applier.rollback_with_evidence(&grant, &bundle, &rollback),
            Err(CapabilityApplyError::Root(_))
        ));
        let transaction = applier
            .open_transaction(
                &transaction_name(&bundle.change_set_id),
                &bundle.change_set_id,
            )
            .unwrap();
        assert_eq!(read_phase(&transaction).unwrap(), JournalPhase::Committed);
        assert!(read_rollback_precondition(&transaction).unwrap().is_none());

        fs::set_permissions(
            workspace.0.join("modify"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let raced_path = workspace.0.join("modify");
        assert!(matches!(
            applier.rollback_with_evidence_internal(
                &grant,
                &bundle,
                &rollback,
                || {
                    fs::write(&raced_path, b"raced").map_err(|error| {
                        io_error(
                            "inject rollback observation race",
                            Path::new("modify"),
                            &error,
                        )
                    })
                },
                || Ok(()),
                || Ok(())
            ),
            Err(CapabilityApplyError::Root(_))
        ));
        let transaction = applier
            .open_transaction(
                &transaction_name(&bundle.change_set_id),
                &bundle.change_set_id,
            )
            .unwrap();
        assert_eq!(read_phase(&transaction).unwrap(), JournalPhase::Committed);
        assert!(read_rollback_precondition(&transaction).unwrap().is_none());

        fs::remove_file(workspace.0.join("modify")).unwrap();
        symlink("outside", workspace.0.join("modify")).unwrap();
        assert!(matches!(
            applier.rollback_with_evidence(&grant, &bundle, &rollback),
            Err(CapabilityApplyError::UnsafeEntry {
                kind: UnsafeFileKind::Symlink,
                ..
            })
        ));
        fs::remove_file(workspace.0.join("modify")).unwrap();
        fs::create_dir(workspace.0.join("modify")).unwrap();
        assert!(matches!(
            applier.rollback_with_evidence(&grant, &bundle, &rollback),
            Err(CapabilityApplyError::UnsafeEntry {
                kind: UnsafeFileKind::Directory,
                ..
            })
        ));
        let transaction = applier
            .open_transaction(
                &transaction_name(&bundle.change_set_id),
                &bundle.change_set_id,
            )
            .unwrap();
        assert_eq!(read_phase(&transaction).unwrap(), JournalPhase::Committed);
        assert!(read_rollback_precondition(&transaction).unwrap().is_none());
    }

    #[test]
    fn retained_precondition_supports_restart_readback_but_rejects_later_drift() {
        let workspace = TestDirectory::new("rollback-restart-workspace");
        let private = TestDirectory::new("rollback-restart-private");
        let journal = private.0.join("journal");
        let (grant, _, bundle, mut applier, rollback) =
            applied_rollback_fixture(&workspace, &private, "rollback-restart-evidence");
        assert!(matches!(
            applier
                .rollback_with_evidence(&grant, &bundle, &rollback)
                .unwrap(),
            CapabilityRollbackAttempt::Completed(_)
        ));
        drop(applier);

        let mut reopened = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
        assert!(reopened.recover_pending(&grant).unwrap().is_empty());
        assert!(matches!(
            reopened
                .rollback_with_evidence(&grant, &bundle, &rollback)
                .unwrap(),
            CapabilityRollbackAttempt::Completed(_)
        ));
        fs::write(workspace.0.join("modify"), b"post-rollback drift").unwrap();
        assert!(matches!(
            reopened.rollback_with_evidence(&grant, &bundle, &rollback),
            Err(CapabilityApplyError::ReconciliationRequired { .. })
        ));
    }

    #[test]
    fn drift_after_retained_precondition_is_reconciliation_never_live_conflict() {
        let workspace = TestDirectory::new("rollback-mid-effect-workspace");
        let private = TestDirectory::new("rollback-mid-effect-private");
        let (grant, _, bundle, mut applier, rollback) =
            applied_rollback_fixture(&workspace, &private, "rollback-mid-effect-drift");
        let drift_path = workspace.0.join("modify");
        let result = applier.rollback_with_evidence_internal(
            &grant,
            &bundle,
            &rollback,
            || Ok(()),
            || Ok(()),
            || {
                fs::write(&drift_path, b"drift after durable precondition").map_err(|error| {
                    io_error(
                        "inject post-precondition drift",
                        Path::new("modify"),
                        &error,
                    )
                })
            },
        );
        assert!(matches!(
            result,
            Err(CapabilityApplyError::ReconciliationRequired { .. })
        ));
        let transaction = applier
            .open_transaction(
                &transaction_name(&bundle.change_set_id),
                &bundle.change_set_id,
            )
            .unwrap();
        assert_eq!(read_phase(&transaction).unwrap(), JournalPhase::RollingBack);
        assert!(read_rollback_precondition(&transaction).unwrap().is_some());
    }

    #[test]
    fn post_rename_phase_sync_ambiguity_requires_reconciliation_and_recovers() {
        let workspace = TestDirectory::new("rollback-phase-sync-workspace");
        let private = TestDirectory::new("rollback-phase-sync-private");
        let journal = private.0.join("journal");
        let (grant, _, bundle, mut applier, rollback) =
            applied_rollback_fixture(&workspace, &private, "rollback-phase-sync-ambiguity");

        let result = applier.rollback_with_evidence_internal(
            &grant,
            &bundle,
            &rollback,
            || Ok(()),
            || {
                Err(CapabilityApplyError::Io {
                    operation: "inject directory sync failure after phase rename",
                    path: PathBuf::from("phase"),
                    message: "injected post-rename durability ambiguity".into(),
                })
            },
            || Ok(()),
        );
        assert!(matches!(
            result,
            Err(CapabilityApplyError::ReconciliationRequired {
                operation: "durably transition evidence-bearing rollback to rolling_back",
                ..
            })
        ));
        let transaction = applier
            .open_transaction(
                &transaction_name(&bundle.change_set_id),
                &bundle.change_set_id,
            )
            .unwrap();
        assert_eq!(read_phase(&transaction).unwrap(), JournalPhase::RollingBack);
        assert!(read_rollback_precondition(&transaction).unwrap().is_some());
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"after");
        drop(transaction);
        drop(applier);

        let mut reopened = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
        let recovery = reopened.recover_pending(&grant).unwrap();
        assert_eq!(
            recovery.recovered_change_sets(),
            std::slice::from_ref(&bundle.change_set_id)
        );
        assert!(matches!(
            reopened
                .rollback_with_evidence(&grant, &bundle, &rollback)
                .unwrap(),
            CapabilityRollbackAttempt::Completed(_)
        ));
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"before");
    }

    #[test]
    fn legacy_rollback_post_rename_phase_ambiguity_is_never_before_effect() {
        let workspace = TestDirectory::new("legacy-rollback-phase-sync-workspace");
        let private = TestDirectory::new("legacy-rollback-phase-sync-private");
        let journal = private.0.join("journal");
        let (grant, _, bundle, mut applier, _) =
            applied_rollback_fixture(&workspace, &private, "legacy-rollback-phase-sync");

        let result = applier.rollback_internal(&grant, &bundle.change_set_id, || {
            Err(CapabilityApplyError::Io {
                operation: "inject legacy rollback phase sync failure",
                path: PathBuf::from("phase"),
                message: "injected post-rename durability ambiguity".into(),
            })
        });
        assert!(matches!(
            result,
            Err(CapabilityApplyError::ReconciliationRequired {
                operation: "durably transition rollback to rolling_back",
                ..
            })
        ));
        let transaction = applier
            .open_transaction(
                &transaction_name(&bundle.change_set_id),
                &bundle.change_set_id,
            )
            .unwrap();
        assert_eq!(read_phase(&transaction).unwrap(), JournalPhase::RollingBack);
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"after");
        drop(transaction);
        drop(applier);

        let mut reopened = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
        assert_eq!(
            reopened
                .recover_pending(&grant)
                .unwrap()
                .recovered_change_sets(),
            &[bundle.change_set_id]
        );
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"before");
    }

    #[test]
    fn manifest_digest_matches_workspace_capture_and_apply_result() {
        let workspace = TestDirectory::new("digest-workspace");
        let private = TestDirectory::new("digest-private");
        let (grant, base, staged) =
            staged_three_file_change(&workspace, &private, "digest-compatible");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        assert_eq!(
            applier.capture_snapshot().unwrap(),
            base.snapshot().snapshot_id
        );
        let outcome = applier.apply(&grant, &staged).unwrap();
        assert_eq!(
            outcome.applied_snapshot(),
            &staged.change_set().result_snapshot
        );
        assert_eq!(
            WorkspaceManifest::capture(&grant, 3)
                .unwrap()
                .snapshot()
                .snapshot_id,
            staged.change_set().result_snapshot
        );
        assert_eq!(
            outcome.live_manifest_digest(),
            &staged.change_set().result_snapshot
        );
        assert_eq!(
            outcome.applied_operations_digest(),
            &staged.change_set().applied_operations_digest().unwrap()
        );
    }

    #[test]
    fn apply_and_target_rollback_preserve_unrelated_files_and_modes() {
        let workspace = TestDirectory::new("rollback-workspace");
        let private = TestDirectory::new("rollback-private");
        let (grant, base, staged) =
            staged_three_file_change(&workspace, &private, "rollback-preserves-unrelated");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        applier.apply(&grant, &staged).unwrap();
        fs::write(workspace.0.join("unrelated"), b"do not touch").unwrap();
        let outcome = applier
            .rollback(&grant, "rollback-preserves-unrelated")
            .unwrap();

        assert_eq!(outcome.base_snapshot(), &base.snapshot().snapshot_id);
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"before");
        assert_eq!(fs::read(workspace.0.join("delete")).unwrap(), b"delete me");
        assert!(!workspace.0.join("create").exists());
        assert_eq!(
            fs::read(workspace.0.join("unrelated")).unwrap(),
            b"do not touch"
        );
        assert_eq!(
            fs::metadata(workspace.0.join("modify")).unwrap().mode() & 0o777,
            0o640
        );
        let observed = WorkspaceManifest::capture(&grant, 4).unwrap();
        assert_eq!(
            outcome.live_manifest_digest(),
            &observed.snapshot().snapshot_id
        );
        assert_ne!(outcome.live_manifest_digest(), outcome.base_snapshot());
        assert_eq!(
            outcome.restored_base_endpoints_digest(),
            &staged
                .change_set()
                .restored_base_endpoints_digest()
                .unwrap()
        );
        assert_eq!(
            outcome.touched_target_set_digest(),
            &staged.change_set().touched_target_set_digest().unwrap()
        );
    }

    #[test]
    fn reopened_rollback_artifacts_bind_plan_base_blobs_and_inode_identity() {
        let workspace = TestDirectory::new("rollback-reference-workspace");
        let private = TestDirectory::new("rollback-reference-private");
        let (grant, base, staged) =
            staged_three_file_change(&workspace, &private, "rollback-reference");
        let journal = private.0.join("journal");
        let mut applier = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
        let application = applier.apply(&grant, &staged).unwrap();

        let reference = applier
            .reopen_rollback_artifacts(&grant, "rollback-reference")
            .unwrap();
        assert_eq!(reference.transaction_id(), application.transaction_id());
        assert_eq!(reference.base_snapshot(), &base.snapshot().snapshot_id);
        assert_eq!(
            reference.touched_target_set_digest(),
            &staged.change_set().touched_target_set_digest().unwrap()
        );
        assert_eq!(reference.transaction_mode(), 0o700);
        assert_eq!(
            reference.artifacts_digest(),
            &Digest::sha256(reference.reopened_artifacts_bytes())
        );
        assert!(!reference.reopened_artifacts_bytes().is_empty());
        assert!(reference.reopened_artifacts_bytes().len() <= MAX_ROLLBACK_REFERENCE_BYTES);
        assert_eq!(reference.artifacts().len(), 3);
        assert!(matches!(
            reference.artifacts()[0].kind(),
            CapabilityRollbackArtifactKind::Plan
        ));
        assert!(
            reference
                .artifacts()
                .iter()
                .all(|artifact| artifact.mode() == 0o600)
        );
        applier
            .validate_rollback_artifacts(&grant, &reference)
            .unwrap();
        assert_eq!(
            applier
                .reopen_rollback_artifacts(&grant, "rollback-reference")
                .unwrap(),
            reference
        );

        let base_artifact = reference
            .artifacts()
            .iter()
            .find(|artifact| {
                matches!(
                    artifact.kind(),
                    CapabilityRollbackArtifactKind::BaseBlob { .. }
                )
            })
            .unwrap();
        let transaction = journal.join(reference.transaction_id());
        let path = transaction.join(base_artifact.name());
        let replacement = private.0.join("same-bytes-replacement");
        fs::rename(&path, &replacement).unwrap();
        fs::write(&path, fs::read(&replacement).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            applier.validate_rollback_artifacts(&grant, &reference),
            Err(CapabilityApplyError::Journal(message))
                if message.contains("differ")
        ));
    }

    #[test]
    fn committed_reconciliation_preserves_unrelated_live_edits() {
        let workspace = TestDirectory::new("committed-reconcile-workspace");
        let private = TestDirectory::new("committed-reconcile-private");
        let (grant, _base, staged) =
            staged_single_create(&workspace, &private, "committed-reconcile");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        applier.apply(&grant, &staged).unwrap();
        fs::write(workspace.0.join("unrelated"), b"post-commit edit").unwrap();

        let CapabilityApplyReconciliation::Committed(outcome) =
            applier.reconcile(&grant, "committed-reconcile").unwrap()
        else {
            panic!("committed transaction must remain committed");
        };
        assert_eq!(
            outcome.applied_snapshot(),
            &staged.change_set().result_snapshot
        );
        assert_ne!(outcome.live_manifest_digest(), outcome.applied_snapshot());
        assert_eq!(
            fs::read(workspace.0.join("unrelated")).unwrap(),
            b"post-commit edit"
        );
    }

    #[test]
    fn unrelated_post_base_edit_is_preserved_during_target_only_apply() {
        let workspace = TestDirectory::new("stale-workspace");
        let private = TestDirectory::new("stale-private");
        let (grant, _base, staged) = staged_single_modify(&workspace, &private, "stale-base");
        fs::write(workspace.0.join("external-edit"), b"changed").unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        let outcome = applier.apply(&grant, &staged).unwrap();
        assert_eq!(fs::read(workspace.0.join("modified")).unwrap(), b"after");
        assert_eq!(
            fs::read(workspace.0.join("external-edit")).unwrap(),
            b"changed"
        );
        assert_ne!(outcome.live_manifest_digest(), outcome.applied_snapshot());
        assert!(applier.recover_pending(&grant).unwrap().is_empty());
    }

    #[test]
    fn production_applier_rejects_verified_no_op_without_creating_a_transaction() {
        let workspace = TestDirectory::new("verified-no-op-workspace");
        let private = TestDirectory::new("verified-no-op-private");
        fs::write(workspace.0.join("anchor"), b"unchanged").unwrap();
        let grant = issue_grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let staged = StagedChangeSet::new(
            ChangeSet {
                change_set_id: "verified-no-op-production".into(),
                base_snapshot: base.snapshot().snapshot_id.clone(),
                result_snapshot: base.snapshot().snapshot_id.clone(),
                operations: Vec::new(),
            },
            BTreeMap::new(),
        )
        .expect("construct explicit verified no-op");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        assert!(matches!(
            applier.apply(&grant, &staged),
            Err(CapabilityApplyError::EmptyChangeSet)
        ));
        assert!(matches!(
            applier.reconcile(&grant, "verified-no-op-production"),
            Err(CapabilityApplyError::TransactionNotFound(id))
                if id == "verified-no-op-production"
        ));
        assert!(applier.recover_pending(&grant).unwrap().is_empty());
    }

    #[test]
    fn every_call_requires_the_exact_acquired_grant() {
        let workspace = TestDirectory::new("grant-mismatch-workspace");
        let private = TestDirectory::new("grant-mismatch-private");
        let (grant, _base, staged) = staged_single_create(&workspace, &private, "grant-mismatch");
        let different = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "different-grant".into(),
            workspace_root: workspace.0.clone(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .unwrap();
        let mut applier = CapabilitySafeApplier::open(grant, private.0.join("journal")).unwrap();

        assert!(matches!(
            applier.apply(&different, &staged),
            Err(CapabilityApplyError::Authority(_))
        ));
        assert!(!workspace.0.join("created").exists());
    }

    #[test]
    fn leaf_and_parent_symlinks_are_rejected_without_touching_outside_files() {
        let workspace = TestDirectory::new("symlink-workspace");
        let private = TestDirectory::new("symlink-private");
        let outside = TestDirectory::new("symlink-outside");
        let (grant, _base, staged) = staged_single_modify(&workspace, &private, "leaf-symlink");
        fs::write(outside.0.join("outside"), b"outside").unwrap();
        fs::remove_file(workspace.0.join("modified")).unwrap();
        symlink(outside.0.join("outside"), workspace.0.join("modified")).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        assert!(matches!(
            applier.apply(&grant, &staged),
            Err(CapabilityApplyError::UnsafeEntry {
                kind: UnsafeFileKind::Symlink,
                ..
            })
        ));
        assert_eq!(fs::read(outside.0.join("outside")).unwrap(), b"outside");

        let workspace = TestDirectory::new("parent-symlink-workspace");
        let private = TestDirectory::new("parent-symlink-private");
        let outside = TestDirectory::new("parent-symlink-outside");
        fs::create_dir(workspace.0.join("sub")).unwrap();
        fs::write(workspace.0.join("sub/file"), b"before").unwrap();
        fs::write(outside.0.join("file"), b"outside").unwrap();
        let grant = issue_grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::write(shadow.root().join("sub/file"), b"after").unwrap();
        let staged = shadow.stage_changes("parent-symlink", 2).unwrap();
        fs::rename(workspace.0.join("sub"), workspace.0.join("sub-original")).unwrap();
        symlink(&outside.0, workspace.0.join("sub")).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        assert!(matches!(
            applier.apply(&grant, &staged),
            Err(CapabilityApplyError::UnsafeEntry {
                kind: UnsafeFileKind::Symlink,
                ..
            })
        ));
        assert_eq!(fs::read(outside.0.join("file")).unwrap(), b"outside");
    }

    #[test]
    fn hardlinks_and_directory_target_collisions_are_rejected() {
        let workspace = TestDirectory::new("hardlink-workspace");
        let private = TestDirectory::new("hardlink-private");
        let outside = TestDirectory::new("hardlink-outside");
        let (grant, _base, staged) = staged_single_modify(&workspace, &private, "hardlink-target");
        fs::write(outside.0.join("shared"), b"before").unwrap();
        fs::remove_file(workspace.0.join("modified")).unwrap();
        fs::hard_link(outside.0.join("shared"), workspace.0.join("modified")).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        assert!(matches!(
            applier.apply(&grant, &staged),
            Err(CapabilityApplyError::UnsafeEntry {
                kind: UnsafeFileKind::HardLink,
                ..
            })
        ));
        assert_eq!(fs::read(outside.0.join("shared")).unwrap(), b"before");

        let workspace = TestDirectory::new("directory-collision-workspace");
        let private = TestDirectory::new("directory-collision-private");
        let (grant, _base, staged) =
            staged_single_create(&workspace, &private, "directory-collision");
        fs::create_dir(workspace.0.join("created")).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        assert!(matches!(
            applier.apply(&grant, &staged),
            Err(CapabilityApplyError::UnsafeEntry {
                kind: UnsafeFileKind::Directory,
                ..
            })
        ));
    }

    #[test]
    fn special_workspace_entries_are_rejected_before_application() {
        let workspace = TestDirectory::new("special-entry-workspace");
        let private = TestDirectory::new("special-entry-private");
        let (grant, _base, staged) = staged_single_create(&workspace, &private, "special-entry");
        let socket_source = std::env::temp_dir().join(format!(
            "gba-socket-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let _socket = UnixListener::bind(&socket_source).unwrap();
        fs::rename(socket_source, workspace.0.join("socket")).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        assert!(matches!(
            applier.apply(&grant, &staged),
            Err(CapabilityApplyError::UnsafeEntry {
                kind: UnsafeFileKind::Special,
                ..
            })
        ));
    }

    #[test]
    fn root_replacement_is_rejected_and_replacement_is_untouched() {
        let workspace = TestDirectory::new("root-replacement-workspace");
        let private = TestDirectory::new("root-replacement-private");
        let (grant, _base, staged) = staged_single_create(&workspace, &private, "root-replacement");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        let moved = workspace.0.with_extension("original-root");
        fs::rename(&workspace.0, &moved).unwrap();
        fs::create_dir(&workspace.0).unwrap();
        fs::write(workspace.0.join("sentinel"), b"replacement").unwrap();

        assert!(matches!(
            applier.apply(&grant, &staged),
            Err(CapabilityApplyError::Root(_) | CapabilityApplyError::Authority(_))
        ));
        assert_eq!(
            fs::read(workspace.0.join("sentinel")).unwrap(),
            b"replacement"
        );

        drop(applier);
        fs::remove_dir_all(&workspace.0).unwrap();
        fs::rename(moved, &workspace.0).unwrap();
    }

    #[test]
    fn dropping_the_applier_releases_the_writer_lock_past_a_duplicated_description() {
        let workspace = TestDirectory::new("lock-release-workspace");
        let private = TestDirectory::new("lock-release-private");
        let (grant, _base, _staged) =
            staged_three_file_change(&workspace, &private, "lock-release");
        let journal = private.0.join("journal");
        let applier = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();

        // A second reference to the *same* open file description, which is what
        // owns the `flock` exclusion. Every `fork` behind a process spawn hands
        // exactly this to the child for every open descriptor until it execs,
        // so an unrelated spawn overlapping this applier's lifetime produces
        // precisely this situation.
        let duplicated = applier
            .writer_lock
            .try_clone()
            .expect("duplicate the writer-lock description");

        drop(applier);

        // Exclusion must be bounded by the applier that owns it, not by the
        // last surviving duplicate of its descriptor.
        CapabilitySafeApplier::open(grant, &journal).expect(
            "a dropped applier releases the writer lock even while a duplicate description is open",
        );

        drop(duplicated);
    }

    #[test]
    fn partial_multi_file_apply_recovers_targets_and_preserves_unrelated_edit() {
        let workspace = TestDirectory::new("fault-workspace");
        let private = TestDirectory::new("fault-private");
        let (grant, base, staged) =
            staged_three_file_change(&workspace, &private, "partial-multi-file");
        let journal = private.0.join("journal");
        let mut first = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
        assert!(matches!(
            first.apply_internal(&grant, &staged, Some(FaultPoint::AfterMutation(1))),
            Err(CapabilityApplyError::InjectedCrash {
                affected_operations: 2
            })
        ));
        fs::write(workspace.0.join("unrelated"), b"preserve me").unwrap();
        drop(first);

        let mut reopened = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
        let report = reopened.recover_pending(&grant).unwrap();
        assert_eq!(report.recovered_change_sets(), &["partial-multi-file"]);
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"before");
        assert_eq!(fs::read(workspace.0.join("delete")).unwrap(), b"delete me");
        assert!(!workspace.0.join("create").exists());
        assert_eq!(
            fs::read(workspace.0.join("unrelated")).unwrap(),
            b"preserve me"
        );
        let CapabilityApplyReconciliation::TargetsRestored(restored) =
            reopened.reconcile(&grant, "partial-multi-file").unwrap()
        else {
            panic!("rolled-back transaction must reconcile as restored");
        };
        assert_eq!(
            restored.transaction_id(),
            transaction_name("partial-multi-file")
        );
        assert_eq!(restored.change_set_id(), "partial-multi-file");
        assert_eq!(restored.base_snapshot(), &base.snapshot().snapshot_id);
        assert_eq!(
            restored.restored_paths(),
            staged
                .change_set()
                .operations
                .iter()
                .map(|operation| operation.path().to_path_buf())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            restored.restored_base_endpoints_digest(),
            &staged
                .change_set()
                .restored_base_endpoints_digest()
                .unwrap()
        );
    }

    #[test]
    fn post_apply_manifest_capture_failure_rolls_back_only_touched_targets() {
        let workspace = TestDirectory::new("manifest-failure-workspace");
        let private = TestDirectory::new("manifest-failure-private");
        let (grant, _base, staged) =
            staged_three_file_change(&workspace, &private, "manifest-failure");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        assert!(matches!(
            applier.apply_internal(
                &grant,
                &staged,
                Some(FaultPoint::InjectUnsafeEntryBeforeManifest)
            ),
            Err(CapabilityApplyError::UnsafeEntry { .. })
        ));
        assert_eq!(fs::read(workspace.0.join("modify")).unwrap(), b"before");
        assert_eq!(fs::read(workspace.0.join("delete")).unwrap(), b"delete me");
        assert!(!workspace.0.join("create").exists());
        assert!(
            fs::symlink_metadata(workspace.0.join("manifest-capture-unsafe-link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(workspace.0.join("manifest-capture-unsafe-link")).unwrap();
        assert!(matches!(
            applier.reconcile(&grant, "manifest-failure").unwrap(),
            CapabilityApplyReconciliation::TargetsRestored(_)
        ));
    }

    #[test]
    fn modify_recovery_rejects_same_content_replacement_and_chmod_conflicts() {
        let workspace = TestDirectory::new("same-content-conflict-workspace");
        let private = TestDirectory::new("same-content-conflict-private");
        let (grant, _base, staged) =
            staged_single_modify(&workspace, &private, "same-content-conflict");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        assert!(matches!(
            applier.apply_internal(&grant, &staged, Some(FaultPoint::AfterMutation(0))),
            Err(CapabilityApplyError::InjectedCrash { .. })
        ));
        fs::remove_file(workspace.0.join("modified")).unwrap();
        fs::write(workspace.0.join("modified"), b"after").unwrap();
        fs::set_permissions(
            workspace.0.join("modified"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();

        assert!(matches!(
            applier.recover_pending(&grant),
            Err(CapabilityApplyError::RecoveryConflict { .. })
        ));
        assert_eq!(fs::read(workspace.0.join("modified")).unwrap(), b"after");

        let workspace = TestDirectory::new("chmod-conflict-workspace");
        let private = TestDirectory::new("chmod-conflict-private");
        let (grant, _base, staged) = staged_single_modify(&workspace, &private, "chmod-conflict");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        assert!(matches!(
            applier.apply_internal(&grant, &staged, Some(FaultPoint::AfterMutation(0))),
            Err(CapabilityApplyError::InjectedCrash { .. })
        ));
        fs::set_permissions(
            workspace.0.join("modified"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        assert!(matches!(
            applier.recover_pending(&grant),
            Err(CapabilityApplyError::RecoveryConflict { .. })
        ));
        assert_eq!(
            fs::metadata(workspace.0.join("modified")).unwrap().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn journal_writer_lock_rejects_a_second_applier_until_drop() {
        let workspace = TestDirectory::new("lock-workspace");
        let private = TestDirectory::new("lock-private");
        fs::write(workspace.0.join("anchor"), b"base").unwrap();
        let grant = issue_grant(&workspace.0);
        let journal = private.0.join("journal");
        let first = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();

        assert!(matches!(
            CapabilitySafeApplier::open(grant.clone(), &journal),
            Err(CapabilityApplyError::Journal(message))
                if message.contains("writer lock")
        ));
        drop(first);
        CapabilitySafeApplier::open(grant, &journal).unwrap();
    }

    #[test]
    fn noncanonical_and_git_paths_fail_closed() {
        assert!(matches!(
            normalize_path(Path::new("a//b")),
            Err(CapabilityApplyError::InvalidPath { .. })
        ));
        assert!(matches!(
            normalize_path(Path::new("a/./b")),
            Err(CapabilityApplyError::InvalidPath { .. })
        ));
        assert!(matches!(
            normalize_path(Path::new("src/.git/config")),
            Err(CapabilityApplyError::InvalidPath { .. })
        ));
        assert!(matches!(
            normalize_path(Path::new("src/.GIT/config")),
            Err(CapabilityApplyError::InvalidPath { .. })
        ));
        assert!(matches!(
            normalize_path(Path::new(&OsString::from_vec(vec![0xff]))),
            Err(CapabilityApplyError::InvalidPath { .. })
        ));
    }

    #[test]
    fn missing_parents_are_journaled_and_empty_parents_roll_back_deepest_first() {
        let workspace = TestDirectory::new("missing-parent-workspace");
        let private = TestDirectory::new("missing-parent-private");
        fs::write(workspace.0.join("anchor"), b"base").unwrap();
        let grant = issue_grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::create_dir_all(shadow.root().join("new-parent/deep")).unwrap();
        fs::write(shadow.root().join("new-parent/deep/file"), b"new").unwrap();
        let staged = shadow.stage_changes("missing-parent", 2).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        applier.apply(&grant, &staged).unwrap();
        assert_eq!(
            fs::read(workspace.0.join("new-parent/deep/file")).unwrap(),
            b"new"
        );
        assert_eq!(
            fs::metadata(workspace.0.join("new-parent")).unwrap().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(workspace.0.join("new-parent/deep"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        applier.rollback(&grant, "missing-parent").unwrap();
        assert!(!workspace.0.join("new-parent").exists());
    }

    #[test]
    fn directory_publish_crash_recovers_and_nonempty_rollback_conflicts_safely() {
        let workspace = TestDirectory::new("directory-crash-workspace");
        let private = TestDirectory::new("directory-crash-private");
        fs::write(workspace.0.join("anchor"), b"base").unwrap();
        let grant = issue_grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::create_dir_all(shadow.root().join("one/two")).unwrap();
        fs::write(shadow.root().join("one/two/file"), b"new").unwrap();
        let staged = shadow.stage_changes("directory-crash", 2).unwrap();
        let journal = private.0.join("journal");
        let mut first = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
        assert!(matches!(
            first.apply_internal(&grant, &staged, Some(FaultPoint::AfterDirectoryMutation(0))),
            Err(CapabilityApplyError::InjectedCrash {
                affected_operations: 1
            })
        ));
        drop(first);
        let mut reopened = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
        assert_eq!(
            reopened
                .recover_pending(&grant)
                .unwrap()
                .recovered_change_sets(),
            &["directory-crash"]
        );
        assert!(!workspace.0.join("one").exists());

        let workspace = TestDirectory::new("directory-conflict-workspace");
        let private = TestDirectory::new("directory-conflict-private");
        fs::write(workspace.0.join("anchor"), b"base").unwrap();
        let grant = issue_grant(&workspace.0);
        let base = WorkspaceManifest::capture(&grant, 1).unwrap();
        let shadow = ShadowWorkspace::create(&grant, &base, private.0.join("shadow")).unwrap();
        fs::create_dir(shadow.root().join("owned-parent")).unwrap();
        fs::write(shadow.root().join("owned-parent/file"), b"new").unwrap();
        let staged = shadow.stage_changes("directory-conflict", 2).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        applier.apply(&grant, &staged).unwrap();
        fs::write(workspace.0.join("owned-parent/external"), b"preserve").unwrap();

        assert!(matches!(
            applier.rollback(&grant, "directory-conflict"),
            Err(CapabilityApplyError::RecoveryConflict { .. })
        ));
        assert_eq!(
            fs::read(workspace.0.join("owned-parent/external")).unwrap(),
            b"preserve"
        );
        assert!(!workspace.0.join("owned-parent/file").exists());
    }

    #[test]
    fn shared_missing_parents_are_deduplicated_and_nested_in_creation_order() {
        let workspace = TestDirectory::new("directory-plan-workspace");
        let private = TestDirectory::new("directory-plan-private");
        let (grant, _base, staged) = staged_nested_creates(&workspace, &private, "directory-plan");
        let applier = CapabilitySafeApplier::open(grant, private.0.join("journal")).unwrap();
        let (_name, _transaction, plan) = applier.prepare_transaction(&staged, None).unwrap();

        assert_eq!(
            plan.directories,
            vec![
                PlannedDirectory {
                    path: PathBuf::from("shared"),
                    mode: 0o755,
                },
                PlannedDirectory {
                    path: PathBuf::from("shared/deep"),
                    mode: 0o755,
                },
            ]
        );
    }

    #[test]
    fn recovery_handles_a_crash_after_every_nested_directory_publish() {
        for crash_index in 0..2 {
            let workspace = TestDirectory::new(&format!("directory-index-{crash_index}-workspace"));
            let private = TestDirectory::new(&format!("directory-index-{crash_index}-private"));
            let id = format!("directory-index-{crash_index}");
            let (grant, _base, staged) = staged_nested_creates(&workspace, &private, &id);
            let journal = private.0.join("journal");
            let mut first = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();

            assert!(matches!(
                first.apply_internal(
                    &grant,
                    &staged,
                    Some(FaultPoint::AfterDirectoryMutation(crash_index)),
                ),
                Err(CapabilityApplyError::InjectedCrash {
                    affected_operations
                }) if affected_operations == crash_index + 1
            ));
            drop(first);

            let mut reopened = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
            assert_eq!(
                reopened
                    .recover_pending(&grant)
                    .unwrap()
                    .recovered_change_sets(),
                &[id]
            );
            assert!(!workspace.0.join("shared").exists());
        }
    }

    #[test]
    fn every_preparation_crash_boundary_is_no_effect_recoverable_and_retryable() {
        let faults = [
            FaultPoint::AfterPreparationCreate,
            FaultPoint::AfterPreparationMode,
            FaultPoint::AfterPreparationDirectorySync,
            FaultPoint::AfterPreparationParentSync,
            FaultPoint::AfterPreparationBlob(1),
            FaultPoint::AfterPreparationBlob(2),
            FaultPoint::AfterPreparationBlob(3),
            FaultPoint::AfterPreparationBlob(4),
            FaultPoint::AfterPreparationPlan,
            FaultPoint::AfterPreparationPhase,
            FaultPoint::AfterPreparationRename,
            FaultPoint::AfterPreparationPublishSync,
        ];
        for (index, fault) in faults.into_iter().enumerate() {
            let workspace = TestDirectory::new(&format!("prepare-fault-{index}-workspace"));
            let private = TestDirectory::new(&format!("prepare-fault-{index}-private"));
            let id = format!("prepare-fault-{index}");
            let (grant, base, staged) = staged_three_file_change(&workspace, &private, &id);
            let journal = private.0.join("journal");
            let mut first = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();

            assert!(matches!(
                first.apply_internal(&grant, &staged, Some(fault)),
                Err(CapabilityApplyError::InjectedPreparationCrash { .. })
            ));
            assert_eq!(
                WorkspaceManifest::capture(&grant, 3)
                    .unwrap()
                    .snapshot()
                    .snapshot_id,
                base.snapshot().snapshot_id
            );
            drop(first);

            let mut reopened = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
            let report = reopened.recover_pending(&grant).unwrap();
            assert!(report.recovered_change_sets().is_empty());
            assert_eq!(report.abandoned_preparations().len(), 1);
            assert_eq!(
                WorkspaceManifest::capture(&grant, 4)
                    .unwrap()
                    .snapshot()
                    .snapshot_id,
                base.snapshot().snapshot_id
            );
            reopened.apply(&grant, &staged).unwrap();
        }
    }

    #[test]
    fn preparation_cleanup_rejects_unknown_links_and_hardlinks_without_deleting() {
        for unsafe_kind in ["unknown", "symlink", "hardlink"] {
            let workspace = TestDirectory::new(&format!("prepare-{unsafe_kind}-workspace"));
            let private = TestDirectory::new(&format!("prepare-{unsafe_kind}-private"));
            let id = format!("prepare-{unsafe_kind}");
            let (grant, _base, staged) = staged_single_create(&workspace, &private, &id);
            let journal = private.0.join("journal");
            let mut first = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
            assert!(matches!(
                first.apply_internal(&grant, &staged, Some(FaultPoint::AfterPreparationCreate)),
                Err(CapabilityApplyError::InjectedPreparationCrash { .. })
            ));
            drop(first);
            let preparation = journal.join(preparation_name(&transaction_name(&id)));
            match unsafe_kind {
                "unknown" => fs::write(preparation.join("unexpected"), b"must remain").unwrap(),
                "symlink" => {
                    let outside = private.0.join("outside");
                    fs::write(&outside, b"outside").unwrap();
                    symlink(&outside, preparation.join("base-000000")).unwrap();
                }
                "hardlink" => {
                    let first = preparation.join("base-000000");
                    fs::write(&first, b"linked").unwrap();
                    fs::set_permissions(&first, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::hard_link(&first, preparation.join("base-000001")).unwrap();
                }
                _ => unreachable!(),
            }

            let mut reopened = CapabilitySafeApplier::open(grant.clone(), &journal).unwrap();
            assert!(reopened.recover_pending(&grant).is_err());
            assert!(preparation.exists());
            assert_eq!(fs::read(workspace.0.join("anchor")).unwrap(), b"base");
            if unsafe_kind == "symlink" {
                assert_eq!(fs::read(private.0.join("outside")).unwrap(), b"outside");
            }
        }
    }

    #[test]
    fn corrupted_plan_fails_closed_before_recovery_mutates_live_targets() {
        let workspace = TestDirectory::new("plan-corruption-workspace");
        let private = TestDirectory::new("plan-corruption-private");
        let (grant, _base, staged) = staged_single_create(&workspace, &private, "plan-corruption");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        let (name, transaction, _plan) = applier.prepare_transaction(&staged, None).unwrap();
        drop(transaction);
        fs::write(
            private.0.join("journal").join(name).join("plan"),
            b"corrupt-plan\n",
        )
        .unwrap();

        assert!(matches!(
            applier.recover_pending(&grant),
            Err(CapabilityApplyError::Journal(message))
                if message.contains("plan version")
        ));
        assert!(!workspace.0.join("created").exists());
    }

    #[test]
    fn recovery_rejects_owned_apply_temp_inode_and_mode_substitution() {
        let workspace = TestDirectory::new("temp-inode-workspace");
        let private = TestDirectory::new("temp-inode-private");
        let id = "temp-inode";
        let (grant, _base, staged) = staged_single_create(&workspace, &private, id);
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        assert!(matches!(
            applier.apply_internal(&grant, &staged, Some(FaultPoint::AfterApplyTempIntent(0)),),
            Err(CapabilityApplyError::InjectedCrash { .. })
        ));
        let temporary = workspace
            .0
            .join(live_artifact_name(&transaction_name(id), 0, "apply"));
        let held = workspace.0.join("attacker-held-original-temp");
        fs::rename(&temporary, &held).unwrap();
        fs::write(&temporary, b"new bytes").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            applier.recover_pending(&grant),
            Err(CapabilityApplyError::RecoveryConflict { .. })
        ));
        assert!(!workspace.0.join("created").exists());

        let workspace = TestDirectory::new("temp-mode-workspace");
        let private = TestDirectory::new("temp-mode-private");
        let id = "temp-mode";
        let (grant, _base, staged) = staged_single_create(&workspace, &private, id);
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();
        assert!(matches!(
            applier.apply_internal(&grant, &staged, Some(FaultPoint::AfterApplyTempIntent(0)),),
            Err(CapabilityApplyError::InjectedCrash { .. })
        ));
        let temporary = workspace
            .0
            .join(live_artifact_name(&transaction_name(id), 0, "apply"));
        let original_mode = fs::metadata(&temporary).unwrap().mode() & 0o777;
        let substituted_mode = if original_mode == 0o600 { 0o640 } else { 0o600 };
        fs::set_permissions(&temporary, fs::Permissions::from_mode(substituted_mode)).unwrap();

        assert!(matches!(
            applier.recover_pending(&grant),
            Err(CapabilityApplyError::RecoveryConflict { .. })
        ));
        assert!(!workspace.0.join("created").exists());
    }

    #[test]
    fn create_no_replace_race_preserves_the_competing_file() {
        let workspace = TestDirectory::new("no-replace-race-workspace");
        let private = TestDirectory::new("no-replace-race-private");
        let (grant, _base, staged) = staged_single_create(&workspace, &private, "no-replace-race");
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        assert!(matches!(
            applier.apply_internal(
                &grant,
                &staged,
                Some(FaultPoint::BeforeCreateNoReplacePublish(0)),
            ),
            Err(CapabilityApplyError::ReconciliationRequired { .. })
        ));
        assert_eq!(
            fs::read(workspace.0.join("created")).unwrap(),
            b"racing writer"
        );
        assert!(matches!(
            applier.reconcile(&grant, "no-replace-race"),
            Err(CapabilityApplyError::RecoveryConflict { .. })
        ));
        assert_eq!(
            fs::read(workspace.0.join("created")).unwrap(),
            b"racing writer"
        );
    }

    #[test]
    fn state_parent_swap_and_workspace_journal_overlap_fail_before_effects() {
        let workspace = TestDirectory::new("state-parent-workspace");
        let private = TestDirectory::new("state-parent-private");
        let (grant, _base, staged) =
            staged_single_create(&workspace, &private, "state-parent-swap");
        let state_parent = private.0.join("state-parent");
        fs::create_dir(&state_parent).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), state_parent.join("journal")).unwrap();
        fs::rename(&state_parent, private.0.join("moved-state-parent")).unwrap();
        fs::create_dir(&state_parent).unwrap();

        assert!(matches!(
            applier.apply(&grant, &staged),
            Err(CapabilityApplyError::Root(_))
        ));
        assert!(!workspace.0.join("created").exists());

        let overlapping = workspace.0.join("journal-inside-workspace");
        assert!(matches!(
            CapabilitySafeApplier::open(grant, &overlapping),
            Err(CapabilityApplyError::Journal(_))
        ));
        assert!(!overlapping.exists());
    }

    #[test]
    fn existing_state_root_and_lock_permissions_are_rejected_not_repaired() {
        let workspace = TestDirectory::new("state-mode-workspace");
        let private = TestDirectory::new("state-mode-private");
        fs::write(workspace.0.join("anchor"), b"base").unwrap();
        let grant = issue_grant(&workspace.0);
        let journal = private.0.join("journal");
        fs::create_dir(&journal).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(
            CapabilitySafeApplier::open(grant.clone(), &journal),
            Err(CapabilityApplyError::Root(_))
        ));
        assert_eq!(fs::metadata(&journal).unwrap().mode() & 0o777, 0o755);

        fs::set_permissions(&journal, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = journal.join(WRITER_LOCK_NAME);
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            CapabilitySafeApplier::open(grant, &journal),
            Err(CapabilityApplyError::Journal(_))
        ));
        assert_eq!(fs::metadata(lock).unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn capability_workspace_stage_applies_and_rolls_back_without_legacy_pipeline() {
        let workspace = TestDirectory::new("capability-e2e-workspace");
        let private = TestDirectory::new("capability-e2e-private");
        fs::write(workspace.0.join("anchor"), b"before\n").unwrap();
        let store_path = private.0.join("store");
        fs::create_dir(&store_path).unwrap();
        fs::set_permissions(&store_path, fs::Permissions::from_mode(0o700)).unwrap();
        let grant = issue_grant(&workspace.0);
        let capability_workspace = CapabilityWorkspace::open(grant.clone()).unwrap();
        let store = CapabilityShadowStore::open(&store_path).unwrap();
        let base = capability_workspace.capture(&grant, 1).unwrap();
        let mut shadow = capability_workspace
            .create_shadow(&grant, &base, &store, "worker-capability")
            .unwrap();
        fs::write(shadow.root().join("anchor"), b"after\n").unwrap();
        fs::create_dir(shadow.root().join("docs")).unwrap();
        fs::write(shadow.root().join("docs/report.txt"), b"report\n").unwrap();
        let staged = shadow.stage_changes(&grant, "capability-e2e", 2).unwrap();
        let mut applier =
            CapabilitySafeApplier::open(grant.clone(), private.0.join("journal")).unwrap();

        applier.apply(&grant, &staged).unwrap();
        assert_eq!(fs::read(workspace.0.join("anchor")).unwrap(), b"after\n");
        assert_eq!(
            fs::read(workspace.0.join("docs/report.txt")).unwrap(),
            b"report\n"
        );
        applier.rollback(&grant, "capability-e2e").unwrap();
        assert_eq!(fs::read(workspace.0.join("anchor")).unwrap(), b"before\n");
        assert!(!workspace.0.join("docs").exists());
    }
