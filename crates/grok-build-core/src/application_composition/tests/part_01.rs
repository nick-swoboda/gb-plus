    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn base_file(
        path: &str,
        content: &str,
        byte_length: u64,
        unix_mode: u32,
    ) -> CompositionBaseFileV2 {
        CompositionBaseFileV2 {
            path: path.into(),
            content_digest: digest(content),
            byte_length,
            unix_mode,
        }
    }

    fn directory(path: &str) -> CompositionBaseDirectoryV2 {
        CompositionBaseDirectoryV2 { path: path.into() }
    }

    fn snapshot(files: &[CompositionBaseFileV2]) -> Digest {
        compute_workspace_manifest_digest(
            &files
                .iter()
                .map(|file| DescriptorRelativeManifestEntry {
                    path: file.path.clone(),
                    content_digest: file.content_digest.clone(),
                    byte_length: file.byte_length,
                    unix_mode: file.unix_mode,
                })
                .collect::<Vec<_>>(),
        )
        .expect("test manifest must be valid")
    }

    fn base_projection(
        files: Vec<CompositionBaseFileV2>,
        directories: Vec<CompositionBaseDirectoryV2>,
    ) -> NonAuthorizingCompositionBaseProjectionV2 {
        let snapshot = snapshot(&files);
        NonAuthorizingCompositionBaseProjectionV2::try_new_non_authorizing(
            snapshot,
            files,
            directories,
        )
        .expect("test base projection must be valid")
    }

    fn create(path: &str, result: &str) -> FileOperation {
        FileOperation::Create {
            path: PathBuf::from(path),
            result_hash: digest(result),
        }
    }

    fn modify(path: &str, base: &str, result: &str) -> FileOperation {
        FileOperation::Modify {
            path: PathBuf::from(path),
            base_hash: digest(base),
            result_hash: digest(result),
        }
    }

    fn delete(path: &str, base: &str) -> FileOperation {
        FileOperation::Delete {
            path: PathBuf::from(path),
            base_hash: digest(base),
        }
    }

    #[derive(Clone, Copy)]
    struct MaterialSpec {
        byte_length: u64,
        create_mode: Option<u32>,
    }

    fn material(byte_length: u64, create_mode: Option<u32>) -> MaterialSpec {
        MaterialSpec {
            byte_length,
            create_mode,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn source_result_named(
        ordinal: u32,
        task_id: &str,
        attempt_id: &str,
        proof_id: &str,
        receipt_id: &str,
        artifact_digest: Digest,
        base: &Digest,
        result: &Digest,
        operations: Vec<FileOperation>,
        material_specs: &[MaterialSpec],
    ) -> Result<NonAuthorizingApplicationCompositionSourceV2, CompositionConflict> {
        let change_set_id = format!("change-set-{ordinal}-{task_id}");
        let mut specs = material_specs.iter();
        let result_material = operations
            .iter()
            .enumerate()
            .filter_map(|(index, operation)| {
                let (path, result_digest, is_create) = match operation {
                    FileOperation::Create { path, result_hash } => (path, result_hash, true),
                    FileOperation::Modify {
                        path, result_hash, ..
                    } => (path, result_hash, false),
                    FileOperation::Delete { .. } => return None,
                };
                let spec = *specs
                    .next()
                    .expect("one material spec per result operation");
                Some(CompositionResultMaterialV2 {
                    operation_index: u32::try_from(index).expect("test operation index"),
                    path: path.to_str().expect("test path UTF-8").into(),
                    result_digest: result_digest.clone(),
                    byte_length: spec.byte_length,
                    operation_kind: if is_create {
                        CompositionResultMaterialKindV2::Create {
                            unix_mode: spec.create_mode.expect("create needs mode"),
                        }
                    } else {
                        assert!(spec.create_mode.is_none(), "modify cannot carry a mode");
                        CompositionResultMaterialKindV2::Modify
                    },
                    source_artifact_digest: artifact_digest.clone(),
                })
            })
            .collect::<Vec<_>>();
        assert!(specs.next().is_none(), "unexpected material spec");
        NonAuthorizingApplicationCompositionSourceV2::try_new_non_authorizing(
            ordinal,
            task_id,
            attempt_id,
            proof_id,
            digest(&format!("proof-{proof_id}")),
            receipt_id,
            digest(&format!("receipt-{receipt_id}")),
            ChangeSet {
                change_set_id: change_set_id.clone(),
                base_snapshot: base.clone(),
                result_snapshot: result.clone(),
                operations,
            },
            TaskIntegrationArtifactReference {
                format_version: COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2,
                artifact_digest,
                change_set_id,
                base_snapshot: base.clone(),
                result_snapshot: result.clone(),
            },
            result_material,
        )
    }

    fn source(
        ordinal: u32,
        base: &Digest,
        result: &Digest,
        operations: Vec<FileOperation>,
        materials: &[MaterialSpec],
    ) -> NonAuthorizingApplicationCompositionSourceV2 {
        source_result_named(
            ordinal,
            &format!("task-{ordinal}"),
            &format!("attempt-{ordinal}"),
            &format!("proof-{ordinal}"),
            &format!("receipt-{ordinal}"),
            digest(&format!("artifact-{ordinal}")),
            base,
            result,
            operations,
            materials,
        )
        .expect("test source must be valid")
    }

    fn final_verification(result: &Digest, attempt: &str) -> CompositionFinalVerificationBindingV2 {
        CompositionFinalVerificationBindingV2 {
            attempt_id: attempt.into(),
            attempt_authority_digest: digest(&format!("authority-{attempt}")),
            snapshot: result.clone(),
            complete_criterion_evidence_set_digest: digest(&format!("criteria-{attempt}")),
        }
    }

    fn inputs(
        base: &Digest,
        result: &Digest,
        sources: &[NonAuthorizingApplicationCompositionSourceV2],
    ) -> NonAuthorizingApplicationCompositionInputsV2 {
        NonAuthorizingApplicationCompositionInputsV2::try_new_non_authorizing(
            "sprint-1",
            base.clone(),
            result.clone(),
            digest("complete-task-done-set"),
            final_verification(result, "final-attempt-1"),
            sources
                .iter()
                .map(|source| source.source_identity.clone())
                .collect(),
        )
        .expect("test composition inputs must be valid")
    }

    fn multi_source_fixture() -> (
        NonAuthorizingApplicationCompositionInputsV2,
        NonAuthorizingCompositionBaseProjectionV2,
        Vec<NonAuthorizingApplicationCompositionSourceV2>,
    ) {
        let base_files = vec![
            base_file("a.txt", "a-0", 3, 0o644),
            base_file("dir/b.txt", "b-0", 3, 0o600),
        ];
        let base = snapshot(&base_files);
        let middle_files = vec![
            base_file("a.txt", "a-1", 4, 0o644),
            base_file("dir/b.txt", "b-0", 3, 0o600),
            base_file("z.txt", "z-1", 3, 0o640),
        ];
        let middle = snapshot(&middle_files);
        let result_files = vec![
            base_file("a.txt", "a-2", 5, 0o644),
            base_file("new.txt", "new-1", 5, 0o600),
            base_file("z.txt", "z-1", 3, 0o640),
        ];
        let result = snapshot(&result_files);
        let projection = NonAuthorizingCompositionBaseProjectionV2::try_new_non_authorizing(
            base.clone(),
            base_files,
            vec![directory("dir")],
        )
        .expect("fixture base projection");
        let sources = vec![
            source(
                0,
                &base,
                &middle,
                vec![create("z.txt", "z-1"), modify("a.txt", "a-0", "a-1")],
                &[material(3, Some(0o640)), material(4, None)],
            ),
            source(
                1,
                &middle,
                &result,
                vec![
                    create("new.txt", "new-1"),
                    delete("dir/b.txt", "b-0"),
                    modify("a.txt", "a-1", "a-2"),
                ],
                &[material(5, Some(0o600)), material(5, None)],
            ),
        ];
        let inputs = inputs(&base, &result, &sources);
        (inputs, projection, sources)
    }

    #[test]
    fn composes_exact_chain_with_modes_lengths_material_and_byte_sorted_aggregate() {
        let (inputs, base, sources) = multi_source_fixture();
        let plan = derive_non_authorizing_application_composition_v2(&inputs, &base, &sources)
            .expect("exact source chain must derive");
        assert_eq!(
            plan.change_set
                .operations
                .iter()
                .map(|operation| operation.path().to_str().expect("portable path"))
                .collect::<Vec<_>>(),
            vec!["a.txt", "dir/b.txt", "new.txt", "z.txt"]
        );
        assert_eq!(
            plan.result_material
                .iter()
                .map(|material| (material.path.as_str(), material.create_mode))
                .collect::<Vec<_>>(),
            vec![
                ("a.txt", None),
                ("new.txt", Some(0o600)),
                ("z.txt", Some(0o640))
            ]
        );
        assert_eq!(plan.final_directories, vec!["dir"]);
        plan.validate_integrity().expect("plan integrity readback");
        assert_eq!(
            plan,
            derive_non_authorizing_application_composition_v2(&inputs, &base, &sources)
                .expect("pure repeated derivation")
        );
    }

    #[test]
    fn source_operation_order_is_authenticated_while_only_aggregate_is_sorted() {
        let base = base_projection(Vec::new(), Vec::new());
        let result_files = vec![base_file("a", "a", 1, 0o600), base_file("b", "b", 1, 0o600)];
        let result = snapshot(&result_files);
        let first = source(
            0,
            &base.snapshot,
            &result,
            vec![create("b", "b"), create("a", "a")],
            &[material(1, Some(0o600)), material(1, Some(0o600))],
        );
        let second = source(
            0,
            &base.snapshot,
            &result,
            vec![create("a", "a"), create("b", "b")],
            &[material(1, Some(0o600)), material(1, Some(0o600))],
        );
        assert_ne!(first.source_identity, second.source_identity);
        let first_plan = derive_non_authorizing_application_composition_v2(
            &inputs(&base.snapshot, &result, std::slice::from_ref(&first)),
            &base,
            &[first],
        )
        .expect("first order");
        let second_plan = derive_non_authorizing_application_composition_v2(
            &inputs(&base.snapshot, &result, std::slice::from_ref(&second)),
            &base,
            &[second],
        )
        .expect("second order");
        assert_eq!(
            first_plan.change_set.operations,
            second_plan.change_set.operations
        );
        assert_ne!(
            first_plan.change_set.change_set_id,
            second_plan.change_set.change_set_id
        );
    }

    #[test]
    fn exact_net_zero_existing_file_path_remains_a_verified_no_op() {
        let base = base_projection(vec![base_file("a", "one", 3, 0o644)], Vec::new());
        let middle_files = vec![base_file("a", "two", 3, 0o644)];
        let middle = snapshot(&middle_files);
        let sources = vec![
            source(
                0,
                &base.snapshot,
                &middle,
                vec![modify("a", "one", "two")],
                &[material(3, None)],
            ),
            source(
                1,
                &middle,
                &base.snapshot,
                vec![modify("a", "two", "one")],
                &[material(3, None)],
            ),
        ];
        let plan = derive_non_authorizing_application_composition_v2(
            &inputs(&base.snapshot, &base.snapshot, &sources),
            &base,
            &sources,
        )
        .expect("existing-file net-zero retains identical topology");
        assert!(plan.change_set.operations.is_empty());
        assert!(plan.derivation_record.aggregate_no_op);
    }

    #[test]
    fn base_projection_recomputes_exact_workspace_manifest_v1_snapshot() {
        let files = vec![base_file("a", "a", 1, 0o644)];
        let forged = digest("forged-base-snapshot");
        assert!(matches!(
            NonAuthorizingCompositionBaseProjectionV2::try_new_non_authorizing(
                forged,
                files,
                Vec::new()
            ),
            Err(CompositionConflict::BaseSnapshotDigestMismatch { .. })
        ));
    }

    #[test]
    fn intermediate_snapshot_is_recomputed_instead_of_trusting_chain_labels() {
        let base = base_projection(vec![base_file("a", "old", 3, 0o644)], Vec::new());
        let forged_result = digest("forged-intermediate");
        let source = source(
            0,
            &base.snapshot,
            &forged_result,
            vec![modify("a", "old", "new")],
            &[material(3, None)],
        );
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(
                    &base.snapshot,
                    &forged_result,
                    std::slice::from_ref(&source)
                ),
                &base,
                &[source]
            ),
            Err(CompositionConflict::SourceResultSnapshotDigestMismatch { ordinal: 0, .. })
        ));
    }

    #[test]
    fn source_result_length_and_inherited_modify_mode_drive_snapshot_truth() {
        let base = base_projection(vec![base_file("a", "old", 3, 0o640)], Vec::new());
        let true_result = snapshot(&[base_file("a", "new", 4, 0o640)]);
        let source = source(
            0,
            &base.snapshot,
            &true_result,
            vec![modify("a", "old", "new")],
            &[material(3, None)],
        );
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(&base.snapshot, &true_result, std::slice::from_ref(&source)),
                &base,
                &[source]
            ),
            Err(CompositionConflict::SourceResultSnapshotDigestMismatch { ordinal: 0, .. })
        ));
    }

    #[test]
    fn delete_recreate_mode_change_fails_closed_instead_of_becoming_modify() {
        let base = base_projection(vec![base_file("a", "old", 3, 0o644)], Vec::new());
        let empty = snapshot(&[]);
        let result = snapshot(&[base_file("a", "new", 3, 0o600)]);
        let sources = vec![
            source(0, &base.snapshot, &empty, vec![delete("a", "old")], &[]),
            source(
                1,
                &empty,
                &result,
                vec![create("a", "new")],
                &[material(3, Some(0o600))],
            ),
        ];
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(&base.snapshot, &result, &sources),
                &base,
                &sources
            ),
            Err(CompositionConflict::UnrepresentableModeTransition {
                path,
                base_mode: 0o644,
                result_mode: 0o600
            }) if path == "a"
        ));
    }

    #[test]
    fn result_material_is_exactly_typed_and_bound_to_source_artifact() {
        let base = base_projection(Vec::new(), Vec::new());
        let result = snapshot(&[base_file("a", "new", 3, 0o600)]);
        let mut crossed_artifact_source = source(
            0,
            &base.snapshot,
            &result,
            vec![create("a", "new")],
            &[material(3, Some(0o600))],
        );
        crossed_artifact_source.result_material[0].source_artifact_digest =
            digest("crossed-artifact");
        assert!(matches!(
            crossed_artifact_source.validate_integrity(),
            Err(CompositionConflict::ResultMaterialMismatch {
                field: "source_artifact_digest",
                ..
            })
        ));

        let mut crossed_kind_source = source(
            0,
            &base.snapshot,
            &result,
            vec![create("a", "new")],
            &[material(3, Some(0o600))],
        );
        crossed_kind_source.result_material[0].operation_kind =
            CompositionResultMaterialKindV2::Modify;
        assert!(matches!(
            crossed_kind_source.validate_integrity(),
            Err(CompositionConflict::ResultMaterialMismatch {
                field: "operation_kind",
                ..
            })
        ));
    }

    #[test]
    fn empty_directory_occupancy_blocks_create() {
        let base = base_projection(Vec::new(), vec![directory("occupied")]);
        let result = snapshot(&[base_file("occupied", "new", 3, 0o600)]);
        let source = source(
            0,
            &base.snapshot,
            &result,
            vec![create("occupied", "new")],
            &[material(3, Some(0o600))],
        );
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(&base.snapshot, &result, std::slice::from_ref(&source)),
                &base,
                &[source]
            ),
            Err(CompositionConflict::CreateOverPresent {
                kind: CompositionEndpointKindV2::Directory,
                ..
            })
        ));
    }

    #[test]
    fn delete_child_then_create_parent_is_a_typed_topology_conflict() {
        let base = base_projection(
            vec![base_file("dir/child", "child", 5, 0o600)],
            vec![directory("dir")],
        );
        let result = snapshot(&[base_file("dir", "file", 4, 0o600)]);
        let source = source(
            0,
            &base.snapshot,
            &result,
            vec![delete("dir/child", "child"), create("dir", "file")],
            &[material(4, Some(0o600))],
        );
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(&base.snapshot, &result, std::slice::from_ref(&source)),
                &base,
                &[source]
            ),
            Err(CompositionConflict::CreateOverPresent {
                kind: CompositionEndpointKindV2::Directory,
                path,
                ..
            }) if path == "dir"
        ));
    }

    #[test]
    fn net_zero_create_delete_in_new_directory_does_not_change_snapshot_semantics() {
        let base = base_projection(Vec::new(), Vec::new());
        let middle = snapshot(&[base_file("dir/file", "file", 4, 0o600)]);
        let sources = vec![
            source(
                0,
                &base.snapshot,
                &middle,
                vec![create("dir/file", "file")],
                &[material(4, Some(0o600))],
            ),
            source(
                1,
                &middle,
                &base.snapshot,
                vec![delete("dir/file", "file")],
                &[],
            ),
        ];
        let plan = derive_non_authorizing_application_composition_v2(
            &inputs(&base.snapshot, &base.snapshot, &sources),
            &base,
            &sources,
        )
        .expect("ephemeral empty directories are outside workspace-manifest-v1 semantics");
        assert!(plan.change_set.operations.is_empty());
        assert!(plan.final_directories.is_empty());
    }

    #[test]
    fn delete_file_then_create_descendant_remains_representable() {
        let base = base_projection(vec![base_file("dir", "old", 3, 0o600)], Vec::new());
        let result = snapshot(&[base_file("dir/child", "new", 3, 0o640)]);
        let source = source(
            0,
            &base.snapshot,
            &result,
            vec![delete("dir", "old"), create("dir/child", "new")],
            &[material(3, Some(0o640))],
        );
        let plan = derive_non_authorizing_application_composition_v2(
            &inputs(&base.snapshot, &result, std::slice::from_ref(&source)),
            &base,
            &[source],
        )
        .expect("delete ancestor before creating descendant is representable");
        assert_eq!(plan.final_directories, vec!["dir"]);
    }

    #[test]
    fn base_directory_projection_must_be_complete_canonical_and_disjoint() {
        let file = base_file("a/b", "b", 1, 0o600);
        let files = vec![file.clone()];
        let state = snapshot(&files);
        assert!(matches!(
            NonAuthorizingCompositionBaseProjectionV2::try_new_non_authorizing(
                state.clone(),
                files.clone(),
                Vec::new()
            ),
            Err(CompositionConflict::IncompleteDirectoryProjection { .. })
        ));
        assert!(matches!(
            NonAuthorizingCompositionBaseProjectionV2::try_new_non_authorizing(
                state.clone(),
                files.clone(),
                vec![directory("a"), directory("a")]
            ),
            Err(CompositionConflict::NonCanonicalPathOrder { .. })
        ));
        let same_path_files = vec![base_file("a", "a", 1, 0o600)];
        assert!(matches!(
            NonAuthorizingCompositionBaseProjectionV2::try_new_non_authorizing(
                snapshot(&same_path_files),
                same_path_files,
                vec![directory("a")]
            ),
            Err(CompositionConflict::BaseTopologyConflict { .. })
        ));
    }

    #[test]
    fn missing_extra_reordered_and_crossed_sources_fail_closed() {
        let (inputs, base, sources) = multi_source_fixture();
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(&inputs, &base, &sources[..1]),
            Err(CompositionConflict::SourceCoverageCountMismatch { .. })
        ));
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs,
                &base,
                &[sources[1].clone(), sources[0].clone()]
            ),
            Err(CompositionConflict::SourceOrdinalMismatch { .. })
        ));
        let mut crossed = sources.clone();
        crossed[0].source_identity = digest("crossed-source");
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(&inputs, &base, &crossed),
            Err(CompositionConflict::SourceDigestMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_artifact_digest_is_legal_when_exact_per_source_links_differ() {
        let base = base_projection(Vec::new(), Vec::new());
        let shared_artifact = digest("shared-empty-artifact");
        let first = source_result_named(
            0,
            "task-0",
            "attempt-0",
            "proof-0",
            "receipt-0",
            shared_artifact.clone(),
            &base.snapshot,
            &base.snapshot,
            Vec::new(),
            &[],
        )
        .expect("first no-op source");
        let second = source_result_named(
            1,
            "task-1",
            "attempt-1",
            "proof-1",
            "receipt-1",
            shared_artifact,
            &base.snapshot,
            &base.snapshot,
            Vec::new(),
            &[],
        )
        .expect("second no-op source");
        let sources = vec![first, second];
        derive_non_authorizing_application_composition_v2(
            &inputs(&base.snapshot, &base.snapshot, &sources),
            &base,
            &sources,
        )
        .expect("artifact deduplication is not a duplicate source identity");
    }

    #[test]
    fn source_operation_and_file_byte_bounds_match_stage_bundle_limits() {
        let base = snapshot(&[]);
        let result = digest("oversized-result");
        let operations = (0..=MAX_COMPOSITION_OPERATIONS_V2)
            .map(|index| create(&format!("p-{index:04}"), &format!("v-{index}")))
            .collect::<Vec<_>>();
        let artifact = digest("oversized-ops-artifact");
        let change_set_id = "oversized-ops".to_owned();
        assert!(matches!(
            NonAuthorizingApplicationCompositionSourceV2::try_new_non_authorizing(
                0,
                "task",
                "attempt",
                "proof",
                digest("proof"),
                "receipt",
                digest("receipt"),
                ChangeSet {
                    change_set_id: change_set_id.clone(),
                    base_snapshot: base.clone(),
                    result_snapshot: result.clone(),
                    operations,
                },
                TaskIntegrationArtifactReference {
                    format_version: COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2,
                    artifact_digest: artifact,
                    change_set_id,
                    base_snapshot: base,
                    result_snapshot: result,
                },
                Vec::new()
            ),
            Err(CompositionConflict::LimitExceeded {
                field: "composition_source.operations",
                ..
            })
        ));

        let base = base_projection(Vec::new(), Vec::new());
        let result = snapshot(&[base_file("a", "a", 1, 0o600)]);
        let oversized = source_result_named(
            0,
            "task",
            "attempt",
            "proof",
            "receipt",
            digest("artifact"),
            &base.snapshot,
            &result,
            vec![create("a", "a")],
            &[material(MAX_COMPOSITION_FILE_BYTES_V2 + 1, Some(0o600))],
        );
        assert!(matches!(
            oversized,
            Err(CompositionConflict::ByteLimitExceeded {
                field: "composition_source.result_material.byte_length"
                    | "composition.result_blob.byte_length",
                ..
            })
        ));
    }

    #[test]
    fn multiple_lawful_source_bundles_do_not_share_one_bundle_byte_cap() {
        let base = base_projection(Vec::new(), Vec::new());
        let middle_files = vec![
            base_file("a", "a", MAX_COMPOSITION_FILE_BYTES_V2, 0o600),
            base_file("b", "b", MAX_COMPOSITION_FILE_BYTES_V2, 0o600),
            base_file("c", "c", MAX_COMPOSITION_FILE_BYTES_V2, 0o600),
        ];
        let middle = snapshot(&middle_files);
        let result_files = vec![
            base_file("d", "d", MAX_COMPOSITION_FILE_BYTES_V2, 0o600),
            base_file("e", "e", MAX_COMPOSITION_FILE_BYTES_V2, 0o600),
            base_file("f", "f", MAX_COMPOSITION_FILE_BYTES_V2, 0o600),
        ];
        let result = snapshot(&result_files);
        let sources = vec![
            source(
                0,
                &base.snapshot,
                &middle,
                vec![create("a", "a"), create("b", "b"), create("c", "c")],
                &[
                    material(MAX_COMPOSITION_FILE_BYTES_V2, Some(0o600)),
                    material(MAX_COMPOSITION_FILE_BYTES_V2, Some(0o600)),
                    material(MAX_COMPOSITION_FILE_BYTES_V2, Some(0o600)),
                ],
            ),
            source(
                1,
                &middle,
                &result,
                vec![
                    delete("a", "a"),
                    delete("b", "b"),
                    delete("c", "c"),
                    create("d", "d"),
                    create("e", "e"),
                    create("f", "f"),
                ],
                &[
                    material(MAX_COMPOSITION_FILE_BYTES_V2, Some(0o600)),
                    material(MAX_COMPOSITION_FILE_BYTES_V2, Some(0o600)),
                    material(MAX_COMPOSITION_FILE_BYTES_V2, Some(0o600)),
                ],
            ),
        ];
        derive_non_authorizing_application_composition_v2(
            &inputs(&base.snapshot, &result, &sources),
            &base,
            &sources,
        )
        .expect("each source and the aggregate independently fit the 64 MiB limit");
    }

    #[test]
    fn source_and_aggregate_total_byte_caps_are_independently_enforced() {
        let base = base_projection(Vec::new(), Vec::new());
        let five_files = ["a", "b", "c", "d", "e"]
            .into_iter()
            .map(|path| base_file(path, path, MAX_COMPOSITION_FILE_BYTES_V2, 0o600))
            .collect::<Vec<_>>();
        let final_snapshot = snapshot(&five_files);
        let five_creates = ["a", "b", "c", "d", "e"]
            .into_iter()
            .map(|path| create(path, path))
            .collect::<Vec<_>>();
        let five_materials = vec![material(MAX_COMPOSITION_FILE_BYTES_V2, Some(0o600)); 5];
        assert!(matches!(
            source_result_named(
                0,
                "task",
                "attempt",
                "proof",
                "receipt",
                digest("artifact"),
                &base.snapshot,
                &final_snapshot,
                five_creates,
                &five_materials,
            ),
            Err(CompositionConflict::ByteLimitExceeded {
                field: "composition_source.result_blob_bytes",
                ..
            })
        ));

        let middle_files = five_files[..3].to_vec();
        let middle_snapshot = snapshot(&middle_files);
        let sources = vec![
            source(
                0,
                &base.snapshot,
                &middle_snapshot,
                vec![create("a", "a"), create("b", "b"), create("c", "c")],
                &[material(MAX_COMPOSITION_FILE_BYTES_V2, Some(0o600)); 3],
            ),
            source(
                1,
                &middle_snapshot,
                &final_snapshot,
                vec![create("d", "d"), create("e", "e")],
                &[material(MAX_COMPOSITION_FILE_BYTES_V2, Some(0o600)); 2],
            ),
        ];
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(&base.snapshot, &final_snapshot, &sources),
                &base,
                &sources,
            ),
            Err(CompositionConflict::ByteLimitExceeded {
                field: "composition.aggregate_blob_bytes",
                ..
            })
        ));
    }

    #[test]
    fn source_count_and_canonical_input_bytes_are_bounded() {
        let identities = (0..=MAX_COMPOSITION_SOURCES_V2)
            .map(|index| digest(&format!("source-{index}")))
            .collect::<Vec<_>>();
        assert!(matches!(
            NonAuthorizingApplicationCompositionInputsV2::try_new_non_authorizing(
                "sprint",
                digest("base"),
                digest("result"),
                digest("task-set"),
                final_verification(&digest("result"), "final"),
                identities
            ),
            Err(CompositionConflict::LimitExceeded {
                field: "composition_inputs.expected_source_identities",
                ..
            })
        ));

        let base = base_projection(Vec::new(), Vec::new());
        let oversized_identifier = "x".repeat(MAX_COMPOSITION_IDENTIFIER_BYTES_V2 + 1);
        let source = source_result_named(
            0,
            &oversized_identifier,
            "attempt",
            "proof",
            "receipt",
            digest("artifact"),
            &base.snapshot,
            &base.snapshot,
            Vec::new(),
            &[],
        );
        assert!(matches!(
            source,
            Err(CompositionConflict::LimitExceeded {
                field: "composition_source.task_id",
                ..
            })
        ));

        let huge_change_set_id = "x".repeat(MAX_COMPOSITION_CANONICAL_INPUT_BYTES_V2 + 1);
        assert!(matches!(
            NonAuthorizingApplicationCompositionSourceV2::try_new_non_authorizing(
                0,
                "task",
                "attempt",
                "proof",
                digest("proof"),
                "receipt",
                digest("receipt"),
                ChangeSet {
                    change_set_id: huge_change_set_id.clone(),
                    base_snapshot: base.snapshot.clone(),
                    result_snapshot: base.snapshot.clone(),
                    operations: Vec::new(),
                },
                TaskIntegrationArtifactReference {
                    format_version: COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2,
                    artifact_digest: digest("artifact"),
                    change_set_id: huge_change_set_id,
                    base_snapshot: base.snapshot.clone(),
                    result_snapshot: base.snapshot,
                },
                Vec::new(),
            ),
            Err(CompositionConflict::LimitExceeded {
                field: "composition_source",
                ..
            })
        ));
    }

    #[test]
    fn plan_integrity_detects_material_directory_and_record_substitution() {
        let (inputs, base, sources) = multi_source_fixture();
        let plan = derive_non_authorizing_application_composition_v2(&inputs, &base, &sources)
            .expect("fixture plan");
        let mut crossed = plan.clone();
        crossed.result_material[0].byte_length += 1;
        assert!(matches!(
            crossed.validate_integrity(),
            Err(CompositionConflict::DerivationRecordMismatch {
                field: "aggregate_result_material_digest"
            })
        ));
        let mut crossed = plan.clone();
        crossed.final_directories.clear();
        assert!(matches!(
            crossed.validate_integrity(),
            Err(CompositionConflict::DerivationRecordMismatch {
                field: "final_directory_state_digest"
            })
        ));
        let mut crossed = plan;
        crossed.derivation_record.record_digest = digest("forged-record");
        assert!(matches!(
            crossed.validate_integrity(),
            Err(CompositionConflict::DerivationRecordMismatch {
                field: "record_digest"
            })
        ));
    }

    #[test]
    fn source_identity_binds_result_material_and_exact_bundle_version() {
        let base = base_projection(Vec::new(), Vec::new());
        let result = snapshot(&[base_file("a", "a", 1, 0o600)]);
        let mut crossed_material_source = source(
            0,
            &base.snapshot,
            &result,
            vec![create("a", "a")],
            &[material(1, Some(0o600))],
        );
        crossed_material_source.result_material[0].byte_length = 2;
        assert!(matches!(
            crossed_material_source.validate_integrity(),
            Err(CompositionConflict::SourceDigestMismatch {
                kind: CompositionSourceDigestKind::SourceIdentity,
                ..
            })
        ));
        let mut crossed_version_source = source(
            0,
            &base.snapshot,
            &result,
            vec![create("a", "a")],
            &[material(1, Some(0o600))],
        );
        crossed_version_source.artifact.format_version += 1;
        assert!(matches!(
            crossed_version_source.validate_integrity(),
            Err(CompositionConflict::InvalidSourceShape {
                kind: CompositionSourceShapeConflict::InvalidArtifactVersion,
                ..
            })
        ));
    }

    #[test]
    fn noncontiguous_ordinals_broken_chain_and_crossed_final_verification_fail_closed() {
        let base = base_projection(Vec::new(), Vec::new());
        let result = snapshot(&[base_file("a", "a", 1, 0o600)]);
        let wrong_ordinal = source(
            2,
            &base.snapshot,
            &result,
            vec![create("a", "a")],
            &[material(1, Some(0o600))],
        );
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(
                    &base.snapshot,
                    &result,
                    std::slice::from_ref(&wrong_ordinal)
                ),
                &base,
                &[wrong_ordinal]
            ),
            Err(CompositionConflict::SourceOrdinalMismatch {
                expected: 0,
                observed: 2
            })
        ));

        let wrong_base = digest("wrong-input-snapshot");
        let broken = source(
            0,
            &wrong_base,
            &result,
            vec![create("a", "a")],
            &[material(1, Some(0o600))],
        );
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(&base.snapshot, &result, std::slice::from_ref(&broken)),
                &base,
                &[broken]
            ),
            Err(CompositionConflict::SnapshotChainMismatch {
                source_ordinal: Some(0),
                ..
            })
        ));

        let valid = source(
            0,
            &base.snapshot,
            &result,
            vec![create("a", "a")],
            &[material(1, Some(0o600))],
        );
        let mut crossed_inputs = inputs(&base.snapshot, &result, std::slice::from_ref(&valid));
        crossed_inputs.final_verification.snapshot = digest("other-final");
        assert!(matches!(
            crossed_inputs.validate_integrity(),
            Err(CompositionConflict::SnapshotChainMismatch {
                source_ordinal: None,
                ..
            })
        ));
    }

    #[test]
    fn duplicate_operations_unlawful_endpoints_and_base_hash_crossing_fail_closed() {
        let base = base_projection(vec![base_file("a", "old", 3, 0o600)], Vec::new());
        let result = digest("result");
        assert!(matches!(
            source_result_named(
                0,
                "task",
                "attempt",
                "proof",
                "receipt",
                digest("artifact"),
                &base.snapshot,
                &result,
                vec![modify("a", "old", "new"), delete("a", "old")],
                &[material(3, None)]
            ),
            Err(CompositionConflict::DuplicateOperation { path, .. }) if path == "a"
        ));

        let create_present = source(
            0,
            &base.snapshot,
            &result,
            vec![create("a", "new")],
            &[material(3, Some(0o600))],
        );
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(
                    &base.snapshot,
                    &result,
                    std::slice::from_ref(&create_present)
                ),
                &base,
                &[create_present]
            ),
            Err(CompositionConflict::CreateOverPresent {
                kind: CompositionEndpointKindV2::RegularFile,
                ..
            })
        ));

        let empty = base_projection(Vec::new(), Vec::new());
        for operation in [modify("a", "old", "new"), delete("a", "old")] {
            let material = if matches!(operation, FileOperation::Modify { .. }) {
                vec![material(3, None)]
            } else {
                Vec::new()
            };
            let absent = source(0, &empty.snapshot, &result, vec![operation], &material);
            assert!(matches!(
                derive_non_authorizing_application_composition_v2(
                    &inputs(&empty.snapshot, &result, std::slice::from_ref(&absent)),
                    &empty,
                    &[absent]
                ),
                Err(CompositionConflict::ModifyOverInvalidEndpoint { .. }
                    | CompositionConflict::DeleteOverInvalidEndpoint { .. })
            ));
        }

        let crossed_hash = source(
            0,
            &base.snapshot,
            &result,
            vec![modify("a", "wrong", "new")],
            &[material(3, None)],
        );
        assert!(matches!(
            derive_non_authorizing_application_composition_v2(
                &inputs(
                    &base.snapshot,
                    &result,
                    std::slice::from_ref(&crossed_hash)
                ),
                &base,
                &[crossed_hash]
            ),
            Err(CompositionConflict::BaseHashMismatch { path, .. }) if path == "a"
        ));
    }

    #[test]
    fn source_shape_digests_and_projection_digests_reject_substitution() {
        let base = base_projection(Vec::new(), Vec::new());
        let result = snapshot(&[base_file("a", "a", 1, 0o600)]);
        let original = source(
            0,
            &base.snapshot,
            &result,
            vec![create("a", "a")],
            &[material(1, Some(0o600))],
        );
        let mut crossed = original.clone();
        crossed.ordered_operations_digest = digest("crossed-operations");
        assert!(matches!(
            crossed.validate_integrity(),
            Err(CompositionConflict::SourceDigestMismatch {
                kind: CompositionSourceDigestKind::OrderedOperations,
                ..
            })
        ));
        let mut crossed = original.clone();
        crossed.touched_endpoints_digest = digest("crossed-endpoints");
        assert!(matches!(
            crossed.validate_integrity(),
            Err(CompositionConflict::SourceDigestMismatch {
                kind: CompositionSourceDigestKind::TouchedEndpoints,
                ..
            })
        ));
        let mut crossed = original;
        crossed.source_identity = digest("crossed-source");
        assert!(matches!(
            crossed.validate_integrity(),
            Err(CompositionConflict::SourceDigestMismatch {
                kind: CompositionSourceDigestKind::SourceIdentity,
                ..
            })
        ));
        let mut crossed_base = base;
        crossed_base.projection_digest = digest("crossed-projection");
        assert!(matches!(
            crossed_base.validate_integrity(),
            Err(CompositionConflict::BaseProjectionDigestMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_task_attempt_proof_and_receipt_members_are_rejected() {
        let base = base_projection(Vec::new(), Vec::new());
        let middle = snapshot(&[base_file("a", "a", 1, 0o600)]);
        let result = snapshot(&[base_file("a", "a", 1, 0o600), base_file("b", "b", 1, 0o600)]);
        let first = source_result_named(
            0,
            "task-0",
            "attempt-0",
            "proof-0",
            "receipt-0",
            digest("artifact-0"),
            &base.snapshot,
            &middle,
            vec![create("a", "a")],
            &[material(1, Some(0o600))],
        )
        .expect("first source");
        let cases = [
            ("task-0", "attempt-1", "proof-1", "receipt-1", "task_id"),
            ("task-1", "attempt-0", "proof-1", "receipt-1", "attempt_id"),
            (
                "task-1",
                "attempt-1",
                "proof-0",
                "receipt-1",
                "task_done_proof_id",
            ),
            (
                "task-1",
                "attempt-1",
                "proof-1",
                "receipt-0",
                "integration_receipt_id",
            ),
        ];
        for (task, attempt, proof, receipt, expected_field) in cases {
            let second = source_result_named(
                1,
                task,
                attempt,
                proof,
                receipt,
                digest("artifact-1"),
                &middle,
                &result,
                vec![create("b", "b")],
                &[material(1, Some(0o600))],
            )
            .expect("second source");
            let sources = vec![first.clone(), second];
            assert!(matches!(
                derive_non_authorizing_application_composition_v2(
                    &inputs(&base.snapshot, &result, &sources),
                    &base,
                    &sources
                ),
                Err(CompositionConflict::DuplicateSourceMember { field, .. })
                    if field == expected_field
            ));
        }
    }

    #[test]
    fn source_set_and_derivation_domains_bind_task_set_base_and_final_verification() {
        let (first_inputs, base, sources) = multi_source_fixture();
        let first =
            derive_non_authorizing_application_composition_v2(&first_inputs, &base, &sources)
                .expect("first plan");
        let second_inputs = NonAuthorizingApplicationCompositionInputsV2::try_new_non_authorizing(
            first_inputs.sprint_id.clone(),
            first_inputs.base_snapshot.clone(),
            first_inputs.result_snapshot.clone(),
            digest("different-task-set"),
            first_inputs.final_verification.clone(),
            first_inputs.expected_source_identities.clone(),
        )
        .expect("second inputs");
        let second =
            derive_non_authorizing_application_composition_v2(&second_inputs, &base, &sources)
                .expect("second plan");
        assert_ne!(
            first.change_set.change_set_id,
            second.change_set.change_set_id
        );

        let mut final_crossed = first_inputs.clone();
        final_crossed.final_verification.attempt_id = "different-final".into();
        let final_crossed =
            derive_non_authorizing_application_composition_v2(&final_crossed, &base, &sources)
                .expect("final verification is a derivation-record domain");
        assert_eq!(
            first.change_set.change_set_id,
            final_crossed.change_set.change_set_id
        );
        assert_ne!(
            first.derivation_record.record_digest,
            final_crossed.derivation_record.record_digest
        );
    }

    #[test]
    fn empty_authority_tampered_source_set_and_unsupported_versions_fail_closed() {
        let result = digest("result");
        assert!(matches!(
            NonAuthorizingApplicationCompositionInputsV2::try_new_non_authorizing(
                "sprint",
                digest("base"),
                result.clone(),
                digest("task-set"),
                final_verification(&result, "final"),
                Vec::new()
            ),
            Err(CompositionConflict::LimitExceeded {
                field: "composition_inputs.expected_source_identities",
                observed: 0,
                ..
            })
        ));
        let (mut inputs, mut base, _) = multi_source_fixture();
        inputs.source_set_digest = digest("tampered-source-set");
        assert!(matches!(
            inputs.validate_integrity(),
            Err(CompositionConflict::SourceSetDigestMismatch { .. })
        ));
        base.composer_version += 1;
        assert!(matches!(
            base.validate_integrity(),
            Err(CompositionConflict::UnsupportedComposerVersion { .. })
        ));
    }

    #[allow(
        clippy::type_complexity,
        clippy::too_many_lines,
        reason = "one deterministic fixture assembles every mutually bound publication contract"
    )]
    fn publication_contract_fixture() -> (
        NonAuthorizingApplicationCompositionPublicationClaimV2,
        NonAuthorizingApplicationCompositionSourceReadbackV2,
        NonAuthorizingApplicationCompositionPlanV2,
        NonAuthorizingApplicationCompositionAggregateReadbackV2,
        NonAuthorizingApplicationCompositionPublicationClosureV2,
        ApplicationArtifactCompositionReceiptV2,
    ) {
        let (inputs, base, sources) = multi_source_fixture();
        let authorities = sources
            .iter()
            .map(|source| {
                NonAuthorizingApplicationCompositionSourceAuthorityV2::try_new_non_authorizing(
                    source.ordinal,
                    source.task_id.clone(),
                    source.attempt_id.clone(),
                    source.task_done_proof_id.clone(),
                    source.task_done_proof_digest.clone(),
                    source.integration_receipt_id.clone(),
                    source.integration_receipt_digest.clone(),
                    source.artifact.clone(),
                    source_result_blob_bytes(source).expect("fixture source blob bytes"),
                    u32::try_from(source.change_set.operations.len())
                        .expect("fixture source operation count"),
                )
                .expect("fixture source authority")
            })
            .collect();
        let claim =
            NonAuthorizingApplicationCompositionPublicationClaimV2::try_new_non_authorizing(
                "publication-1",
                inputs,
                base,
                authorities,
            )
            .expect("fixture publication claim");
        let source_readback =
            NonAuthorizingApplicationCompositionSourceReadbackV2::try_new_non_authorizing(
                &claim, sources,
            )
            .expect("fixture source readback");
        let plan = derive_non_authorizing_application_composition_v2(
            &claim.inputs,
            &claim.base,
            &source_readback.sources,
        )
        .expect("fixture composition plan");
        let mut blob_lengths = BTreeMap::new();
        let mut create_modes = Vec::new();
        for material in &plan.result_material {
            if let Some(previous) =
                blob_lengths.insert(material.result_digest.clone(), material.byte_length)
            {
                assert_eq!(previous, material.byte_length);
            }
            if let Some(unix_mode) = material.create_mode {
                create_modes.push(CompositionAggregateCreateModeReadbackV2 {
                    path: material.path.clone(),
                    unix_mode,
                });
            }
        }
        create_modes.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let aggregate_artifact = TaskIntegrationArtifactReference {
            format_version: COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2,
            artifact_digest: digest("aggregate-artifact"),
            change_set_id: plan.change_set.change_set_id.clone(),
            base_snapshot: plan.change_set.base_snapshot.clone(),
            result_snapshot: plan.change_set.result_snapshot.clone(),
        };
        let aggregate_readback =
            NonAuthorizingApplicationCompositionAggregateReadbackV2::try_new_non_authorizing(
                &claim,
                aggregate_artifact,
                plan.change_set.clone(),
                blob_lengths
                    .into_iter()
                    .map(|(digest, byte_length)| CompositionAggregateBlobReadbackV2 {
                        digest,
                        byte_length,
                    })
                    .collect(),
                create_modes,
            )
            .expect("fixture aggregate readback");
        let closure =
            NonAuthorizingApplicationCompositionPublicationClosureV2::try_new_non_authorizing(
                &claim,
                &aggregate_readback,
                digest("publication-journal"),
                digest("published-journal-head"),
            )
            .expect("fixture publication closure");
        let receipt = ApplicationArtifactCompositionReceiptV2::try_new_non_authorizing(
            &claim,
            &source_readback,
            &plan,
            &aggregate_readback,
            &closure,
        )
        .expect("fixture composition receipt");
        (
            claim,
            source_readback,
            plan,
            aggregate_readback,
            closure,
            receipt,
        )
    }

    fn source_authority_with_accounting(
        source: &NonAuthorizingApplicationCompositionSourceAuthorityV2,
        reopened_result_blob_bytes: u64,
        source_operation_count: u32,
    ) -> Result<NonAuthorizingApplicationCompositionSourceAuthorityV2, CompositionConflict> {
        NonAuthorizingApplicationCompositionSourceAuthorityV2::try_new_non_authorizing(
            source.ordinal,
            source.task_id.clone(),
            source.attempt_id.clone(),
            source.task_done_proof_id.clone(),
            source.task_done_proof_digest.clone(),
            source.integration_receipt_id.clone(),
            source.integration_receipt_digest.clone(),
            source.artifact.clone(),
            reopened_result_blob_bytes,
            source_operation_count,
        )
    }

    #[test]
    fn publication_contracts_round_trip_rederive_and_match_digest_goldens() {
        let (claim, source_readback, plan, aggregate_readback, closure, receipt) =
            publication_contract_fixture();
        let claim_round_trip: NonAuthorizingApplicationCompositionPublicationClaimV2 =
            serde_json::from_slice(&serde_json::to_vec(&claim).expect("encode claim"))
                .expect("decode claim");
        let source_round_trip: NonAuthorizingApplicationCompositionSourceReadbackV2 =
            serde_json::from_slice(
                &serde_json::to_vec(&source_readback).expect("encode source readback"),
            )
            .expect("decode source readback");
        let aggregate_round_trip: NonAuthorizingApplicationCompositionAggregateReadbackV2 =
            serde_json::from_slice(
                &serde_json::to_vec(&aggregate_readback).expect("encode aggregate readback"),
            )
            .expect("decode aggregate readback");
        let closure_round_trip: NonAuthorizingApplicationCompositionPublicationClosureV2 =
            serde_json::from_slice(&serde_json::to_vec(&closure).expect("encode closure"))
                .expect("decode closure");
        let receipt_round_trip: ApplicationArtifactCompositionReceiptV2 =
            serde_json::from_slice(&serde_json::to_vec(&receipt).expect("encode receipt"))
                .expect("decode receipt");
        assert_eq!(claim_round_trip, claim);
        assert_eq!(source_round_trip, source_readback);
        assert_eq!(aggregate_round_trip, aggregate_readback);
        assert_eq!(closure_round_trip, closure);
        assert_eq!(receipt_round_trip, receipt);
        assert_eq!(
            claim.publication_claim_digest.as_str(),
            "14c96afadc8cfd5982aa10ff932b0e2c43f7a157d632c50205bae394cffac0c9"
        );
        assert_eq!(
            source_readback.source_readback_digest.as_str(),
            "1608903b2044d08584ea39b82c5f6125d7312362145d286ff288389025c33287"
        );
        assert_eq!(
            aggregate_readback.aggregate_readback_digest.as_str(),
            "8f8205874fcb5166ac6d216cb460263b13c155720d8affa85fb868c137cca8c5"
        );
        assert_eq!(
            closure.publication_closure_observation_digest.as_str(),
            "38a158b9d1a3230da2b757e31849a6d6b3488d21148dbf9619b25184d3933208"
        );
        assert_eq!(
            receipt.receipt_digest.as_str(),
            "0914020a7f7873dce83ffc669bdb0a356740f296d98718db22e247bd68573efe"
        );
        receipt
            .validate_against_non_authorizing(
                &claim,
                &source_readback,
                &plan,
                &aggregate_readback,
                &closure,
            )
            .expect("round-tripped receipt backing");
    }

    #[test]
    fn publication_claim_rejects_omitted_reordered_and_crossed_sources() {
        let (claim, _, _, _, _, _) = publication_contract_fixture();
        let mut omitted = claim.clone();
        omitted.sources.pop();
        assert!(omitted.validate_integrity().is_err());
        let mut reordered = claim.clone();
        reordered.sources.swap(0, 1);
        assert!(reordered.validate_integrity().is_err());
        let mut crossed = claim;
        crossed.sources[0].integration_receipt_id = "crossed-receipt".into();
        assert!(crossed.validate_integrity().is_err());
    }

    #[test]
    fn publication_claim_accounting_accepts_exact_bounds_and_rejects_one_over() {
        let (claim, _, _, _, _, _) = publication_contract_fixture();
        let first = &claim.sources[0];
        source_authority_with_accounting(
            first,
            MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2,
            first.source_operation_count,
        )
        .expect("one exact-bound source is representable");
        assert!(matches!(
            source_authority_with_accounting(
                first,
                MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2 + 1,
                first.source_operation_count,
            ),
            Err(CompositionConflict::ByteLimitExceeded {
                field: "source_authority.reopened_result_blob_bytes",
                ..
            })
        ));

        let first_bytes = MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2 / 2;
        let second_bytes = MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2 - first_bytes;
        let exact_sources = vec![
            source_authority_with_accounting(
                &claim.sources[0],
                first_bytes,
                claim.sources[0].source_operation_count,
            )
            .unwrap(),
            source_authority_with_accounting(
                &claim.sources[1],
                second_bytes,
                claim.sources[1].source_operation_count,
            )
            .unwrap(),
        ];
        NonAuthorizingApplicationCompositionPublicationClaimV2::try_new_non_authorizing(
            claim.publication_id.clone(),
            claim.inputs.clone(),
            claim.base.clone(),
            exact_sources,
        )
        .expect("exact cumulative source-byte bound");
        let over_sources = vec![
            source_authority_with_accounting(
                &claim.sources[0],
                first_bytes,
                claim.sources[0].source_operation_count,
            )
            .unwrap(),
            source_authority_with_accounting(
                &claim.sources[1],
                second_bytes + 1,
                claim.sources[1].source_operation_count,
            )
            .unwrap(),
        ];
        assert!(matches!(
            NonAuthorizingApplicationCompositionPublicationClaimV2::try_new_non_authorizing(
                claim.publication_id,
                claim.inputs,
                claim.base,
                over_sources,
            ),
            Err(CompositionConflict::ByteLimitExceeded {
                field: "publication_claim.reopened_source_bytes",
                ..
            })
        ));
    }

    #[test]
    fn publication_claim_operation_accounting_rejects_the_first_source_over_the_total() {
        fn declared_sources(
            count: usize,
            snapshot: &Digest,
        ) -> Vec<NonAuthorizingApplicationCompositionSourceAuthorityV2> {
            (0..count)
                .map(|index| {
                    let ordinal = u32::try_from(index).unwrap();
                    NonAuthorizingApplicationCompositionSourceAuthorityV2::try_new_non_authorizing(
                        ordinal,
                        format!("declared-task-{index}"),
                        format!("declared-attempt-{index}"),
                        format!("declared-proof-{index}"),
                        digest(&format!("declared-proof-digest-{index}")),
                        format!("declared-integration-{index}"),
                        digest(&format!("declared-integration-digest-{index}")),
                        TaskIntegrationArtifactReference {
                            format_version: COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2,
                            artifact_digest: digest(&format!("declared-artifact-{index}")),
                            change_set_id: format!("declared-change-{index}"),
                            base_snapshot: snapshot.clone(),
                            result_snapshot: snapshot.clone(),
                        },
                        0,
                        u32::try_from(MAX_COMPOSITION_OPERATIONS_V2).unwrap(),
                    )
                    .unwrap()
                })
                .collect()
        }

        let base = base_projection(Vec::new(), Vec::new());
        let base_snapshot = base.snapshot.clone();
        let exact_count =
            MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2 / MAX_COMPOSITION_OPERATIONS_V2;
        let exact_sources = declared_sources(exact_count, &base_snapshot);
        let exact_inputs = NonAuthorizingApplicationCompositionInputsV2::try_new_non_authorizing(
            "declared-operation-sprint",
            base_snapshot.clone(),
            base_snapshot.clone(),
            digest("declared-complete-task-set"),
            final_verification(&base_snapshot, "declared-final"),
            (0..exact_count)
                .map(|index| digest(&format!("declared-source-identity-{index}")))
                .collect(),
        )
        .unwrap();
        NonAuthorizingApplicationCompositionPublicationClaimV2::try_new_non_authorizing(
            "declared-operation-publication",
            exact_inputs,
            base.clone(),
            exact_sources,
        )
        .expect("exact cumulative source-operation bound");

        let over_count = exact_count + 1;
        let over_inputs = NonAuthorizingApplicationCompositionInputsV2::try_new_non_authorizing(
            "declared-operation-sprint",
            base_snapshot.clone(),
            base_snapshot.clone(),
            digest("declared-complete-task-set"),
            final_verification(&base_snapshot, "declared-final"),
            (0..over_count)
                .map(|index| digest(&format!("declared-source-identity-{index}")))
                .collect(),
        )
        .unwrap();
        assert!(matches!(
            NonAuthorizingApplicationCompositionPublicationClaimV2::try_new_non_authorizing(
                "declared-operation-publication",
                over_inputs,
                base,
                declared_sources(over_count, &base_snapshot),
            ),
            Err(CompositionConflict::LimitExceeded {
                field: "publication_claim.reopened_source_operations",
                ..
            })
        ));
    }

    #[test]
    fn publication_readbacks_reject_source_blob_mode_and_artifact_crossing() {
        let (claim, source_readback, _, aggregate_readback, _, _) = publication_contract_fixture();
        let mut crossed_source = source_readback;
        crossed_source.sources[0].task_done_proof_id = "crossed-proof".into();
        assert!(
            crossed_source
                .validate_against_non_authorizing(&claim)
                .is_err()
        );
        let mut crossed_blob = aggregate_readback.clone();
        crossed_blob.blobs[0].byte_length += 1;
        assert!(
            crossed_blob
                .validate_against_non_authorizing(&claim)
                .is_err()
        );
        let mut crossed_mode = aggregate_readback.clone();
        crossed_mode.create_modes[0].unix_mode ^= 0o100;
        assert!(
            crossed_mode
                .validate_against_non_authorizing(&claim)
                .is_err()
        );
        let mut crossed_artifact = aggregate_readback;
        crossed_artifact.aggregate_artifact.artifact_digest = digest("crossed-artifact");
        assert!(
            crossed_artifact
                .validate_against_non_authorizing(&claim)
                .is_err()
        );

        let (claim, source_readback, _, _, _, _) = publication_contract_fixture();
        let mut misstated_sources = claim.sources.clone();
        misstated_sources[0] = source_authority_with_accounting(
            &claim.sources[0],
            claim.sources[0].reopened_result_blob_bytes + 1,
            claim.sources[0].source_operation_count,
        )
        .unwrap();
        let misstated_claim =
            NonAuthorizingApplicationCompositionPublicationClaimV2::try_new_non_authorizing(
                claim.publication_id,
                claim.inputs,
                claim.base,
                misstated_sources,
            )
            .unwrap();
        assert!(matches!(
            NonAuthorizingApplicationCompositionSourceReadbackV2::try_new_non_authorizing(
                &misstated_claim,
                source_readback.sources,
            ),
            Err(CompositionConflict::PublicationReadbackMismatch {
                field: "source_readback_authority"
            })
        ));
    }

    #[test]
    fn receipt_is_inseparable_from_exact_published_journal_closure() {
        let (claim, source_readback, plan, aggregate_readback, closure, receipt) =
            publication_contract_fixture();
        let crossed_closure =
            NonAuthorizingApplicationCompositionPublicationClosureV2::try_new_non_authorizing(
                &claim,
                &aggregate_readback,
                digest("other-journal"),
                digest("other-published-head"),
            )
            .expect("alternate caller-manufacturable closure");
        assert!(
            receipt
                .validate_against_non_authorizing(
                    &claim,
                    &source_readback,
                    &plan,
                    &aggregate_readback,
                    &crossed_closure,
                )
                .is_err()
        );
        let mut crossed_receipt = receipt;
        crossed_receipt.published_journal_head_digest = digest("crossed-published-head");
        assert!(crossed_receipt.validate_integrity().is_err());
        closure
            .validate_against_non_authorizing(&claim, &aggregate_readback)
            .expect("original closure remains exact");
    }

    #[test]
    fn publication_contracts_deny_unknown_fields_and_bound_identifiers() {
        let (claim, source_readback, _, aggregate_readback, closure, receipt) =
            publication_contract_fixture();
        let mut values = vec![
            serde_json::to_value(&claim).expect("claim JSON"),
            serde_json::to_value(&source_readback).expect("source JSON"),
            serde_json::to_value(&aggregate_readback).expect("aggregate JSON"),
            serde_json::to_value(&closure).expect("closure JSON"),
            serde_json::to_value(&receipt).expect("receipt JSON"),
        ];
        for value in &mut values {
            value
                .as_object_mut()
                .expect("contract object")
                .insert("unknown".into(), serde_json::json!(true));
        }
        assert!(
            serde_json::from_value::<NonAuthorizingApplicationCompositionPublicationClaimV2>(
                values.remove(0)
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<NonAuthorizingApplicationCompositionSourceReadbackV2>(
                values.remove(0)
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<NonAuthorizingApplicationCompositionAggregateReadbackV2>(
                values.remove(0)
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<NonAuthorizingApplicationCompositionPublicationClosureV2>(
                values.remove(0)
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<ApplicationArtifactCompositionReceiptV2>(values.remove(0))
                .is_err()
        );
        let mut oversized = claim;
        oversized.publication_id = "x".repeat(MAX_COMPOSITION_IDENTIFIER_BYTES_V2 + 1);
        assert!(matches!(
            oversized.validate_integrity(),
            Err(CompositionConflict::LimitExceeded {
                field: "publication_claim.publication_id",
                ..
            })
        ));
    }

    #[test]
    fn nonportable_paths_and_unknown_fields_fail_closed() {
        let base = base_projection(Vec::new(), Vec::new());
        let result = digest("result");
        for path in [
            "",
            "/absolute",
            "a\\b",
            "a//b",
            "./a",
            "a/../b",
            ".git/config",
        ] {
            assert!(matches!(
                source_result_named(
                    0,
                    "task",
                    "attempt",
                    "proof",
                    "receipt",
                    digest("artifact"),
                    &base.snapshot,
                    &result,
                    vec![create(path, "new")],
                    &[material(1, Some(0o600))]
                ),
                Err(CompositionConflict::InvalidPortablePath { .. })
            ));
        }
        let (inputs, _, sources) = multi_source_fixture();
        let mut json = serde_json::to_value(inputs).expect("serialize inputs");
        json.as_object_mut()
            .expect("object")
            .insert("publication_authority".into(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<NonAuthorizingApplicationCompositionInputsV2>(json).is_err()
        );
        let mut json = serde_json::to_value(&sources[0]).expect("serialize source");
        json.as_object_mut()
            .expect("object")
            .insert("reopened".into(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<NonAuthorizingApplicationCompositionSourceV2>(json).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_source_path_is_a_typed_portability_conflict() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let base = base_projection(Vec::new(), Vec::new());
        let operation = FileOperation::Create {
            path: PathBuf::from(OsString::from_vec(vec![b'a', 0xff])),
            result_hash: digest("new"),
        };
        let result = digest("result");
        let change_set_id = String::from("non-utf8");
        assert!(matches!(
            NonAuthorizingApplicationCompositionSourceV2::try_new_non_authorizing(
                0,
                "task",
                "attempt",
                "proof",
                digest("proof"),
                "receipt",
                digest("receipt"),
                ChangeSet {
                    change_set_id: change_set_id.clone(),
                    base_snapshot: base.snapshot.clone(),
                    result_snapshot: result.clone(),
                    operations: vec![operation],
                },
                TaskIntegrationArtifactReference {
                    format_version: COMPOSITION_SOURCE_BUNDLE_FORMAT_VERSION_V2,
                    artifact_digest: digest("artifact"),
                    change_set_id,
                    base_snapshot: base.snapshot,
                    result_snapshot: result,
                },
                Vec::new()
            ),
            Err(CompositionConflict::InvalidPortablePath {
                kind: PortablePathConflictKind::NonUtf8,
                ..
            })
        ));
    }
