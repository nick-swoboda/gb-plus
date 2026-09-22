    #[test]
    fn capture_id_is_a_no_replay_fence_and_writer_lock_is_cross_process_visible() {
        let fixture = Fixture::new();
        let first_store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let second_store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "journal-lock", 8);
        let claim =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = first_store
            .reserve_anchored_capture(&intent, &claim, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();
        assert!(matches!(
            second_store.reserve_anchored_capture(&intent, &claim, 2),
            Err(CommandOutputStoreError::Io { .. })
        ));

        let capture = first_store.reopen_anchored_capture(&acquired).unwrap();
        assert!(matches!(
            second_store.reopen_capture(&intent.capture_id),
            Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(id),
                ..
            }) if id == intent.capture_id
        ));
        let (stdout, stderr, publisher) = capture.split();
        drop(stdout);
        drop(stderr);
        drop(publisher);
        let restarted = second_store.reopen_capture(&intent.capture_id).unwrap();
        assert_eq!(
            restarted.state(),
            super::CommandOutputCaptureJournalStateV1::WriterAttached
        );
        assert_eq!(restarted.store_head().generation, 3);
    }

    #[test]
    fn exact_id_recovery_classifies_and_resolves_torn_and_synced_record_cuts() {
        for (index, cut, expected_class, expected_cleanup_generation) in [
            (
                0,
                super::command_output_journal::InjectedRecordCut::TempCreated,
                super::command_output_journal::CommandOutputCapturePendingRecordClassV1::Torn,
                4,
            ),
            (
                1,
                super::command_output_journal::InjectedRecordCut::BytesSynced,
                super::command_output_journal::CommandOutputCapturePendingRecordClassV1::ValidSuccessor,
                5,
            ),
        ] {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let label = format!("journal-record-cut-{index}");
            let intent = capture_intent(&fixture, &label, 8);
            let dispatch = super::command_output_journal::expected_dispatch_claim_id(
                &intent.source.effect_id,
            );
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            super::command_output_journal::inject_writer_attached_record_cut(
                &store,
                &intent.capture_id,
                cut,
            )
            .expect("inject exact interrupted record");
            let recovery = store
                .reopen_capture(&intent.capture_id)
                .expect("classify exact pending record");
            let pending = recovery.pending_record().expect("pending record");
            assert_eq!(pending.sequence(), 3);
            assert_eq!(pending.class(), expected_class);

            let claim = recovery_claim(&intent.capture_id, 1, None);
            let cleaned = store
                .cleanup_capture(&claim, &acquired.store_head)
                .expect("fenced owner resolves exact pending record and cleans");
            assert_eq!(
                cleaned.state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned
            );
            assert_eq!(
                cleaned.cleaned_store_head().unwrap().generation,
                expected_cleanup_generation
            );
            assert!(cleaned.pending_record().is_none());
        }
    }

    #[test]
    fn concurrent_identical_publishers_converge_on_one_exact_artifact() {
        let fixture = Fixture::new();
        let source = source("concurrent");
        let mut publications = Vec::new();
        for _ in 0..2 {
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let capture = store
                .reserve_capture(source.clone(), 12)
                .expect("reserve capture");
            let (mut stdout, mut stderr, publisher) = capture.split();
            stdout.append(b"stdout").unwrap();
            stderr.append(b"stderr").unwrap();
            publications.push((
                publisher,
                stdout.finish().unwrap(),
                stderr.finish().unwrap(),
            ));
        }
        let barrier = Arc::new(Barrier::new(2));
        let handles = publications
            .into_iter()
            .map(|(publisher, stdout, stderr)| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    publisher
                        .publish(stdout, stderr)
                        .map(|artifact| artifact.reference().clone())
                })
            })
            .collect::<Vec<_>>();
        let mut references = Vec::new();
        for handle in handles {
            references.push(handle.join().expect("publisher thread").expect("publish"));
        }
        assert_eq!(references[0], references[1]);
        let artifact = artifact_path(&fixture.state, &source);
        assert!(
            artifact
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(FINAL_PREFIX)
        );
        assert_eq!(fs::read_dir(artifact).unwrap().count(), 3);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one matrix test proves generic refusal and branch-specific recovery for every prelaunch v2 generation"
    )]
    fn prelaunch_abort_is_derived_only_from_exact_zero_through_three_prefixes() {
        for (generation, core_has_acquisition) in
            [(0_u64, false), (1, false), (2, false), (2, true), (3, true)]
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(
                &fixture,
                &format!("prelaunch-g{generation}-core-acquired-{core_has_acquisition}"),
                4_096,
            );
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
            let mut core_acquired = None;
            match generation {
                0 => {
                    store
                        .reserve_anchored_capture(&intent, &dispatch, 2)
                        .expect("reserve v1 without v2 prefix")
                        .into_acquired_anchor_for_handoff()
                        .expect("close v1 acquired handoff");
                }
                1 => {
                    super::sensitive_output_journal::record_intent(&store, &intent, &policy)
                        .expect("record v2 intent prefix");
                    store
                        .reserve_anchored_capture(&intent, &dispatch, 2)
                        .expect("reserve v1 after v2 intent")
                        .into_acquired_anchor_for_handoff()
                        .expect("close v1 acquired handoff");
                }
                2 | 3 => {
                    let acquired = store
                        .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
                        .expect("reserve v2 capture")
                        .into_acquired_anchor_for_handoff()
                        .expect("close acquired handoff");
                    if core_has_acquisition {
                        core_acquired = Some(acquired.clone());
                    }
                    if generation == 3 {
                        drop(
                            store
                                .reopen_anchored_capture_v2(&acquired, &policy)
                                .expect("record writer-attached prefix"),
                        );
                    }
                }
                _ => unreachable!(),
            }
            let claim = recovery_claim(&intent.capture_id, 1, None);
            if generation > 0 {
                let before = store
                    .reopen_capture(&intent.capture_id)
                    .expect("reopen pre-launch v1 custody before generic refusals");
                let acquired = before
                    .acquired()
                    .cloned()
                    .expect("every pre-launch fixture has physical acquisition");
                assert!(
                    store
                        .reconcile_capture_restart(&intent, &claim, Some(before.store_head()),)
                        .is_err(),
                    "generic reconciliation must reject every present v2 prefix"
                );
                assert!(
                    store.cleanup_capture(&claim, before.store_head()).is_err(),
                    "generic cleanup must reject every present v2 prefix"
                );
                let timestamp_called = Cell::new(false);
                assert!(
                    store
                        .resolve_unknown_capture(
                            &intent,
                            &acquired,
                            before.store_head(),
                            &claim,
                            before.store_head(),
                            || {
                                timestamp_called.set(true);
                                Ok(claim.acquired_at_unix_ms + 1)
                            },
                        )
                        .is_err(),
                    "generic Unknown resolution must reject every present v2 prefix"
                );
                assert!(!timestamp_called.get());
                assert_same_durable_capture(
                    &store
                        .reopen_capture(&intent.capture_id)
                        .expect("generic pre-launch refusal leaves v1 unchanged"),
                    &before,
                );
            }
            let disposition = store
                .resume_sensitive_output_prelaunch_abort_v2(&intent, core_acquired.as_ref(), &claim)
                .expect("finish exact pre-launch cleanup");
            disposition.validate().expect("validate joined disposition");
            assert_eq!(disposition.v2_generation(), generation);
            assert_eq!(disposition.capture_id(), intent.capture_id);
            assert_eq!(
                store
                    .reopen_sensitive_output_prelaunch_aborted_v2(&intent)
                    .expect("reopen derived disposition"),
                Some(disposition.disposition().clone())
            );
            let physical = disposition
                .fenced_v1_recovery()
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .expect("materialize exact initial prelaunch fence evidence");
            physical
                .validate_against(&intent, &claim, core_acquired.as_ref())
                .expect("initial prelaunch fence matches exact core acquisition authority");
            assert_eq!(
                physical.requested_store_head.as_ref(),
                core_acquired.as_ref().map(|acquired| &acquired.store_head)
            );

            let second_claim = recovery_claim(&intent.capture_id, 2, Some(claim.claim_id.clone()));
            let repeated = store
                .resume_sensitive_output_prelaunch_abort_v2(
                    &intent,
                    core_acquired.as_ref(),
                    &second_claim,
                )
                .expect("fresh higher claim fences idempotent pre-launch readback");
            assert_eq!(
                repeated.disposition(),
                disposition.disposition(),
                "idempotent fencing cannot change the immutable v1/v2 disposition"
            );
            assert_eq!(repeated.reconciliation_claim(), &second_claim);
            let repeated_physical = repeated
                .fenced_v1_recovery()
                .physical_reconciliation_evidence(
                    &intent,
                    &second_claim,
                    second_claim.acquired_at_unix_ms + 1,
                )
                .expect("materialize higher-claim idempotent fence evidence");
            repeated_physical
                .validate_against(&intent, &second_claim, core_acquired.as_ref())
                .expect("idempotent recovery remains exact core-bound evidence");
            assert_eq!(
                repeated_physical.requested_store_head.as_ref(),
                core_acquired.as_ref().map(|acquired| &acquired.store_head)
            );

            assert!(
                store
                    .resume_sensitive_output_prelaunch_abort_v2(
                        &intent,
                        core_acquired.as_ref(),
                        &claim,
                    )
                    .is_err(),
                "the superseded prelaunch claim cannot regain physical authority"
            );
            let crossed_capture_id = Digest::sha256(b"crossed-prelaunch-capture").to_string();
            let crossed_claim = recovery_claim(&crossed_capture_id, 1, None);
            assert!(
                store
                    .resume_sensitive_output_prelaunch_abort_v2(
                        &intent,
                        core_acquired.as_ref(),
                        &crossed_claim,
                    )
                    .is_err(),
                "a claim for another capture cannot fence prelaunch recovery"
            );
        }
    }

    #[test]
    fn prelaunch_abort_cleanup_retry_completes_exact_interrupted_plan() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "prelaunch-cleanup-retry", 4_096);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
            .expect("reserve v2 capture")
            .into_acquired_anchor_for_handoff()
            .expect("close acquired handoff");
        let first_claim = recovery_claim(&intent.capture_id, 1, None);
        let error = super::command_output_journal::inject_restart_cleanup_cut(
            &store,
            &intent,
            &first_claim,
            Some(&acquired.store_head),
            super::command_output_journal::CleanupCheckpoint::CleanupIntended,
        )
        .expect_err("inject cleanup crash cut");
        assert!(error.to_string().contains("CleanupIntended"));
        assert_eq!(
            store.capture_state(&intent.capture_id).expect("reopen cut"),
            super::CommandOutputCaptureJournalStateV1::CleanupIntended
        );
        let second_claim =
            recovery_claim(&intent.capture_id, 2, Some(first_claim.claim_id.clone()));
        let disposition = store
            .resume_sensitive_output_prelaunch_abort_v2(&intent, Some(&acquired), &second_claim)
            .expect("resume exact interrupted cleanup");
        assert_eq!(disposition.v2_generation(), 2);
        disposition.validate().expect("validate retry disposition");
    }

    #[test]
    fn arbitrary_empty_v2_directory_is_not_generation_zero() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "arbitrary-empty-v2", 4_096);
        let directory = fixture
            .state
            .join(format!("sensitive-output-journal-v2-{}", intent.capture_id));
        fs::create_dir(&directory).expect("create arbitrary empty v2 directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("set arbitrary directory mode");
        let lock = directory.join("writer.lock");
        fs::write(&lock, []).expect("create empty writer lock");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))
            .expect("set writer-lock mode");
        let error = store
            .reopen_sensitive_output_prelaunch_aborted_v2(&intent)
            .expect_err("an existing empty v2 directory is malformed, not generation zero");
        assert!(error.to_string().contains("empty sensitive-output journal"));
    }

    #[test]
    fn generation_four_remains_unknown_and_prelaunch_cleanup_does_not_mutate_v1() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "prelaunch-g4-unknown", 4_096);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
            .expect("reserve v2 capture")
            .into_acquired_anchor_for_handoff()
            .expect("close acquired handoff");
        let capture = store
            .reopen_anchored_capture_v2(&acquired, &policy)
            .expect("attach writer");
        let (stdout, stderr, mut publisher) = capture.split();
        #[cfg(target_os = "linux")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::linux();
        #[cfg(target_os = "macos")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::macos();
        publisher
            .record_launch_intended_v2(
                "prelaunch-g4-test/v1",
                br#"{"fixture":"g4-unknown"}"#.to_vec(),
                &core_dump,
            )
            .expect("record generation-four launch boundary");
        drop(stdout);
        drop(stderr);
        drop(publisher);
        let claim = recovery_claim(&intent.capture_id, 1, None);
        assert!(matches!(
            store.resume_sensitive_output_prelaunch_abort_v2(&intent, Some(&acquired), &claim),
            Err(CommandOutputStoreError::ReconciliationRequired { .. })
        ));
        assert_eq!(
            store.capture_state(&intent.capture_id).expect("reopen v1"),
            super::CommandOutputCaptureJournalStateV1::LaunchIntended
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&intent.capture_id)
                .expect("reopen v2")
                .head()
                .generation,
            4
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        clippy::items_after_statements,
        reason = "the exact split-cut regression keeps launch classification, crossed-proof nonmutation, zero-first cleanup, immutable-head readback, and idempotence together"
    )]
    fn split_launch_quarantine_is_zero_first_unknown_and_preserves_both_immutable_heads() {
        fn inspect_retained(
            path: &Path,
            forbidden: &[&[u8]],
            forbidden_digests: &[String],
            observed_zero_lengths: &mut usize,
        ) {
            for entry in fs::read_dir(path).expect("enumerate retained split-launch state") {
                let entry = entry.expect("read retained split-launch entry");
                let file_type = entry.file_type().expect("inspect retained entry type");
                if file_type.is_dir() {
                    inspect_retained(
                        &entry.path(),
                        forbidden,
                        forbidden_digests,
                        observed_zero_lengths,
                    );
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                let bytes = fs::read(entry.path()).expect("read retained split-launch evidence");
                for value in forbidden {
                    assert!(
                        !bytes.windows(value.len()).any(|window| window == *value),
                        "pre-zero output bytes survived split-launch quarantine"
                    );
                }
                for digest in forbidden_digests {
                    assert!(
                        !bytes
                            .windows(digest.len())
                            .any(|window| window == digest.as_bytes()),
                        "pre-zero output digest survived split-launch quarantine"
                    );
                }
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                    continue;
                };
                fn inspect_json(
                    value: &serde_json::Value,
                    output_object: bool,
                    observed_zero_lengths: &mut usize,
                ) {
                    match value {
                        serde_json::Value::Object(fields) => {
                            for (field, value) in fields {
                                if output_object && field == "byte_length" {
                                    *observed_zero_lengths += 1;
                                    assert_eq!(
                                        value.as_u64(),
                                        Some(0),
                                        "retained split-launch output length must be constant zero"
                                    );
                                }
                                assert!(
                                    ![
                                        "output_digest",
                                        "fingerprint",
                                        "offset",
                                        "matched_length",
                                        "matched_rule",
                                        "summary",
                                    ]
                                    .contains(&field.as_str()),
                                    "retained split-launch evidence contains derived field {field}"
                                );
                                inspect_json(
                                    value,
                                    output_object || matches!(field.as_str(), "stdout" | "stderr"),
                                    observed_zero_lengths,
                                );
                            }
                        }
                        serde_json::Value::Array(values) => {
                            for value in values {
                                inspect_json(value, output_object, observed_zero_lengths);
                            }
                        }
                        _ => {}
                    }
                }
                inspect_json(&value, false, observed_zero_lengths);
            }
        }

        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "split-launch-quarantine", 4_096);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
            .expect("reserve v2 split-launch capture")
            .into_acquired_anchor_for_handoff()
            .expect("close split-launch acquisition handoff");
        let capture = store
            .reopen_anchored_capture_v2(&acquired, &policy)
            .expect("attach split-launch v2 writer");
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        let launch_head = publisher
            .record_launch_intended(
                "split-launch-quarantine-test/v1",
                br#"{"fixture":"crash-after-v1-before-v2"}"#.to_vec(),
            )
            .expect("inject exact crash cut after v1 LaunchIntended before v2 generation four");
        let stdout_prefix = b"split-launch stdout prefix with nonconstant length";
        let stderr_prefix = b"split-launch stderr prefix with another length";
        stdout
            .append(stdout_prefix)
            .expect("stage split-launch stdout prefix");
        stderr
            .append(stderr_prefix)
            .expect("stage split-launch stderr prefix");
        drop(stdout);
        drop(stderr);
        drop(publisher);

        let before_v1 = store
            .reopen_capture(&intent.capture_id)
            .expect("reopen exact v1 split-launch cut");
        let before_v2 = store
            .reopen_sensitive_output_journal_v2(&intent.capture_id)
            .expect("reopen exact v2 split-launch cut");
        assert_eq!(
            before_v1.state(),
            super::CommandOutputCaptureJournalStateV1::LaunchIntended
        );
        assert_eq!(before_v1.launch_intended_store_head(), Some(&launch_head));
        assert_eq!(before_v2.head().generation, 3);
        assert!(matches!(
            before_v2.stage(),
            super::SensitiveOutputJournalStageV2::WriterAttached { .. }
        ));

        let claim = recovery_claim(&intent.capture_id, 1, None);
        assert!(matches!(
            store.resume_sensitive_output_prelaunch_abort_v2(&intent, Some(&acquired), &claim),
            Err(CommandOutputStoreError::ReconciliationRequired { .. })
        ));
        assert_same_durable_capture(
            &store
                .reopen_capture(&intent.capture_id)
                .expect("prelaunch refusal leaves split v1 unchanged"),
            &before_v1,
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&intent.capture_id)
                .expect("prelaunch refusal leaves split v2 unchanged"),
            before_v2
        );

        let binding = crate::CommandDomainCleanupBinding::try_new(
            intent.source.runner_session_id.clone(),
            intent.source.effect_id.clone(),
            intent.source.request_digest.clone(),
        )
        .expect("construct exact split-launch cleanup binding");
        let native_cleanup_proof =
            crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&binding);
        assert!(
            store
                .quarantine_split_sensitive_output_launch_v2(
                    &intent,
                    &claim,
                    crate::CommandDomainCleanupBackend::MacOsDedicatedIdentity,
                    &native_cleanup_proof,
                )
                .is_err(),
            "crossed native backend must fail before split-launch output mutation"
        );
        let crossed_binding = crate::CommandDomainCleanupBinding::try_new(
            intent.source.runner_session_id.clone(),
            "crossed-split-launch-effect",
            intent.source.request_digest.clone(),
        )
        .expect("construct crossed split-launch cleanup binding");
        let crossed_proof =
            crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&crossed_binding);
        assert!(
            store
                .quarantine_split_sensitive_output_launch_v2(
                    &intent,
                    &claim,
                    crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                    &crossed_proof,
                )
                .is_err(),
            "crossed native request binding must fail before split-launch output mutation"
        );
        assert_same_durable_capture(
            &store
                .reopen_capture(&intent.capture_id)
                .expect("crossed proofs leave split v1 unchanged"),
            &before_v1,
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&intent.capture_id)
                .expect("crossed proofs leave split v2 unchanged"),
            before_v2
        );

        let quarantine = store
            .quarantine_split_sensitive_output_launch_v2(
                &intent,
                &claim,
                crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                &native_cleanup_proof,
            )
            .expect("zero-first quarantine exact split-launch Unknown");
        quarantine
            .validate()
            .expect("validate typed split-launch quarantine");
        assert_eq!(quarantine.v2_writer_attached(), &before_v2);
        assert_eq!(quarantine.v1_launch_intended_store_head(), &launch_head);
        assert_eq!(
            quarantine.command_domain_cleanup_proof_id(),
            native_cleanup_proof.os_evidence_digest()
        );
        assert_eq!(
            quarantine.v1_cleaned().state(),
            super::CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert!(quarantine.v1_cleaned().expected_reference().is_none());
        super::command_output_journal::validate_sensitive_cleanup_plan_zero(
            &store,
            &acquired,
            &launch_head,
        )
        .expect("split-launch quarantine persisted only a zero-length cleanup plan");

        let repeated = store
            .quarantine_split_sensitive_output_launch_v2(
                &intent,
                &claim,
                crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                &native_cleanup_proof,
            )
            .expect("same split-launch quarantine is idempotent");
        assert_eq!(
            repeated.v2_writer_attached(),
            quarantine.v2_writer_attached()
        );
        assert_eq!(
            repeated.v1_cleaned().store_head(),
            quarantine.v1_cleaned().store_head()
        );
        assert_eq!(
            repeated.v1_cleaned().launch_intended_store_head(),
            quarantine.v1_cleaned().launch_intended_store_head()
        );
        let first_physical = quarantine
            .v1_cleaned()
            .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
            .expect("first split-launch quarantine retains exact fenced evidence");
        let repeated_physical = repeated
            .v1_cleaned()
            .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
            .expect("idempotent split-launch quarantine retains exact fenced evidence");
        first_physical
            .validate_against(&intent, &claim, Some(&acquired))
            .expect("first split-launch physical evidence remains core-bound");
        repeated_physical
            .validate_against(&intent, &claim, Some(&acquired))
            .expect("idempotent split-launch physical evidence remains core-bound");
        assert_eq!(
            first_physical.final_store_head,
            repeated_physical.final_store_head
        );

        let forbidden_digests = [
            Digest::sha256(stdout_prefix).to_string(),
            Digest::sha256(stderr_prefix).to_string(),
        ];
        let mut observed_zero_lengths = 0;
        inspect_retained(
            &fixture.state,
            &[stdout_prefix, stderr_prefix],
            &forbidden_digests,
            &mut observed_zero_lengths,
        );
        assert!(
            observed_zero_lengths >= 2,
            "split-launch cleanup evidence must expose constant-zero object lengths"
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&intent.capture_id)
                .expect("split-launch v2 prefix remains immutable"),
            before_v2
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression keeps the exact split cut, valid join, two crossed authorities, and both no-mutation readbacks contiguous"
    )]
    fn unknown_terminal_join_rejects_crossed_head_and_acquisition_without_mutation() {
        fn snapshot_directory(path: &Path) -> Vec<(String, Vec<u8>)> {
            let mut snapshot = fs::read_dir(path)
                .expect("enumerate v2 journal")
                .map(|entry| {
                    let entry = entry.expect("read v2 journal entry");
                    let name = entry
                        .file_name()
                        .into_string()
                        .expect("v2 journal name is UTF-8");
                    let bytes = fs::read(entry.path()).expect("read v2 journal file");
                    (name, bytes)
                })
                .collect::<Vec<_>>();
            snapshot.sort_by(|left, right| left.0.cmp(&right.0));
            snapshot
        }

        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "unknown-terminal-join-target", 4_096);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
            .expect("reserve target v2 capture")
            .into_acquired_anchor_for_handoff()
            .expect("close target acquisition handoff");
        let capture = store
            .reopen_anchored_capture_v2(&acquired, &policy)
            .expect("attach target v2 writer");
        let (stdout, stderr, mut publisher) = capture.split();
        publisher
            .record_launch_intended(
                "unknown-terminal-join-test/v1",
                br#"{"fixture":"split-launch"}"#.to_vec(),
            )
            .expect("persist target v1-only launch cut");
        drop(stdout);
        drop(stderr);
        drop(publisher);

        let binding = crate::CommandDomainCleanupBinding::try_new(
            intent.source.runner_session_id.clone(),
            intent.source.effect_id.clone(),
            intent.source.request_digest.clone(),
        )
        .expect("construct target cleanup binding");
        let native_cleanup_proof =
            crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&binding);
        let claim = recovery_claim(&intent.capture_id, 1, None);
        let quarantine = store
            .quarantine_split_sensitive_output_launch_v2(
                &intent,
                &claim,
                crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                &native_cleanup_proof,
            )
            .expect("quarantine exact target split-launch cut");
        quarantine
            .validate()
            .expect("validate target split-launch quarantine");
        let target_v1 = store
            .reopen_capture(&intent.capture_id)
            .expect("reopen target v1 terminal");
        let target_v2 = store
            .reopen_sensitive_output_journal_v2(&intent.capture_id)
            .expect("reopen target v2 prefix");
        let joined = store
            .reopen_sensitive_output_unknown_terminal_join_v2(
                &intent,
                &acquired,
                target_v1.store_head(),
                &policy,
                crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                &native_cleanup_proof,
            )
            .expect("join exact split-launch Unknown terminal");
        assert_eq!(joined.v1_terminal(), &target_v1);
        assert_eq!(joined.v2_head(), target_v2.head());

        let crossed_intent = capture_intent(&fixture, "unknown-terminal-join-crossed", 4_096);
        let crossed_dispatch = super::command_output_journal::expected_dispatch_claim_id(
            &crossed_intent.source.effect_id,
        );
        let crossed_acquired = store
            .reserve_anchored_capture_v2(&crossed_intent, &crossed_dispatch, 3, &policy)
            .expect("reserve independently valid crossed capture")
            .into_acquired_anchor_for_handoff()
            .expect("close crossed acquisition handoff");

        assert!(
            store
                .reopen_sensitive_output_unknown_terminal_join_v2(
                    &intent,
                    &crossed_acquired,
                    target_v1.store_head(),
                    &policy,
                    crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                    &native_cleanup_proof,
                )
                .is_err(),
            "crossed acquired anchor must be rejected"
        );
        assert!(
            store
                .reopen_sensitive_output_unknown_terminal_join_v2(
                    &intent,
                    &acquired,
                    &crossed_acquired.store_head,
                    &policy,
                    crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                    &native_cleanup_proof,
                )
                .is_err(),
            "crossed expected v1 terminal head must be rejected"
        );
        assert_same_durable_capture(
            &store
                .reopen_capture(&intent.capture_id)
                .expect("crossed joins leave target v1 unchanged"),
            &target_v1,
        );
        assert_eq!(
            store
                .reopen_sensitive_output_journal_v2(&intent.capture_id)
                .expect("crossed joins leave target v2 unchanged"),
            target_v2
        );

        super::sensitive_output_journal::inject_current_record_pending_test_cut(
            &store,
            &intent.capture_id,
        )
        .expect("inject exact pending v2 crash cut");
        let journal_path = fixture.state.join(format!(
            "{}{}",
            super::sensitive_output_journal::JOURNAL_PREFIX,
            intent.capture_id
        ));
        let pending_before = snapshot_directory(&journal_path);
        assert!(
            pending_before
                .iter()
                .any(|(name, _)| name.starts_with(".pending-record-")),
            "fixture must retain one pending v2 record"
        );
        let pending_error = store
            .reopen_sensitive_output_unknown_terminal_join_v2(
                &intent,
                &acquired,
                target_v1.store_head(),
                &policy,
                crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                &native_cleanup_proof,
            )
            .expect_err("read-only join must reject pending v2 recovery");
        assert!(
            pending_error
                .to_string()
                .contains("refuses pending record roll-forward")
        );
        assert_eq!(
            snapshot_directory(&journal_path),
            pending_before,
            "read-only join must not rename, rewrite, or remove pending v2 bytes"
        );
        assert_same_durable_capture(
            &store
                .reopen_capture(&intent.capture_id)
                .expect("pending v2 refusal leaves target v1 unchanged"),
            &target_v1,
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn optional_v2_diagnostic_reopen_rejects_pending_without_namespace_mutation() {
        fn snapshot_directory(path: &Path) -> Vec<(String, Vec<u8>)> {
            let mut snapshot = fs::read_dir(path)
                .expect("enumerate diagnostic v2 journal")
                .map(|entry| {
                    let entry = entry.expect("read diagnostic v2 journal entry");
                    let name = entry
                        .file_name()
                        .into_string()
                        .expect("diagnostic v2 journal name is UTF-8");
                    let bytes = fs::read(entry.path()).expect("read diagnostic v2 journal file");
                    (name, bytes)
                })
                .collect::<Vec<_>>();
            snapshot.sort_by(|left, right| left.0.cmp(&right.0));
            snapshot
        }

        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "optional-v2-diagnostic-pending", 64);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        store
            .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
            .expect("reserve diagnostic v2 capture")
            .into_acquired_anchor_for_handoff()
            .expect("close diagnostic acquisition handoff");
        super::sensitive_output_journal::inject_current_record_pending_test_cut(
            &store,
            &intent.capture_id,
        )
        .expect("inject exact pending diagnostic cut");
        let journal_path = fixture.state.join(format!(
            "{}{}",
            super::sensitive_output_journal::JOURNAL_PREFIX,
            intent.capture_id
        ));
        let pending_before = snapshot_directory(&journal_path);
        assert!(
            pending_before
                .iter()
                .any(|(name, _)| name.starts_with(".pending-record-")),
            "fixture must retain a valid pending record"
        );

        let error = store
            .reopen_optional_sensitive_output_journal_v2_diagnostic(&intent.capture_id)
            .expect_err("diagnostic reopen must reject pending publication");
        assert!(
            error
                .to_string()
                .contains("refuses pending record roll-forward")
        );
        assert_eq!(
            snapshot_directory(&journal_path),
            pending_before,
            "diagnostic reopen must not rename, rewrite, synchronize, or remove pending bytes"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the adversarial test keeps generic-API refusal, native-proof admission, zero-first restart, idempotence, and retained-evidence inspection together"
    )]
    fn generation_four_quarantine_is_zero_first_unknown_and_retains_no_output_derived_evidence() {
        fn inspect_json(
            value: &serde_json::Value,
            observed_lengths: &mut usize,
            output_object: bool,
        ) {
            match value {
                serde_json::Value::Object(fields) => {
                    for (field, value) in fields {
                        if output_object && field == "byte_length" {
                            *observed_lengths += 1;
                            assert_eq!(
                                value.as_u64(),
                                Some(0),
                                "every retained output-object length must be constant zero"
                            );
                        }
                        assert!(
                            ![
                                "content_digest",
                                "output_digest",
                                "fingerprint",
                                "offset",
                                "matched_length",
                                "matched_rule",
                                "message",
                                "summary",
                            ]
                            .contains(&field.as_str()),
                            "retained quarantine evidence contains output/match-derived field {field}"
                        );
                        inspect_json(
                            value,
                            observed_lengths,
                            output_object || matches!(field.as_str(), "stdout" | "stderr"),
                        );
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        inspect_json(value, observed_lengths, output_object);
                    }
                }
                _ => {}
            }
        }

        fn inspect_retained_files(
            path: &Path,
            prefix: &[u8],
            marker: &[u8],
            observed_lengths: &mut usize,
        ) {
            for entry in fs::read_dir(path).expect("enumerate retained private state") {
                let entry = entry.expect("read retained private-state entry");
                let file_type = entry.file_type().expect("inspect retained entry type");
                if file_type.is_dir() {
                    inspect_retained_files(&entry.path(), prefix, marker, observed_lengths);
                } else if file_type.is_file() {
                    let bytes = fs::read(entry.path()).expect("read retained evidence bytes");
                    assert!(
                        !bytes.windows(prefix.len()).any(|window| window == prefix),
                        "released prefix bytes must not survive quarantine"
                    );
                    assert!(
                        !bytes.windows(marker.len()).any(|window| window == marker),
                        "matched marker bytes must not survive quarantine"
                    );
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        inspect_json(&value, observed_lengths, false);
                    }
                }
            }
        }

        for (index, (stdout_prefix, stderr_prefix, marker)) in [
            (
                b"ordinary-released-stdout-prefix-alpha".as_slice(),
                b"ordinary-stderr-prefix-alpha".as_slice(),
                b"ANTHROPIC_API_KEY=quarantine-marker-alpha".as_slice(),
            ),
            (
                b"ordinary-stdout-prefix-beta-with-a-different-length".as_slice(),
                b"ordinary-released-stderr-prefix-beta-with-a-different-length".as_slice(),
                b"OPENAI_API_KEY=quarantine-marker-beta".as_slice(),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("g4-quarantine-{index}"), 4_096);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
            let acquired = store
                .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
                .expect("reserve v2 capture")
                .into_acquired_anchor_for_handoff()
                .expect("close acquired handoff");
            let capture = store
                .reopen_anchored_capture_v2(&acquired, &policy)
                .expect("attach v2 writer");
            let (mut stdout, mut stderr, mut publisher) = capture.split();
            #[cfg(target_os = "linux")]
            let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::linux();
            #[cfg(target_os = "macos")]
            let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::macos();
            let launch_head = publisher
                .record_launch_intended_v2(
                    "generation-four-quarantine-test/v1",
                    format!(r#"{{"fixture":"g4-quarantine-{index}"}}"#).into_bytes(),
                    &core_dump,
                )
                .expect("record generation-four launch boundary");
            stdout
                .append(stdout_prefix)
                .expect("stage scanner-released stdout prefix");
            stderr
                .append(stderr_prefix)
                .expect("stage scanner-released stderr prefix");
            assert!(matches!(
                publisher.abandon_unpublished(stdout.into_custody(), stderr.into_custody()),
                Err(CommandOutputStoreError::ReconciliationRequired { .. })
            ));

            let before_v1 = store
                .reopen_capture(&intent.capture_id)
                .expect("reopen generation-four v1 custody");
            let before_v2 = store
                .reopen_sensitive_output_journal_v2(&intent.capture_id)
                .expect("reopen generation-four v2 custody");
            let claim = recovery_claim(&intent.capture_id, 1, None);
            assert!(matches!(
                store.reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head)),
                Err(CommandOutputStoreError::ReconciliationRequired { .. })
            ));
            assert!(matches!(
                store.cleanup_capture(&claim, &launch_head),
                Err(CommandOutputStoreError::ReconciliationRequired { .. })
            ));
            let timestamp_called = Cell::new(false);
            assert!(matches!(
                store.resolve_unknown_capture(
                    &intent,
                    &acquired,
                    &launch_head,
                    &claim,
                    &launch_head,
                    || {
                        timestamp_called.set(true);
                        Ok(claim.acquired_at_unix_ms + 1)
                    },
                ),
                Err(CommandOutputStoreError::ReconciliationRequired { .. })
            ));
            assert!(!timestamp_called.get());
            let clean_timestamp_called = Cell::new(false);
            assert!(
                store
                    .resolve_sensitive_output_clean_unknown_capture_v2(
                        &intent,
                        &acquired,
                        &launch_head,
                        &claim,
                        &launch_head,
                        &policy,
                        || {
                            clean_timestamp_called.set(true);
                            Ok(claim.acquired_at_unix_ms + 1)
                        },
                    )
                    .is_err()
            );
            assert!(!clean_timestamp_called.get());
            assert_same_durable_capture(
                &store
                    .reopen_capture(&intent.capture_id)
                    .expect("generic refusal leaves v1 unchanged"),
                &before_v1,
            );
            assert_eq!(
                store
                    .reopen_sensitive_output_journal_v2(&intent.capture_id)
                    .expect("generic refusal leaves v2 unchanged"),
                before_v2
            );

            let binding = crate::CommandDomainCleanupBinding::try_new(
                intent.source.runner_session_id.clone(),
                intent.source.effect_id.clone(),
                intent.source.request_digest.clone(),
            )
            .expect("construct exact native cleanup binding");
            let native_cleanup_proof =
                crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&binding);
            assert!(
                store
                    .quarantine_unclassified_sensitive_output_after_launch_v2(
                        &intent,
                        &claim,
                        crate::CommandDomainCleanupBackend::MacOsDedicatedIdentity,
                        &native_cleanup_proof,
                    )
                    .is_err(),
                "a valid proof from a different independently selected backend must fail"
            );
            assert_same_durable_capture(
                &store
                    .reopen_capture(&intent.capture_id)
                    .expect("wrong-backend proof leaves v1 unchanged"),
                &before_v1,
            );
            let quarantine = store
                .quarantine_unclassified_sensitive_output_after_launch_v2(
                    &intent,
                    &claim,
                    crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                    &native_cleanup_proof,
                )
                .expect("zero-first quarantine generation-four Unknown");
            quarantine.validate().expect("validate typed quarantine");
            assert_eq!(quarantine.v2_launch_intended(), &before_v2);
            assert_eq!(
                quarantine.command_domain_cleanup_proof_id(),
                native_cleanup_proof.os_evidence_digest()
            );
            assert_eq!(
                quarantine.expected_cleanup_backend(),
                crate::CommandDomainCleanupBackend::LinuxCgroupV2
            );
            assert_eq!(quarantine.native_cleanup_proof(), &native_cleanup_proof);
            assert_eq!(
                quarantine.v1_cleaned().state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned
            );
            assert!(quarantine.v1_cleaned().expected_reference().is_none());
            super::command_output_journal::validate_sensitive_cleanup_plan_zero(
                &store,
                &acquired,
                &launch_head,
            )
            .expect("quarantine persisted only an exact zero-length cleanup plan");
            let repeated = store
                .quarantine_unclassified_sensitive_output_after_launch_v2(
                    &intent,
                    &claim,
                    crate::CommandDomainCleanupBackend::LinuxCgroupV2,
                    &native_cleanup_proof,
                )
                .expect("same exact quarantine is idempotent");
            assert_eq!(
                repeated.v1_cleaned().store_head(),
                quarantine.v1_cleaned().store_head()
            );
            assert_eq!(
                repeated.v2_launch_intended(),
                quarantine.v2_launch_intended()
            );

            let mut observed_lengths = 0;
            inspect_retained_files(&fixture.state, stdout_prefix, marker, &mut observed_lengths);
            inspect_retained_files(&fixture.state, stderr_prefix, marker, &mut observed_lengths);
            assert!(
                observed_lengths >= 4,
                "retained intent/acquisition/cleanup evidence must expose its zero object lengths"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test keeps legacy refusal, generic refusal, exact clean receipt admission, and idempotent fenced readback together"
    )]
    fn clean_v2_unknown_resolution_requires_current_receipt_policy_and_terminal_head() {
        let legacy_fixture = Fixture::new();
        let legacy_store =
            CapabilityCommandOutputStore::open(&legacy_fixture.state).expect("open legacy store");
        let legacy_intent = capture_intent(&legacy_fixture, "legacy-clean-resolve-refusal", 64);
        let legacy_dispatch = super::command_output_journal::expected_dispatch_claim_id(
            &legacy_intent.source.effect_id,
        );
        let legacy_acquired = legacy_store
            .reserve_anchored_capture(&legacy_intent, &legacy_dispatch, 2)
            .expect("reserve legacy v1 capture")
            .into_acquired_anchor_for_handoff()
            .expect("close legacy acquired handoff");
        let legacy_before = legacy_store
            .reopen_capture(&legacy_intent.capture_id)
            .expect("reopen legacy v1 capture");
        let legacy_claim = recovery_claim(&legacy_intent.capture_id, 1, None);
        let legacy_timestamp_called = Cell::new(false);
        assert!(
            legacy_store
                .resolve_sensitive_output_clean_unknown_capture_v2(
                    &legacy_intent,
                    &legacy_acquired,
                    legacy_before.store_head(),
                    &legacy_claim,
                    legacy_before.store_head(),
                    &grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
                    || {
                        legacy_timestamp_called.set(true);
                        Ok(legacy_claim.acquired_at_unix_ms + 1)
                    },
                )
                .is_err(),
            "a legacy v1 capture cannot manufacture clean-v2 authority"
        );
        assert!(!legacy_timestamp_called.get());
        assert_same_durable_capture(
            &legacy_store
                .reopen_capture(&legacy_intent.capture_id)
                .expect("legacy refusal leaves v1 unchanged"),
            &legacy_before,
        );

        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "clean-v2-fenced-resolution", 4_096);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
            .expect("reserve v2 capture")
            .into_acquired_anchor_for_handoff()
            .expect("close acquired handoff");
        let capture = store
            .reopen_anchored_capture_v2(&acquired, &policy)
            .expect("attach v2 writer");
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        #[cfg(target_os = "linux")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::linux();
        #[cfg(target_os = "macos")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::macos();
        publisher
            .record_launch_intended_v2(
                "clean-v2-resolution-test/v1",
                br#"{"fixture":"clean-v2-resolution"}"#.to_vec(),
                &core_dump,
            )
            .expect("record v2 launch boundary");
        stdout.append(b"verified clean stdout").unwrap();
        stderr.append(b"verified clean stderr").unwrap();
        publisher
            .record_sensitive_output_scanned_clean_v2()
            .expect("record exact clean scan decision");
        let artifact = publisher
            .publish(stdout.finish().unwrap(), stderr.finish().unwrap())
            .expect("publish exact clean output");
        drop(artifact);
        let published_recovery = store
            .reopen_capture(&intent.capture_id)
            .expect("reopen published clean output");
        let published_head = published_recovery
            .published_store_head()
            .cloned()
            .expect("published v1 head");
        let terminal = store
            .prepare_capture_terminal(
                &intent.capture_id,
                &published_head,
                "clean-v2-resolution-terminal/v1",
                br#"{"terminal":"clean"}"#.to_vec(),
            )
            .expect("persist v1 TerminalPrepared");
        let terminal_head = terminal
            .terminal_prepared_store_head()
            .cloned()
            .expect("terminal-prepared v1 head");
        let terminal_record_digest = Digest::sha256(b"clean-v2-terminal-record");
        let receipt = store
            .record_sensitive_output_clean_terminal_prepared_v2(
                &intent.capture_id,
                &terminal_head,
                &terminal_record_digest,
                grok_build_core::CommandTerminationV1::Exited { code: 0 },
            )
            .expect("persist exact terminal clean receipt");
        receipt.validate().expect("validate clean receipt");

        let claim = recovery_claim(&intent.capture_id, 1, None);
        let generic_timestamp_called = Cell::new(false);
        assert!(matches!(
            store.resolve_unknown_capture(
                &intent,
                &acquired,
                &terminal_head,
                &claim,
                &terminal_head,
                || {
                    generic_timestamp_called.set(true);
                    Ok(claim.acquired_at_unix_ms + 1)
                },
            ),
            Err(CommandOutputStoreError::ReconciliationRequired { .. })
        ));
        assert!(!generic_timestamp_called.get());

        let crossed_observed_timestamp_called = Cell::new(false);
        assert!(
            store
                .resolve_sensitive_output_clean_unknown_capture_v2(
                    &intent,
                    &acquired,
                    &terminal_head,
                    &claim,
                    &acquired.store_head,
                    &policy,
                    || {
                        crossed_observed_timestamp_called.set(true);
                        Ok(claim.acquired_at_unix_ms + 1)
                    },
                )
                .is_err(),
            "the core-requested Acquired head cannot substitute for the observed TerminalPrepared head"
        );
        assert!(!crossed_observed_timestamp_called.get());

        let crossed_terminal_timestamp_called = Cell::new(false);
        assert!(
            store
                .resolve_sensitive_output_clean_unknown_capture_v2(
                    &intent,
                    &acquired,
                    &acquired.store_head,
                    &claim,
                    &terminal_head,
                    &policy,
                    || {
                        crossed_terminal_timestamp_called.set(true);
                        Ok(claim.acquired_at_unix_ms + 1)
                    },
                )
                .is_err(),
            "the core-requested Acquired head cannot substitute for the clean-v2 terminal head"
        );
        assert!(!crossed_terminal_timestamp_called.get());

        let resolved = store
            .resolve_sensitive_output_clean_unknown_capture_v2(
                &intent,
                &acquired,
                &terminal_head,
                &claim,
                &terminal_head,
                &policy,
                || Ok(claim.acquired_at_unix_ms + 1),
            )
            .expect("resolve only through the exact clean-v2 branch");
        assert_eq!(
            resolved.recovery().state(),
            super::CommandOutputCaptureJournalStateV1::TerminalPrepared
        );
        assert_eq!(resolved.recovery().store_head(), &terminal_head);
        assert_eq!(
            resolved
                .physical_reconciliation()
                .requested_store_head
                .as_ref(),
            Some(&acquired.store_head),
            "initial core restart remains bound to the original acquisition head"
        );
        assert_eq!(
            resolved
                .physical_reconciliation()
                .initial_store_head
                .as_ref(),
            Some(&terminal_head),
            "the independent physical fence records the freshly observed terminal head"
        );
        assert_eq!(
            resolved.physical_reconciliation().initial_state,
            Some(grok_build_core::CommandOutputCaptureRestartStateV1::TerminalPrepared)
        );
        resolved
            .physical_reconciliation()
            .validate_against(&intent, &claim, Some(&acquired))
            .expect("core-acquired validation accepts distinct requested and observed heads");
        assert_eq!(
            store
                .reopen_sensitive_output_clean_v2(&intent.capture_id)
                .expect("reopen clean receipt after resolution"),
            Some(receipt.clone())
        );
        let repeated = store
            .resolve_sensitive_output_clean_unknown_capture_v2(
                &intent,
                &acquired,
                &terminal_head,
                &claim,
                &terminal_head,
                &policy,
                || Ok(claim.acquired_at_unix_ms + 2),
            )
            .expect("same clean-v2 branch resolution is idempotent");
        assert_eq!(
            repeated.recovery().store_head(),
            resolved.recovery().store_head()
        );
        assert_eq!(
            repeated
                .physical_reconciliation()
                .requested_store_head
                .as_ref(),
            Some(&acquired.store_head)
        );
        assert_eq!(
            repeated
                .physical_reconciliation()
                .initial_store_head
                .as_ref(),
            Some(&terminal_head)
        );
        let successor_claim = recovery_claim(&intent.capture_id, 2, Some(claim.claim_id.clone()));
        let successor = store
            .resolve_sensitive_output_clean_unknown_capture_v2(
                &intent,
                &acquired,
                &terminal_head,
                &successor_claim,
                &terminal_head,
                &policy,
                || Ok(successor_claim.acquired_at_unix_ms + 1),
            )
            .expect("higher successor claim re-fences exact clean-v2 terminal readback");
        assert_same_durable_capture(resolved.recovery(), successor.recovery());
        assert_eq!(
            successor.recovery().state(),
            super::CommandOutputCaptureJournalStateV1::TerminalPrepared
        );
        assert_eq!(successor.recovery().store_head(), &terminal_head);
        assert_eq!(
            successor.physical_reconciliation().reconciliation_claim,
            successor_claim
        );
        assert_eq!(
            successor
                .physical_reconciliation()
                .physical_fence_chain_length,
            2
        );
        assert_eq!(
            successor.physical_reconciliation().predecessor_fence_digest,
            Some(
                resolved
                    .physical_reconciliation()
                    .physical_fence_digest
                    .clone()
            )
        );
        assert_eq!(
            successor.physical_reconciliation().resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
        );
        successor
            .physical_reconciliation()
            .validate_against(&intent, &successor_claim, Some(&acquired))
            .expect("successor clean-v2 receipt validates against its fresh core claim");
        assert_eq!(
            store
                .reopen_sensitive_output_clean_v2(&intent.capture_id)
                .expect("clean receipt remains unchanged after retry"),
            Some(receipt)
        );
    }

    #[test]
    fn every_sensitive_neutralization_physical_cut_restarts_to_identical_zero_receipt() {
        use super::command_output_journal::SensitiveNeutralizationCheckpoint as Cut;

        for cut in [
            Cut::StdoutTruncated,
            Cut::StdoutSynchronized,
            Cut::StdoutZeroReadBack,
            Cut::StderrTruncated,
            Cut::StderrSynchronized,
            Cut::StderrZeroReadBack,
        ] {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("neutralization-{cut:?}"), 4_096);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
            let acquired = store
                .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
                .expect("reserve v2 capture")
                .into_acquired_anchor_for_handoff()
                .expect("close acquired handoff");
            let capture = store
                .reopen_anchored_capture_v2(&acquired, &policy)
                .expect("attach v2 writer");
            let (mut stdout, mut stderr, mut publisher) = capture.split();
            stdout
                .append(b"ordinary rejected-command stdout prefix")
                .expect("stage ordinary stdout prefix");
            stderr
                .append(b"ordinary rejected-command stderr prefix")
                .expect("stage ordinary stderr prefix");
            #[cfg(target_os = "linux")]
            let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::linux();
            #[cfg(target_os = "macos")]
            let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::macos();
            let launch_head = publisher
                .record_launch_intended_v2(
                    "neutralization-cut-test/v1",
                    br#"{"fixture":"neutralization-cut"}"#.to_vec(),
                    &core_dump,
                )
                .expect("record launch boundary");
            publisher
                .record_sensitive_output_detected_v2(&launch_head, &policy)
                .expect("record detection boundary");
            drop(stdout);
            drop(stderr);
            drop(publisher);

            let error = super::command_output_journal::inject_sensitive_neutralization_cut(
                &store,
                &acquired,
                &launch_head,
                cut,
            )
            .expect_err("inject exact neutralization physical cut");
            assert!(error.to_string().contains(&format!("{cut:?}")));
            assert_eq!(
                store
                    .capture_state(&intent.capture_id)
                    .expect("v1 remains pre-cleanup"),
                super::CommandOutputCaptureJournalStateV1::LaunchIntended
            );
            assert!(matches!(
                store
                    .reopen_sensitive_output_journal_v2(&intent.capture_id)
                    .expect("v2 remains detected")
                    .stage(),
                super::SensitiveOutputJournalStageV2::SensitiveOutputDetected {}
            ));

            let cleanup_proof_id =
                Digest::sha256(format!("neutralization-proof-{cut:?}").as_bytes()).to_string();
            let neutralization = store
                .resume_sensitive_output_neutralization_v2(&intent.capture_id, &cleanup_proof_id)
                .expect("restart completes exact neutralization");
            let repeated = store
                .resume_sensitive_output_neutralization_v2(&intent.capture_id, &cleanup_proof_id)
                .expect("neutralization readback is idempotent");
            assert_eq!(neutralization, repeated);
            assert_eq!(neutralization.aggregate_zero_length, 0);
            assert_eq!(neutralization.stdout.byte_length, 0);
            assert_eq!(neutralization.stderr.byte_length, 0);

            let claim = recovery_claim(&intent.capture_id, 1, None);
            let rejection = store
                .resume_sensitive_output_rejection_v2(
                    &intent.capture_id,
                    &claim,
                    grok_build_core::CommandTerminationV1::Exited { code: 0 },
                    &policy,
                )
                .expect("finish v1 zero-only cleanup and v2 rejection");
            assert_eq!(rejection.staging_neutralization, neutralization);
            super::command_output_journal::validate_sensitive_cleanup_plan_zero(
                &store,
                &acquired,
                &launch_head,
            )
            .expect("frozen v1 cleanup plan contains only exact zero-length objects");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial test keeps the late-write failure, unchanged journals, detected-branch refusal, restart neutralization, and terminal rejection together"
    )]
    fn abandonment_rereads_exact_zero_after_stream_custody_closes() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "late-write-after-neutralization", 4_096);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
            .expect("reserve v2 capture")
            .into_acquired_anchor_for_handoff()
            .expect("close acquired handoff");
        let capture = store
            .reopen_anchored_capture_v2(&acquired, &policy)
            .expect("attach v2 writer");
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        #[cfg(target_os = "linux")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::linux();
        #[cfg(target_os = "macos")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::macos();
        let launch_head = publisher
            .record_launch_intended_v2(
                "late-write-neutralization-test/v1",
                br#"{"fixture":"late-write"}"#.to_vec(),
                &core_dump,
            )
            .expect("record launch boundary");
        stdout
            .append(b"ordinary prefix before detection")
            .expect("stage ordinary prefix");
        publisher
            .record_sensitive_output_detected_v2(&launch_head, &policy)
            .expect("record detected branch");
        let neutralization = publisher
            .neutralize_sensitive_output_staging_v2(&mut stdout, &mut stderr)
            .expect("neutralize both live stream objects");
        stdout
            .append(b"late bytes after neutralization")
            .expect("exercise the former append-after-zero window");
        let cleanup_proof_id = Digest::sha256(b"late-write-zero-reread-proof").to_string();
        let Err(error) = publisher.abandon_sensitive_output_v2(
            stdout.into_custody(),
            stderr.into_custody(),
            grok_build_core::CommandTerminationV1::Exited { code: 0 },
            &cleanup_proof_id,
            &policy,
            &neutralization,
        ) else {
            panic!("fresh post-custody zero reread must reject the late write")
        };
        assert!(matches!(
            error,
            CommandOutputStoreError::ReconciliationRequired { .. }
        ));
        assert_eq!(
            store
                .capture_state(&intent.capture_id)
                .expect("v1 remains before cleanup"),
            super::CommandOutputCaptureJournalStateV1::LaunchIntended
        );
        assert!(matches!(
            store
                .reopen_sensitive_output_journal_v2(&intent.capture_id)
                .expect("v2 remains detected")
                .stage(),
            super::SensitiveOutputJournalStageV2::SensitiveOutputDetected {}
        ));
        let claim = recovery_claim(&intent.capture_id, 1, None);
        let detected_before = store
            .reopen_capture(&intent.capture_id)
            .expect("reopen detected v1 custody");
        let detected_timestamp_called = Cell::new(false);
        assert!(
            store
                .resolve_sensitive_output_clean_unknown_capture_v2(
                    &intent,
                    &acquired,
                    &launch_head,
                    &claim,
                    detected_before.store_head(),
                    &policy,
                    || {
                        detected_timestamp_called.set(true);
                        Ok(claim.acquired_at_unix_ms + 1)
                    },
                )
                .is_err(),
            "the detected branch cannot be reinterpreted as clean"
        );
        assert!(!detected_timestamp_called.get());
        assert_same_durable_capture(
            &store
                .reopen_capture(&intent.capture_id)
                .expect("clean-branch refusal leaves detected v1 unchanged"),
            &detected_before,
        );

        let restarted_neutralization = store
            .resume_sensitive_output_neutralization_v2(&intent.capture_id, &cleanup_proof_id)
            .expect("restart neutralizes the exact closed staging objects");
        assert_eq!(restarted_neutralization, neutralization);
        store
            .resume_sensitive_output_rejection_v2(
                &intent.capture_id,
                &claim,
                grok_build_core::CommandTerminationV1::Exited { code: 0 },
                &policy,
            )
            .expect("exact rejection branch completes after restart neutralization");
        let rejected_before = store
            .reopen_capture(&intent.capture_id)
            .expect("reopen rejected v1 cleanup");
        let clean_timestamp_called = Cell::new(false);
        assert!(
            store
                .resolve_sensitive_output_clean_unknown_capture_v2(
                    &intent,
                    &acquired,
                    &launch_head,
                    &claim,
                    rejected_before.store_head(),
                    &policy,
                    || {
                        clean_timestamp_called.set(true);
                        Ok(claim.acquired_at_unix_ms + 1)
                    },
                )
                .is_err(),
            "the classified rejection branch cannot be reinterpreted as clean"
        );
        assert!(!clean_timestamp_called.get());
        assert_same_durable_capture(
            &store
                .reopen_capture(&intent.capture_id)
                .expect("clean-branch refusal leaves rejected v1 unchanged"),
            &rejected_before,
        );
        super::command_output_journal::validate_sensitive_cleanup_plan_zero(
            &store,
            &acquired,
            &launch_head,
        )
        .expect("restarted cleanup plan is exact zero-only custody");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one restart test keeps all rejection generations and native-proof rejoin negatives visible"
    )]
    fn sensitive_output_restart_neutralizes_then_completes_without_replay() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "sensitive-restart", 4_096);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
            .expect("reserve v2 capture")
            .into_acquired_anchor_for_handoff()
            .expect("handoff acquired anchor");
        let capture = store
            .reopen_anchored_capture_v2(&acquired, &policy)
            .expect("attach v2 writer");
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        stdout
            .append(b"ordinary clean prefix that must be neutralized")
            .expect("stage ordinary stdout prefix");
        stderr
            .append(b"ordinary clean stderr prefix that must be neutralized")
            .expect("stage ordinary stderr prefix");
        #[cfg(target_os = "linux")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::linux();
        #[cfg(target_os = "macos")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::macos();
        let launch_head = publisher
            .record_launch_intended_v2(
                "sensitive-restart-test/v1",
                br#"{"fixture":"sensitive-restart"}"#.to_vec(),
                &core_dump,
            )
            .expect("record exact launch intent");
        publisher
            .record_sensitive_output_detected_v2(&launch_head, &policy)
            .expect("record detection before simulated crash");
        drop(stdout);
        drop(stderr);
        drop(publisher);

        let cleanup_binding = crate::CommandDomainCleanupBinding::try_new(
            intent.source.runner_session_id.clone(),
            intent.source.effect_id.clone(),
            intent.source.request_digest.clone(),
        )
        .expect("construct independently retained command-domain binding");
        let native_cleanup_proof =
            crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&cleanup_binding);
        let cleanup_proof_id = native_cleanup_proof.os_evidence_digest().to_string();
        let neutralization = store
            .resume_sensitive_output_neutralization_v2(&intent.capture_id, &cleanup_proof_id)
            .expect("resume exact staging neutralization");
        neutralization
            .validate_against(&acquired)
            .expect("neutralization binds exact acquired objects");
        assert_eq!(neutralization.aggregate_zero_length, 0);
        assert_eq!(neutralization.stdout.byte_length, 0);
        assert_eq!(neutralization.stderr.byte_length, 0);
        assert_eq!(
            store
                .resume_sensitive_output_neutralization_v2(&intent.capture_id, &cleanup_proof_id,)
                .expect("neutralization restart is idempotent"),
            neutralization
        );

        let claim = recovery_claim(&intent.capture_id, 1, None);
        let termination = grok_build_core::CommandTerminationV1::Exited { code: 0 };
        let receipt = store
            .resume_sensitive_output_rejection_v2(&intent.capture_id, &claim, termination, &policy)
            .expect("resume exact cleanup and rejection terminal");
        receipt
            .validate()
            .expect("validate complete rejection chain");
        assert_eq!(receipt.staging_neutralization, neutralization);
        assert_eq!(receipt.launch_intended_store_head, launch_head);
        assert_eq!(
            store
                .resume_sensitive_output_rejection_v2(
                    &intent.capture_id,
                    &claim,
                    termination,
                    &policy,
                )
                .expect("rejected terminal readback is idempotent"),
            receipt
        );
        assert_eq!(
            store
                .reopen_sensitive_output_rejection_v2(&intent.capture_id)
                .expect("reopen terminal rejection"),
            Some(receipt.clone())
        );

        let missing_native_proof = super::SensitiveOutputRejectionNativeProofRejoinV1::try_new(
            receipt.clone(),
            None,
            crate::CommandDomainCleanupBackend::LinuxCgroupV2,
            &cleanup_binding,
        )
        .expect_err("terminal v2 receipt alone cannot reconstruct native cleanup evidence");
        assert!(matches!(
            missing_native_proof,
            super::CommandOutputStoreError::ReconciliationRequired { .. }
        ));

        super::SensitiveOutputRejectionNativeProofRejoinV1::try_new(
            receipt.clone(),
            Some(native_cleanup_proof.clone()),
            crate::CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            &cleanup_binding,
        )
        .expect_err("core-selected cleanup backend cannot be crossed");

        let crossed_binding = crate::CommandDomainCleanupBinding::try_new(
            cleanup_binding.runner_session_id(),
            "crossed-sensitive-output-effect",
            cleanup_binding.command_request_digest().clone(),
        )
        .expect("construct crossed cleanup binding");
        super::SensitiveOutputRejectionNativeProofRejoinV1::try_new(
            receipt.clone(),
            Some(native_cleanup_proof.clone()),
            crate::CommandDomainCleanupBackend::LinuxCgroupV2,
            &crossed_binding,
        )
        .expect_err("core-selected command-effect binding cannot be crossed");

        let alternate_proof =
            crate::cleanup_proof::tests::alternate_validated_linux_cleanup_proof_for(
                &cleanup_binding,
            );
        assert_ne!(
            alternate_proof.os_evidence_digest(),
            native_cleanup_proof.os_evidence_digest()
        );
        super::SensitiveOutputRejectionNativeProofRejoinV1::try_new(
            receipt.clone(),
            Some(alternate_proof),
            crate::CommandDomainCleanupBackend::LinuxCgroupV2,
            &cleanup_binding,
        )
        .expect_err("receipt cleanup-proof digest cannot be substituted");

        let tampered_proof =
            crate::cleanup_proof::tests::tampered_linux_cleanup_proof_for(&cleanup_binding);
        super::SensitiveOutputRejectionNativeProofRejoinV1::try_new(
            receipt.clone(),
            Some(tampered_proof),
            crate::CommandDomainCleanupBackend::LinuxCgroupV2,
            &cleanup_binding,
        )
        .expect_err("tampered native proof bytes cannot be rejoined");

        let surviving_proof =
            crate::cleanup_proof::tests::surviving_linux_cleanup_proof_for(&cleanup_binding);
        super::SensitiveOutputRejectionNativeProofRejoinV1::try_new(
            receipt.clone(),
            Some(surviving_proof),
            crate::CommandDomainCleanupBackend::LinuxCgroupV2,
            &cleanup_binding,
        )
        .expect_err("native proof with survivors cannot be rejoined");

        let mut nonterminal_receipt = receipt.clone();
        nonterminal_receipt.rejected_terminal_journal_head =
            nonterminal_receipt.cleaned_journal_head.clone();
        super::SensitiveOutputRejectionNativeProofRejoinV1::try_new(
            nonterminal_receipt,
            Some(native_cleanup_proof.clone()),
            crate::CommandDomainCleanupBackend::LinuxCgroupV2,
            &cleanup_binding,
        )
        .expect_err("nonterminal rejection receipt cannot be rejoined");

        let rejoined = super::SensitiveOutputRejectionNativeProofRejoinV1::try_new(
            receipt.clone(),
            Some(native_cleanup_proof.clone()),
            crate::CommandDomainCleanupBackend::LinuxCgroupV2,
            &cleanup_binding,
        )
        .expect("independently reopened exact native proof rejoins terminal v2 receipt");
        assert_eq!(rejoined.receipt(), &receipt);
        assert_eq!(rejoined.native_cleanup_proof(), &native_cleanup_proof);
        assert_eq!(
            rejoined.expected_cleanup_backend(),
            crate::CommandDomainCleanupBackend::LinuxCgroupV2
        );
        let response = crate::wire::RunnerResponseV12::command_output_abandoned_rejoined(rejoined)
            .expect("only the completed native-proof rejoin reconstructs a v12 response");
        let crate::wire::RunnerResponseV12::CommandOutputAbandoned { rejection } = response else {
            panic!("native-proof rejoin must reconstruct only the abandoned response")
        };
        assert_eq!(rejection.journal_receipt, receipt);
        assert_eq!(
            rejection.backend,
            crate::CommandDomainCleanupBackend::LinuxCgroupV2
        );
        assert_eq!(
            rejection.cleanup_proof.os_evidence_bytes,
            native_cleanup_proof.os_evidence_bytes()
        );
    }
