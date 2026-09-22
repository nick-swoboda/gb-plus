    #[test]
    #[allow(clippy::too_many_lines)] // Restart ownership, two cleanup domains, and terminal readback are one proof chain.
    fn v27_unknown_terminal_resolves_monotonically_after_exact_cleanup() {
        let mut fixture = prepare_fresh_command_dispatch_input("v27-restart-terminal");
        let verifier_policy = compiled_test_policy("v27-crossed-final-verifier-cleanup-policy");
        let verifier_launch = runner_launch(
            "v27-crossed-final-verifier-cleanup-launch",
            "v27-crossed-final-verifier-cleanup-session",
            RunnerSessionPurpose::FinalVerifier,
            None,
            &verifier_policy,
            1_165,
        );
        admit_test_runner_launch(&mut fixture.ledger, &verifier_launch, &verifier_policy);
        fixture.proposal = effect_proposal_event(
            &fixture.intent,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("command proposal sequence after crossed verifier launch"),
            &fixture.proposal.event_id,
        );
        let source = CommandOutputArtifactSourceV1 {
            sprint_id: fixture.intent.sprint_id.clone(),
            runner_launch_id: fixture.launch.launch_id.clone(),
            runner_session_id: fixture.session.session_id.clone(),
            effect_id: fixture.intent.effect_id.clone(),
            request_digest: fixture.intent.request_digest.clone(),
        };
        let capture_intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(b"v27-restart-terminal-capture").as_str(),
            source.clone(),
            fixture.launch.private_state_digest.clone(),
            MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES,
            fixture.intent.created_at_unix_ms,
        )
        .expect("construct restart capture intent");
        let permit = match fixture
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
                &capture_intent,
            )
            .expect("admit restart capture intent")
        {
            CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh restart admission returned {other:?}"),
        };
        let acquired = CommandOutputCaptureAcquiredV1::try_new(
            &capture_intent,
            permit
                .expected_output_capture_dispatch_claim_id()
                .expect("capture claim identity"),
            CommandOutputCaptureStoreHeadV1 {
                generation: 2,
                record_digest: Digest::sha256(b"v27-restart-acquired"),
            },
            CommandOutputCaptureDirectoryIdentityV1 {
                device_id: 8,
                inode: 80,
                owner_uid: 501,
                mode: 0o700,
                link_count: 2,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 8,
                inode: 81,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 8,
                inode: 82,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            1_210,
        )
        .expect("construct restart acquisition");
        let (_, transport) = fixture
            .ledger
            .claim_command_output_capture_dispatch(
                permit,
                acquired.clone(),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("commit restart dispatch claim");
        let observation_authority = transport
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate restart command transport");

        let observation = effect_observation(
            &fixture.intent,
            "v27-restart-terminal-observation",
            EffectOutcome::Unknown {
                evidence_digest: effect_evidence_digest(),
            },
            1_220,
        );
        let event = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("Unknown terminal sequence"),
            "v27-restart-terminal-event",
        );
        let forged_terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture_intent,
            Some(&acquired),
            &observation,
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
            CommandOutputCaptureStoreHeadV1 {
                generation: acquired.store_head.generation + 1,
                record_digest: Digest::sha256(b"v27-forged-direct-unknown-head"),
            },
            observation.outcome.evidence_digest().clone(),
            None,
            1_230,
        )
        .expect("construct self-valid forged-head Unknown terminal");
        let raw_forged_head = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw forged direct-Unknown head attempt");
        let raw_forged_head_error = v27_insert_raw_direct_unresolved_terminal(
            &raw_forged_head,
            &forged_terminal,
            &fixture.intent.sprint_id,
        )
        .expect_err("raw SQL must reject a direct Unknown beyond the Acquired head");
        assert!(
            raw_forged_head_error
                .to_string()
                .contains("capture terminal anchor must match exact intent/acquisition/claim"),
            "unexpected raw forged-head rejection: {raw_forged_head_error}"
        );
        drop(raw_forged_head);
        let forged_head_failure = fixture
            .ledger
            .record_claimed_command_unknown_with_capture_reconciliation_required(
                observation_authority,
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &event,
                &forged_terminal,
            )
            .expect_err("API must reject a direct Unknown beyond the Acquired head");
        assert!(matches!(
            forged_head_failure.error(),
            LedgerError::ReferenceMismatch {
                entity: "command output capture unresolved terminal",
                ..
            }
        ));
        let (_, retry_authority) = forged_head_failure.into_parts();
        let observation_authority = retry_authority
            .expect("definite forged-head rejection returns exact observation authority");
        let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture_intent,
            Some(&acquired),
            &observation,
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
            acquired.store_head.clone(),
            observation.outcome.evidence_digest().clone(),
            None,
            1_230,
        )
        .expect("construct immutable Unknown terminal anchor");
        fixture
            .ledger
            .record_claimed_command_unknown_with_capture_reconciliation_required(
                observation_authority,
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &event,
                &terminal,
            )
            .expect("commit Unknown without fabricating cleanup");
        let unresolved = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.intent.effect_id)
            .expect("load unresolved Unknown capture");
        assert_eq!(unresolved.terminal.as_ref(), Some(&terminal));
        assert!(unresolved.reconciliation_resolution.is_none());
        assert!(unresolved.reconciliation_obligation_closure.is_none());
        assert_eq!(
            row_count(&fixture.ledger, "command_domain_cleanup_proofs"),
            0
        );
        assert!(matches!(
            fixture
                .ledger
                .classify_command_output_capture_recovery(&capture_intent.capture_id)
                .expect("classify Unknown capture"),
            CommandOutputCaptureRecovery::ReconciliationRequired(_)
        ));

        let platform_proof_bytes = b"validated-v27-restart-command-cleanup".to_vec();
        let command_cleanup = CommandDomainCleanupProof {
            contract_version: CONTRACT_VERSION,
            proof_id: "v27-restart-command-cleanup-proof".into(),
            sprint_id: fixture.intent.sprint_id.clone(),
            launch_id: fixture.launch.launch_id.clone(),
            session_id: fixture.session.session_id.clone(),
            effect_id: fixture.intent.effect_id.clone(),
            observation_id: Some(observation.observation_id.clone()),
            request_digest: fixture.intent.request_digest.clone(),
            backend: CommandDomainBackend::LinuxCgroupV2,
            disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            surviving_processes: 0,
            platform_proof_digest: Digest::sha256(&platform_proof_bytes),
            platform_proof_bytes,
            cleaned_at_unix_ms: 1_250,
        };
        fixture
            .ledger
            .record_command_domain_cleanup_proof(&command_cleanup)
            .expect("persist exact command cleanup before runner cleanup");

        let unknown_evidence = crate::TaskAttemptUnknownEvidence {
            effect_id: fixture.intent.effect_id.clone(),
            observation_id: observation.observation_id.clone(),
            evidence: crate::TaskAttemptEvidence::new(
                "v27-restart-unknown-source".into(),
                crate::TaskAttemptEvidenceKind::UnknownTerminalEffect,
                EFFECT_EVIDENCE_BYTES.to_vec(),
            )
            .expect("construct exact Unknown source evidence"),
        };
        let disposition = fixture
            .ledger
            .with_task_command_unknown_cleaned_disposition_derived_timestamps(
                &command_cleanup,
                &fixture.running.attempt,
                TaskState::Running,
                "v27-restart-unknown-cleaned-disposition",
                &unknown_evidence,
                "v27-restart-unknown-cleaned-release",
                "v27-restart-unknown-cleaned-marker",
                "v27-restart-unknown-task-transition",
                1_260,
                |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "v27-restart-runner-cleanup",
                        5_000,
                    ))
                },
            )
            .expect("derive UnknownCleaned time from late exact runner cleanup");
        let runner_cleanup_receipt_id = match &disposition {
            TaskAttemptDisposition::UnknownCleaned(value) => {
                assert_eq!(value.metadata.disposed_at_unix_ms, 5_000);
                assert_eq!(value.cleanup_release.released_at_unix_ms, 5_000);
                value.cleanup_release.cleanup_receipt.receipt_id.clone()
            }
            other => panic!("expected UnknownCleaned disposition, got {other:?}"),
        };
        let replay = fixture
            .ledger
            .with_task_command_unknown_cleaned_disposition_derived_timestamps(
                &command_cleanup,
                &fixture.running.attempt,
                TaskState::Running,
                "v27-restart-unknown-cleaned-disposition",
                &unknown_evidence,
                "v27-restart-unknown-cleaned-release",
                "v27-restart-unknown-cleaned-marker",
                "v27-restart-unknown-task-transition",
                9_000,
                |_| panic!("durable derived UnknownCleaned replay must not invoke cleanup"),
            )
            .expect("replay derived UnknownCleaned with a later caller timestamp");
        assert_eq!(replay, disposition);
        let history = fixture
            .ledger
            .load_task_attempt_history(&fixture.intent.sprint_id, "task-1")
            .expect("reload derived UnknownCleaned history");
        assert_eq!(
            history
                .unknown_terminalization_pending
                .as_ref()
                .expect("derived cleanup creates exact pending marker")
                .created_at_unix_ms,
            5_000
        );

        let crossed_verifier_cleanup = fixture
            .ledger
            .with_runner_launch_cleanup_exclusion(
                &verifier_launch.sprint_id,
                &verifier_launch.launch_id,
                |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "v27-crossed-final-verifier-cleanup",
                        5_010,
                    ))
                },
            )
            .expect("persist internally valid worker-free FinalVerifier cleanup");
        let crossed_verifier_cleanup_receipt_id = match crossed_verifier_cleanup.finish_receipt {
            PersistedFinishReceipt::WorkerCleanup(evidence) => {
                assert!(evidence.receipt.worker_lease.is_none());
                evidence.receipt.receipt_id
            }
            other => panic!("expected FinalVerifier cleanup receipt, got {other:?}"),
        };
        let crossed_reconciliation_permit = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-crossed-claim").as_str(),
                "desktop-crossed-owner",
                5_020,
                5_030,
            )
            .expect("claim unresolved capture for crossed cleanup regression")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh restart claim returned {other:?}"),
        };
        let stdout = b"restart-reconciled-output";
        let artifacts = CommandOutputArtifactSetReferenceV1::try_new(
            source,
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stdout,
                byte_length: u64::try_from(stdout.len()).expect("stdout length fits u64"),
                content_digest: Digest::sha256(stdout),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stderr,
                byte_length: 0,
                content_digest: Digest::sha256(&[]),
            },
        )
        .expect("construct reconciled artifacts");
        let crossed_resolution = CommandOutputCaptureReconciliationResolutionV1::try_new(
            &capture_intent,
            &terminal,
            crossed_reconciliation_permit.claim(),
            CommandOutputCaptureTerminalDispositionV1::Published,
            CommandOutputCaptureStoreHeadV1 {
                generation: 5,
                record_digest: Digest::sha256(b"v27-restart-crossed-resolution"),
            },
            Digest::sha256(b"v27-restart-crossed-resolution-record"),
            Some(artifacts.clone()),
            5_025,
        )
        .expect("construct crossed-cleanup resolution attempt");
        let raw_current_publication = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw current-policy Published resolution probe");
        let raw_current_error = v27_insert_raw_reconciliation_resolution(
            &raw_current_publication,
            &crossed_resolution,
            &Digest::sha256(b"unreachable-current-v29-physical-receipt"),
            &command_cleanup.proof_id,
            &crossed_verifier_cleanup_receipt_id,
        )
        .expect_err("SQL rejects current-policy Unknown publication before v27 authority");
        assert!(raw_current_error.to_string().contains(
            "current-policy Unknown publication requires exact clean-scan resolution receipt"
        ));
        drop(raw_current_publication);
        let crossed_failure = fixture
            .ledger
            .resolve_claimed_command_output_capture_unknown(
                crossed_reconciliation_permit,
                &crossed_resolution,
                None,
                None,
                &command_cleanup,
                &crossed_verifier_cleanup_receipt_id,
            )
            .expect_err("current-policy Unknown output cannot be published by v27 authority");
        assert!(matches!(
            crossed_failure.error(),
            LedgerError::ReferenceMismatch {
                entity: "command output capture reconciliation resolution",
                detail,
            } if detail.contains("current-policy Unknown publication")
        ));
        assert!(crossed_failure.has_retry_permit());
        let (_, retry_permit) = crossed_failure.into_parts();
        fixture
            .ledger
            .release_command_output_capture_reconciliation(
                retry_permit.expect("definite precommit failure returns the original permit"),
                5_026,
            )
            .expect("release returned crossed-attempt permit without waiting for expiry");

        // Continue this v27 reconciliation test under the exact positive
        // migration state that owns the historical Published behavior. The
        // preceding assertion proves a current v29 capture cannot borrow it.
        fixture
            .ledger
            .connection
            .execute_batch(
                "DROP TRIGGER command_output_sensitive_policy_no_delete;
                 DROP TRIGGER pre_v29_sensitive_output_policy_exemptions_no_insert;",
            )
            .expect("open test-only historical policy projection");
        fixture
            .ledger
            .connection
            .execute(
                "DELETE FROM command_output_sensitive_detection_policy_admissions_v29
                 WHERE effect_id = ?1",
                [&fixture.intent.effect_id],
            )
            .expect("remove current policy inside the test-only projection");
        fixture
            .ledger
            .connection
            .execute(
                "INSERT INTO pre_v29_sensitive_output_policy_exemptions (
                     effect_id, capture_id, intent_digest, contract_version
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    fixture.intent.effect_id,
                    capture_intent.capture_id,
                    capture_intent.intent_digest.as_str(),
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect("project exact historical v27 policy exemption for this test only");

        let (reconciliation_permit, reconciliation_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-claim").as_str(),
                "desktop-restart-owner",
                5_027,
                5_500,
            )
            .expect("reclaim unresolved capture immediately after exact release")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh replacement restart claim returned {other:?}"),
        };
        let resolution_states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureRestartStateV1::LaunchIntended,
            CommandOutputCaptureRestartStateV1::Finished,
            CommandOutputCaptureRestartStateV1::Published,
        ];
        let resolution_label = "v27-restart-advancing-resolution";
        let resolution_history = v27_test_physical_history(resolution_label, &resolution_states);
        let launch_head = resolution_history[3].store_head.clone();
        let finished_head = resolution_history[4].store_head.clone();
        let resolution_launch = CommandOutputCaptureRestartLaunchEvidenceV1::try_new(
            "runner-launch-binding/v1",
            br#"{"pid":8181,"launch":"unknown-resolution"}"#.to_vec(),
            launch_head,
        )
        .expect("construct advancing-resolution launch evidence");
        let resolution_physical = v27_test_physical_reconciliation(
            &capture_intent,
            &reconciliation_claim,
            resolution_label,
            &resolution_states,
            Some(terminal.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::LaunchIntended),
            CommandOutputCapturePendingResolutionV1::RolledForward {
                sequence: finished_head.generation,
                state: CommandOutputCaptureRestartStateV1::Finished,
                record_digest: finished_head.record_digest,
            },
            CommandOutputCapturePhysicalResolutionActionV1::FinishedPublicationRecovered,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
                evidence: resolution_launch,
            },
            Some(artifacts),
            None,
            5_040,
        )
        .expect("construct exact advancing physical resolution receipt");
        let resolution = CommandOutputCaptureReconciliationResolutionV1::try_new(
            &capture_intent,
            &terminal,
            &reconciliation_claim,
            CommandOutputCaptureTerminalDispositionV1::Published,
            resolution_physical.final_store_head.clone(),
            resolution_physical.final_store_head.record_digest.clone(),
            resolution_physical.artifact_reference.clone(),
            5_040,
        )
        .expect("construct exact monotonic resolution");
        let crossed_record = command_output_capture_authority::reconciliation_resolution_with_record_digest_for_test(
            &resolution,
            Digest::sha256(b"v27-substituted-resolution-record"),
        )
        .expect("construct canonical crossed resolution-record digest");
        assert!(
            resolution_physical
                .validate_for_unknown_resolution(
                    &capture_intent,
                    &acquired,
                    &terminal,
                    &reconciliation_claim,
                    &crossed_record,
                )
                .is_err(),
            "advancing physical authority must bind the exact final record digest"
        );
        let exact_artifact = resolution
            .artifact_reference
            .as_ref()
            .expect("published resolution has artifacts");
        let crossed_source_artifact = CommandOutputArtifactSetReferenceV1::try_new(
            CommandOutputArtifactSourceV1 {
                sprint_id: "crossed-sprint".into(),
                runner_launch_id: "crossed-launch".into(),
                runner_session_id: "crossed-session".into(),
                effect_id: fixture.intent.effect_id.clone(),
                request_digest: Digest::sha256(b"crossed-request"),
            },
            exact_artifact.stdout.clone(),
            exact_artifact.stderr.clone(),
        )
        .expect("construct canonical artifact with crossed source tuple");
        let crossed_source_physical =
            command_output_capture_authority::physical_reconciliation_with_artifact_for_test(
                &resolution_physical,
                crossed_source_artifact.clone(),
            )
            .expect("construct self-canonical physical receipt with crossed source");
        let crossed_source_resolution =
            command_output_capture_authority::reconciliation_resolution_with_artifact_for_test(
                &resolution,
                crossed_source_artifact,
            )
            .expect("construct self-canonical resolution with crossed source");
        assert!(
            crossed_source_physical
                .validate_for_unknown_resolution(
                    &capture_intent,
                    &acquired,
                    &terminal,
                    &reconciliation_claim,
                    &crossed_source_resolution,
                )
                .is_err(),
            "loader-side validator rejects crossed artifact source tuples"
        );
        let raw_crossed_source = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw crossed artifact-source resolution attempt");
        v27_insert_raw_restart_receipt(&raw_crossed_source, &crossed_source_physical, None)
            .expect("stage self-canonical crossed-source physical receipt");
        v27_insert_raw_consumed_reconciliation_release(
            &raw_crossed_source,
            &reconciliation_claim,
            &terminal.terminal_anchor_digest,
            crossed_source_resolution.resolved_at_unix_ms,
        )
        .expect("stage release for crossed-source resolution");
        let raw_crossed_source_error = v27_insert_raw_reconciliation_resolution(
            &raw_crossed_source,
            &crossed_source_resolution,
            &crossed_source_physical.reconciliation_digest,
            &command_cleanup.proof_id,
            &runner_cleanup_receipt_id,
        )
        .expect_err("raw SQL cannot persist a crossed artifact source tuple");
        assert!(
            raw_crossed_source_error
                .to_string()
                .contains("capture resolution must bind exact Unknown")
        );
        drop(raw_crossed_source);
        let raw_crossed_command_cleanup = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw crossed command-cleanup resolution attempt");
        raw_crossed_command_cleanup
            .execute_batch("DROP TRIGGER command_domain_cleanup_proofs_no_update;")
            .expect("allow transactional command-cleanup corruption");
        raw_crossed_command_cleanup
            .execute(
                "UPDATE command_domain_cleanup_proofs
                 SET request_digest = ?1 WHERE proof_id = ?2",
                params![
                    Digest::sha256(b"crossed-command-cleanup-request").as_str(),
                    command_cleanup.proof_id,
                ],
            )
            .expect("cross command cleanup request inside rollback transaction");
        v27_insert_raw_restart_receipt(&raw_crossed_command_cleanup, &resolution_physical, None)
            .expect("stage exact physical receipt before crossed command cleanup");
        v27_insert_raw_consumed_reconciliation_release(
            &raw_crossed_command_cleanup,
            &reconciliation_claim,
            &terminal.terminal_anchor_digest,
            resolution.resolved_at_unix_ms,
        )
        .expect("stage exact release before crossed command cleanup");
        let raw_crossed_command_error = v27_insert_raw_reconciliation_resolution(
            &raw_crossed_command_cleanup,
            &resolution,
            &resolution_physical.reconciliation_digest,
            &command_cleanup.proof_id,
            &runner_cleanup_receipt_id,
        )
        .expect_err("raw SQL cannot use a crossed command cleanup request");
        assert!(
            raw_crossed_command_error
                .to_string()
                .contains("capture resolution must bind exact Unknown")
        );
        drop(raw_crossed_command_cleanup);
        let raw_crossed_runner_cleanup = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw crossed runner-cleanup resolution attempt");
        v27_insert_raw_restart_receipt(&raw_crossed_runner_cleanup, &resolution_physical, None)
            .expect("stage exact physical receipt before crossed runner cleanup");
        v27_insert_raw_consumed_reconciliation_release(
            &raw_crossed_runner_cleanup,
            &reconciliation_claim,
            &terminal.terminal_anchor_digest,
            resolution.resolved_at_unix_ms,
        )
        .expect("stage exact release before crossed runner cleanup");
        let raw_crossed_runner_error = v27_insert_raw_reconciliation_resolution(
            &raw_crossed_runner_cleanup,
            &resolution,
            &resolution_physical.reconciliation_digest,
            &command_cleanup.proof_id,
            &crossed_verifier_cleanup_receipt_id,
        )
        .expect_err("raw SQL cannot substitute another runner role cleanup");
        assert!(
            raw_crossed_runner_error
                .to_string()
                .contains("capture resolution must bind exact Unknown")
        );
        drop(raw_crossed_runner_cleanup);
        let raw_stale_claim = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw stale resolution-claim ordering attempt");
        v27_insert_raw_restart_receipt(&raw_stale_claim, &resolution_physical, None)
            .expect("stage exact physical resolution receipt for stale ordering");
        v27_insert_raw_consumed_reconciliation_release(
            &raw_stale_claim,
            &reconciliation_claim,
            &terminal.terminal_anchor_digest,
            resolution.resolved_at_unix_ms,
        )
        .expect("stage consumed resolution claim before newer epoch");
        let later_claim = command_output_capture_authority::reconciliation_claim_for_test(
            Digest::sha256(b"v27-later-resolution-claim").as_str(),
            &capture_intent.capture_id,
            "desktop-later-owner",
            reconciliation_claim.claim_epoch + 1,
            Some(reconciliation_claim.claim_id.clone()),
            resolution.resolved_at_unix_ms + 1,
            5_600,
        )
        .expect("construct later reconciliation epoch");
        v27_insert_raw_reconciliation_claim(&raw_stale_claim, &later_claim)
            .expect("stage later claim after consumed unresolved epoch");
        v27_insert_raw_reconciliation_release(
            &raw_stale_claim,
            &later_claim,
            "Released",
            later_claim.acquired_at_unix_ms + 1,
            None,
        )
        .expect("stage exact release of later epoch");
        let stale_claim_error = v27_insert_raw_reconciliation_resolution(
            &raw_stale_claim,
            &resolution,
            &resolution_physical.reconciliation_digest,
            &command_cleanup.proof_id,
            &runner_cleanup_receipt_id,
        )
        .expect_err("a released stale claim cannot resolve after a later epoch exists");
        assert!(
            stale_claim_error
                .to_string()
                .contains("capture resolution must bind exact Unknown")
        );
        drop(raw_stale_claim);
        let raw_record = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw advancing-record substitution");
        v27_insert_raw_restart_receipt(&raw_record, &resolution_physical, None)
            .expect("stage exact advancing physical receipt");
        v27_insert_raw_consumed_reconciliation_release(
            &raw_record,
            &reconciliation_claim,
            &terminal.terminal_anchor_digest,
            crossed_record.resolved_at_unix_ms,
        )
        .expect("stage exact advancing resolution claim release");
        let raw_record_error = v27_insert_raw_reconciliation_resolution(
            &raw_record,
            &crossed_record,
            &resolution_physical.reconciliation_digest,
            &command_cleanup.proof_id,
            &runner_cleanup_receipt_id,
        )
        .expect_err("raw SQL cannot cross the advancing resolution-record digest");
        assert!(
            raw_record_error
                .to_string()
                .contains("capture resolution must bind exact Unknown")
        );
        drop(raw_record);

        let raw_receipt = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw advancing-receipt substitution");
        v27_insert_raw_consumed_reconciliation_release(
            &raw_receipt,
            &reconciliation_claim,
            &terminal.terminal_anchor_digest,
            resolution.resolved_at_unix_ms,
        )
        .expect("stage exact claim release for wrong receipt FK");
        let wrong_receipt_digest = Digest::sha256(b"v27-wrong-advancing-physical-receipt");
        let raw_receipt_error = v27_insert_raw_reconciliation_resolution(
            &raw_receipt,
            &resolution,
            &wrong_receipt_digest,
            &command_cleanup.proof_id,
            &runner_cleanup_receipt_id,
        )
        .expect_err("raw SQL cannot substitute an absent physical receipt FK");
        assert!(
            raw_receipt_error
                .to_string()
                .contains("capture resolution must bind exact Unknown")
        );
        drop(raw_receipt);
        let capture = fixture
            .ledger
            .resolve_claimed_command_output_capture_unknown(
                reconciliation_permit,
                &resolution,
                Some(&resolution_physical),
                None,
                &command_cleanup,
                &runner_cleanup_receipt_id,
            )
            .expect("consume restart claim into monotonic Unknown resolution");
        assert_eq!(capture.acquired.as_ref(), Some(&acquired));
        assert_eq!(capture.terminal.as_ref(), Some(&terminal));
        assert_eq!(
            capture.reconciliation_resolution.as_ref(),
            Some(&resolution)
        );
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        assert_eq!(
            fixture
                .ledger
                .connection
                .query_row(
                    "SELECT release_kind
                     FROM command_output_capture_reconciliation_claim_releases
                     WHERE terminal_anchor_digest = ?1",
                    [terminal.terminal_anchor_digest.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .expect("load consumed restart claim"),
            "ConsumedTerminal"
        );
        assert!(matches!(
            fixture
                .ledger
                .classify_command_output_capture_recovery(&capture_intent.capture_id)
                .expect("classify resolved Unknown capture"),
            CommandOutputCaptureRecovery::Terminal(_)
        ));
        let unchanged = fixture
            .ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("reload immutable Unknown effect");
        assert_eq!(unchanged.observation.as_ref(), Some(&observation));
        assert_eq!(unchanged.terminal_event.as_ref(), Some(&event));

        let capture_id = capture_intent.capture_id.clone();
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER command_output_capture_intents_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_output_capture_intents
                         SET max_aggregate_output_bytes = max_aggregate_output_bytes - 1
                         WHERE capture_id = ?1",
                        [&capture_id],
                    )
                    .expect("cross redundant intent limit");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER command_output_capture_obligations_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_output_capture_reconciliation_obligations
                         SET contract_version = contract_version + 1
                         WHERE capture_id = ?1",
                        [&capture_id],
                    )
                    .expect("cross redundant obligation contract");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER command_output_capture_acquisitions_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_output_capture_acquisitions
                         SET store_head_generation = store_head_generation + 1
                         WHERE capture_id = ?1",
                        [&capture_id],
                    )
                    .expect("cross redundant acquisition head");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "PRAGMA defer_foreign_keys = ON;
             DROP TRIGGER effect_session_bindings_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE effect_session_bindings
                         SET session_id = ?1 WHERE effect_id = ?2",
                        params![
                            Digest::sha256(b"v27-crossed-recovery-session").as_str(),
                            fixture.intent.effect_id,
                        ],
                    )
                    .expect("cross the capture recovery session source");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "PRAGMA defer_foreign_keys = ON;
             DROP TRIGGER runner_effect_dispatch_claims_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE runner_effect_dispatch_claims
                         SET launch_id = ?1 WHERE effect_id = ?2",
                        params![
                            Digest::sha256(b"v27-crossed-recovery-dispatch-launch").as_str(),
                            fixture.intent.effect_id,
                        ],
                    )
                    .expect("cross the durable capture dispatch claim");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER command_output_capture_terminal_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_output_capture_terminal_anchors
                         SET store_head_generation = store_head_generation + 1
                         WHERE capture_id = ?1",
                        [&capture_id],
                    )
                    .expect("cross redundant terminal head");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "PRAGMA defer_foreign_keys = ON;
             DROP TRIGGER command_output_capture_reconciliation_claims_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_output_capture_reconciliation_claims
                         SET capture_id = ?1 WHERE claim_id = ?2",
                        params![
                            Digest::sha256(b"v27-crossed-away-claim-capture").as_str(),
                            reconciliation_claim.claim_id,
                        ],
                    )
                    .expect("move redundant latest claim away from its canonical capture");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER command_output_capture_reconciliation_releases_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_output_capture_reconciliation_claim_releases
                         SET fencing_token = ?1 WHERE claim_id = ?2",
                        params![
                            Digest::sha256(b"v27-crossed-release-fence").as_str(),
                            reconciliation_claim.claim_id,
                        ],
                    )
                    .expect("cross redundant terminal release fence");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER command_output_capture_reconciliation_releases_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_output_capture_reconciliation_claim_releases
                         SET released_at_unix_ms = ?1 WHERE claim_id = ?2",
                        params![
                            sqlite_integer(
                                "test crossed predecessor release time",
                                reconciliation_claim.acquired_at_unix_ms + 1,
                            )
                            .expect("crossed predecessor release time fits SQLite"),
                            crossed_resolution.reconciliation_claim_id,
                        ],
                    )
                    .expect("move predecessor release after successor acquisition");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER command_domain_cleanup_proofs_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_domain_cleanup_proofs
                         SET request_digest = ?1 WHERE proof_id = ?2",
                        params![
                            Digest::sha256(b"v27-loader-crossed-command-cleanup").as_str(),
                            command_cleanup.proof_id,
                        ],
                    )
                    .expect("cross command cleanup request for loader regression");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER worker_cleanup_receipts_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE worker_cleanup_receipts
                         SET cleaned_at_unix_ms = ?1 WHERE receipt_id = ?2",
                        params![
                            sqlite_integer(
                                "test crossed runner cleanup time",
                                terminal.anchored_at_unix_ms - 1,
                            )
                            .expect("crossed runner cleanup time fits SQLite"),
                            runner_cleanup_receipt_id,
                        ],
                    )
                    .expect("backdate exact runner cleanup before Unknown terminal");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER command_output_capture_reconciliation_resolutions_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_output_capture_reconciliation_resolutions
                         SET store_head_generation = store_head_generation + 1
                         WHERE resolution_anchor_digest = ?1",
                        [resolution.resolution_anchor_digest.as_str()],
                    )
                    .expect("cross redundant resolution head");
            },
        );
        assert_v27_capture_loader_rejects_transactional_corruption(
            &mut fixture.ledger,
            &capture_id,
            "DROP TRIGGER command_output_capture_obligation_closures_no_update;",
            |transaction| {
                transaction
                    .execute(
                        "UPDATE command_output_capture_reconciliation_obligation_closures
                         SET closed_at_unix_ms = closed_at_unix_ms + 1
                         WHERE capture_id = ?1",
                        [&capture_id],
                    )
                    .expect("cross exact obligation closure time");
            },
        );

        let crossed_completion = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw moved-intent completion attempt");
        isolate_v27_completion_fence(&crossed_completion);
        crossed_completion
            .execute_batch(
                "PRAGMA defer_foreign_keys = ON;
                 DROP TRIGGER command_output_capture_intents_no_update;",
            )
            .expect("allow rollback-only capture-intent source crossing");
        crossed_completion
            .execute(
                "UPDATE command_output_capture_intents
                 SET sprint_id = ?1 WHERE capture_id = ?2",
                params![
                    Digest::sha256(b"v27-crossed-completion-sprint").as_str(),
                    capture_id,
                ],
            )
            .expect("move capture intent away from immutable effect sprint");
        let crossed_completion_error = crossed_completion
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
                params![
                    fixture.intent.sprint_id,
                    "v27-raw-crossed-capture-completion-receipt",
                    event.event_id,
                    i64::from(CONTRACT_VERSION),
                    sqlite_integer(
                        "test raw crossed completion time",
                        event.occurred_at_unix_ms,
                    )
                    .expect("raw crossed completion time fits SQLite"),
                ],
            )
            .expect_err("moved capture intent cannot escape the original sprint completion fence");
        assert!(
            crossed_completion_error
                .to_string()
                .contains("completion requires every capture obligation and claim closed"),
            "unexpected raw moved-intent completion rejection: {crossed_completion_error}"
        );
        drop(crossed_completion);

        let corrupted_terminal_completion = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw terminal-corruption completion attempt");
        isolate_v27_completion_fence(&corrupted_terminal_completion);
        corrupted_terminal_completion
            .execute_batch("DROP TRIGGER command_output_capture_terminal_no_update;")
            .expect("allow rollback-only terminal redundancy corruption");
        corrupted_terminal_completion
            .execute(
                "UPDATE command_output_capture_terminal_anchors
                 SET store_head_generation = store_head_generation + 1
                 WHERE capture_id = ?1",
                [&capture_id],
            )
            .expect("cross terminal store-head generation before raw completion");
        let corrupted_terminal_completion_error = corrupted_terminal_completion
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
                params![
                    fixture.intent.sprint_id,
                    "v27-raw-corrupt-terminal-completion-receipt",
                    event.event_id,
                    i64::from(CONTRACT_VERSION),
                    sqlite_integer(
                        "test raw corrupt terminal completion time",
                        event.occurred_at_unix_ms,
                    )
                    .expect("raw corrupt terminal completion time fits SQLite"),
                ],
            )
            .expect_err("terminal selector corruption must fail the raw completion fence");
        assert!(
            corrupted_terminal_completion_error
                .to_string()
                .contains("completion requires every capture obligation and claim closed"),
            "unexpected corrupt-terminal completion rejection: {corrupted_terminal_completion_error}"
        );
        drop(corrupted_terminal_completion);

        let crossed_resolution_selector_completion = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw resolution-selector completion attempt");
        isolate_v27_completion_fence(&crossed_resolution_selector_completion);
        crossed_resolution_selector_completion
            .execute_batch(
                "DROP TRIGGER command_output_capture_reconciliation_resolutions_no_update;",
            )
            .expect("allow rollback-only resolution authority substitution");
        crossed_resolution_selector_completion
            .execute(
                "UPDATE command_output_capture_reconciliation_resolutions
                 SET runner_cleanup_receipt_id = ?1
                 WHERE resolution_anchor_digest = ?2",
                params![
                    crossed_verifier_cleanup_receipt_id,
                    resolution.resolution_anchor_digest.as_str(),
                ],
            )
            .expect("cross resolution to another FK-valid runner cleanup receipt");
        let crossed_resolution_completion_error = crossed_resolution_selector_completion
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
                params![
                    fixture.intent.sprint_id,
                    "v27-raw-crossed-resolution-selector-completion-receipt",
                    event.event_id,
                    i64::from(CONTRACT_VERSION),
                    sqlite_integer(
                        "test raw crossed resolution selector completion time",
                        event.occurred_at_unix_ms,
                    )
                    .expect("crossed resolution selector completion time fits SQLite"),
                ],
            )
            .expect_err("FK-valid resolution cleanup substitution cannot admit completion");
        assert!(
            crossed_resolution_completion_error
                .to_string()
                .contains("completion requires every capture obligation and claim closed"),
            "unexpected crossed-resolution completion rejection: \
             {crossed_resolution_completion_error}"
        );
        drop(crossed_resolution_selector_completion);

        let crossed_acquisition_completion = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw acquisition-source completion attempt");
        isolate_v27_completion_fence(&crossed_acquisition_completion);
        crossed_acquisition_completion
            .execute_batch("DROP TRIGGER command_output_capture_acquisitions_no_update;")
            .expect("allow rollback-only acquisition source substitution");
        crossed_acquisition_completion
            .execute(
                "UPDATE command_output_capture_acquisitions
                 SET sprint_id = ?1 WHERE capture_id = ?2",
                params![
                    Digest::sha256(b"v27-crossed-acquisition-completion-sprint").as_str(),
                    capture_id,
                ],
            )
            .expect("cross durable acquisition away from its canonical JSON and intent");
        let crossed_acquisition_completion_error = crossed_acquisition_completion
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
                params![
                    fixture.intent.sprint_id,
                    "v27-raw-crossed-acquisition-completion-receipt",
                    event.event_id,
                    i64::from(CONTRACT_VERSION),
                    sqlite_integer(
                        "test crossed acquisition completion time",
                        event.occurred_at_unix_ms,
                    )
                    .expect("crossed acquisition completion time fits SQLite"),
                ],
            )
            .expect_err("crossed acquisition source cannot admit raw completion");
        assert!(
            crossed_acquisition_completion_error
                .to_string()
                .contains("completion requires every capture obligation and claim closed"),
            "unexpected crossed-acquisition completion rejection: \
             {crossed_acquisition_completion_error}"
        );
        drop(crossed_acquisition_completion);

        let crossed_claim_completion = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw noncanonical-claim completion attempt");
        isolate_v27_completion_fence(&crossed_claim_completion);
        crossed_claim_completion
            .execute_batch("DROP TRIGGER command_output_capture_reconciliation_claims_no_update;")
            .expect("allow rollback-only claim owner substitution");
        crossed_claim_completion
            .execute(
                "UPDATE command_output_capture_reconciliation_claims
                 SET owner_id = ?1 WHERE claim_id = ?2",
                params!["crossed-completion-owner", reconciliation_claim.claim_id,],
            )
            .expect("cross claim owner away from its canonical JSON and fencing token");
        let crossed_claim_completion_error = crossed_claim_completion
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
                params![
                    fixture.intent.sprint_id,
                    "v27-raw-crossed-claim-completion-receipt",
                    event.event_id,
                    i64::from(CONTRACT_VERSION),
                    sqlite_integer(
                        "test crossed claim completion time",
                        event.occurred_at_unix_ms,
                    )
                    .expect("crossed claim completion time fits SQLite"),
                ],
            )
            .expect_err("noncanonical historical claim cannot admit raw completion");
        assert!(
            crossed_claim_completion_error
                .to_string()
                .contains("completion requires every capture obligation and claim closed"),
            "unexpected crossed-claim completion rejection: {crossed_claim_completion_error}"
        );
        drop(crossed_claim_completion);
    }

    #[test]
    fn v27_unknown_resolution_commit_attempt_failure_never_returns_retry_permit() {
        let failure = CommandOutputCaptureUnknownResolutionWriteFailure::commit_attempted(
            LedgerError::PostCommitStateUncertain {
                operation: "test Unknown resolution commit boundary",
                recovery_id: "capture-recovery-id".into(),
                detail: "injected readback uncertainty".into(),
            },
        );
        assert!(!failure.has_retry_permit());
        assert!(failure.retry_permit().is_none());
        let (error, retry_permit) = failure.into_parts();
        assert!(matches!(
            error,
            LedgerError::PostCommitStateUncertain {
                operation: "test Unknown resolution commit boundary",
                ..
            }
        ));
        assert!(retry_permit.is_none());
    }

    #[test]
    fn fresh_runner_effect_dispatch_permit_round_trips_exact_authority_once() {
        let mut fixture = prepare_fresh_dispatch_input("exact");
        let (persisted, permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint exact fresh dispatch permit");
        assert_eq!(persisted.intent, fixture.intent);
        assert_eq!(persisted.request_bytes, EFFECT_REQUEST_BYTES);
        assert_eq!(persisted.proposed_event, fixture.proposal);
        assert!(persisted.observation.is_none());
        assert!(persisted.evidence_bytes.is_none());
        assert!(persisted.terminal_event.is_none());
        assert_eq!(
            persisted.mutation_artifact,
            PersistedMutationArtifact::NotRequired
        );
        assert_eq!(
            persisted.finish_receipt,
            PersistedFinishReceipt::NotRequired
        );
        let (claimed, transport_permit) = fixture
            .ledger
            .claim_runner_effect_dispatch(permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("durably claim exact fresh dispatch");
        assert!(claimed.dispatch_claim.is_some());
        let observation_authority = transport_permit
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("consume exact claimed transport permit");
        drop(observation_authority);
    }

    #[test]
    fn v19_direct_claim_insert_requires_the_exact_task_running_companion() {
        let mut fixture = prepare_fresh_dispatch_input("v19-direct-companion");
        let (_, permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint fresh TaskRunning permit");
        drop(permit);
        let claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&fixture.intent.effect_id),
            effect_id: fixture.intent.effect_id.clone(),
            sprint_id: fixture.intent.sprint_id.clone(),
            launch_id: fixture.launch.launch_id.clone(),
            session_id: fixture.session.session_id.clone(),
            running_boundary_id: Some(fixture.running.boundary_id.clone()),
            authority: RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id: fixture.running.boundary_id.clone(),
            },
            request_digest: fixture.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES),
            policy_hash: fixture.intent.policy_hash.clone(),
            input_snapshot: fixture.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        let transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct v19 claim insert");
        assert!(matches!(
            insert_runner_effect_dispatch_claim(&transaction, &claim),
            Err(LedgerError::Sql(_))
        ));
        drop(transaction);
        assert_eq!(
            row_count(&fixture.ledger, "runner_effect_dispatch_claims"),
            0
        );
        assert_eq!(
            row_count(&fixture.ledger, "runner_effect_dispatch_claim_authorities"),
            0
        );
    }

    #[test]
    fn v19_companion_rejects_future_class_and_orphan_commit() {
        let mut fixture = prepare_fresh_dispatch_input("v19-companion-integrity");
        let (_, permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint TaskRunning permit");
        drop(permit);
        let claim_id = runner_effect_dispatch_claim_id(&fixture.intent.effect_id);
        let future = fixture.ledger.connection.execute(
            "INSERT INTO runner_effect_dispatch_claim_authorities (
                    dispatch_claim_id, authority_class, running_boundary_id,
                    formal_check_admission_id, integration_admission_id,
                    sprint_phase_event_id, rollback_reference_id, contract_version
                 ) VALUES (?1, 'SprintFinalVerification', NULL, NULL, NULL, ?2, NULL, ?3)",
            params![
                claim_id,
                fixture.proposal.event_id,
                i64::from(CONTRACT_VERSION)
            ],
        );
        assert!(future.is_err(), "reserved phase companion is fail-closed");

        let transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start orphan-companion transaction");
        transaction
            .execute(
                "INSERT INTO runner_effect_dispatch_claim_authorities (
                    dispatch_claim_id, authority_class, running_boundary_id,
                    formal_check_admission_id, integration_admission_id,
                    sprint_phase_event_id, rollback_reference_id, contract_version
                 ) VALUES (?1, 'TaskRunning', ?2, NULL, NULL, NULL, NULL, ?3)",
                params![
                    claim_id,
                    fixture.running.boundary_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )
            .expect("deferred parent relation permits only the in-transaction predecessor");
        assert!(
            transaction.commit().is_err(),
            "orphan companion cannot commit"
        );
        assert_eq!(
            row_count(&fixture.ledger, "runner_effect_dispatch_claim_authorities"),
            0
        );
    }

    #[test]
    fn v19_companion_cannot_be_attached_to_an_existing_claim() {
        let mut fixture = prepare_fresh_dispatch_input("v19-existing-parent");
        let (_, permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint exact permit");
        let (_, transport) = fixture
            .ledger
            .claim_runner_effect_dispatch(permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("commit parent and its sole companion");
        drop(transport);
        let rejected = fixture.ledger.connection.execute(
            "INSERT INTO runner_effect_dispatch_claim_authorities (
                dispatch_claim_id, authority_class, running_boundary_id,
                formal_check_admission_id, integration_admission_id,
                sprint_phase_event_id, rollback_reference_id, contract_version
             ) VALUES (?1, 'TaskRunning', ?2, NULL, NULL, NULL, NULL, ?3)",
            params![
                runner_effect_dispatch_claim_id(&fixture.intent.effect_id),
                fixture.running.boundary_id,
                i64::from(CONTRACT_VERSION),
            ],
        );
        assert!(
            rejected.is_err(),
            "post-parent companion attachment is rejected"
        );
        assert_eq!(
            row_count(&fixture.ledger, "runner_effect_dispatch_claim_authorities"),
            1
        );
    }

    #[test]
    fn v19_missing_task_running_companion_is_corrupt_readback() {
        let mut fixture = prepare_fresh_dispatch_input("v19-missing-companion");
        let (_, permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint exact permit");
        let (_, transport) = fixture
            .ledger
            .claim_runner_effect_dispatch(permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("commit claimed TaskRunning effect");
        drop(transport);
        fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER runner_effect_dispatch_claim_authorities_no_delete;")
            .expect("disable immutable fence only to inject corruption");
        fixture
            .ledger
            .connection
            .execute(
                "DELETE FROM runner_effect_dispatch_claim_authorities WHERE dispatch_claim_id = ?1",
                [runner_effect_dispatch_claim_id(&fixture.intent.effect_id)],
            )
            .expect("inject missing companion corruption");
        assert!(matches!(
            fixture.ledger.load_effect(&fixture.intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "runner effect dispatch claim authority",
                ..
            })
        ));
    }

    #[test]
    fn provider_and_cleanup_kinds_cannot_commit_dispatch_authority() {
        let mut fixture = prepare_fresh_dispatch_input("forbidden-kind");
        let counts = (
            row_count(&fixture.ledger, "effect_intents"),
            row_count(&fixture.ledger, "effect_session_bindings"),
            row_count(&fixture.ledger, "effect_request_payloads"),
            row_count(&fixture.ledger, "agent_events"),
        );
        for kind in [EffectKind::ProviderRequest, EffectKind::CleanupWorkerDomain] {
            let mut intent = fixture.intent.clone();
            intent.kind = kind;
            assert!(matches!(
                fixture.ledger.record_runner_effect_intent_for_dispatch(
                    &intent,
                    EFFECT_REQUEST_BYTES,
                    &fixture.proposal,
                    &fixture.session.session_id,
                ),
                Err(LedgerError::ReferenceMismatch {
                    entity: "fresh runner effect dispatch permit",
                    ..
                })
            ));
            assert_eq!(
                (
                    row_count(&fixture.ledger, "effect_intents"),
                    row_count(&fixture.ledger, "effect_session_bindings"),
                    row_count(&fixture.ledger, "effect_request_payloads"),
                    row_count(&fixture.ledger, "agent_events"),
                ),
                counts,
                "forbidden {kind:?} wrote durable rows"
            );
        }
    }

    #[test]
    fn fresh_dispatch_permit_rejects_crossed_effect_session_and_binding() {
        for crossing in ["effect", "session", "binding", "running"] {
            let mut fixture = prepare_fresh_dispatch_input(crossing);
            let (_, permit) = fixture
                .ledger
                .record_runner_effect_intent_for_dispatch(
                    &fixture.intent,
                    EFFECT_REQUEST_BYTES,
                    &fixture.proposal,
                    &fixture.session.session_id,
                )
                .expect("mint crossing-test permit");
            let (_, transport_permit) = fixture
                .ledger
                .claim_runner_effect_dispatch(permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
                .expect("claim crossing-test effect");
            let mut intent = fixture.intent.clone();
            let mut launch = fixture.launch.clone();
            let mut session = fixture.session.clone();
            let mut running = fixture.running.clone();
            match crossing {
                "effect" => intent.effect_id = "crossed-effect".into(),
                "session" => {
                    launch.session_id = "crossed-session".into();
                    session.session_id = "crossed-session".into();
                    running.runner_session_id = "crossed-session".into();
                }
                "binding" => {
                    launch.launch_id = "crossed-launch".into();
                    session.launch_id = "crossed-launch".into();
                    running.runner_launch_id = "crossed-launch".into();
                }
                "running" => running.boundary_id = "crossed-running-boundary".into(),
                _ => unreachable!("closed crossing matrix"),
            }
            assert!(matches!(
                transport_permit.validate_transport_request(
                    &intent,
                    EFFECT_REQUEST_BYTES,
                    &launch,
                    &session,
                    Some(&running),
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                ),
                Err(LedgerError::ReferenceMismatch {
                    entity: "runner effect dispatch claim" | "fresh runner effect dispatch permit",
                    ..
                })
            ));
            let durable = fixture
                .ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("crossing leaves exact pending effect durable");
            assert!(durable.observation.is_none(), "crossing {crossing}");
        }
    }

    #[test]
    fn duplicate_and_recovered_effects_cannot_remint_dispatch_permits() {
        let mut fixture = prepare_fresh_dispatch_input("no-remint");
        let (_, permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint only fresh permit");
        let counts = (
            row_count(&fixture.ledger, "effect_intents"),
            row_count(&fixture.ledger, "effect_session_bindings"),
            row_count(&fixture.ledger, "effect_request_payloads"),
            row_count(&fixture.ledger, "agent_events"),
        );
        assert!(matches!(
            fixture.ledger.record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            ),
            Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect intent",
                ..
            })
        ));
        assert_eq!(
            (
                row_count(&fixture.ledger, "effect_intents"),
                row_count(&fixture.ledger, "effect_session_bindings"),
                row_count(&fixture.ledger, "effect_request_payloads"),
                row_count(&fixture.ledger, "agent_events"),
            ),
            counts
        );
        let (_, transport_permit) = fixture
            .ledger
            .claim_runner_effect_dispatch(permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("duplicate refusal does not cross the sole fresh permit");
        let observation_authority = transport_permit
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claimed permit validates once");
        drop(observation_authority);

        let database_path = fixture.database.path.clone();
        drop(fixture.ledger);
        let mut reopened = EventLedger::open(&database_path).expect("reopen recovered effect");
        assert!(matches!(
            reopened.record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            ),
            Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect intent",
                ..
            })
        ));
        let recovered = reopened
            .load_effect(&fixture.intent.effect_id)
            .expect("reload claimed unfinished effect");
        assert!(recovered.dispatch_claim.is_some());
        assert!(recovered.observation.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn postcommit_uncertainty_returns_no_dispatch_permit_and_cannot_remint() {
        let mut fixture = prepare_fresh_dispatch_input("postcommit-uncertain");
        let hardlink = fixture
            .database
            .directory
            .join("fresh-dispatch-postcommit-hardlink.sqlite3");
        fs::hard_link(&fixture.database.path, &hardlink)
            .expect("inject dispatch post-commit hardening fault");
        assert!(matches!(
            fixture.ledger.record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            ),
            Err(LedgerError::PostCommitStateUncertain {
                operation: "effect intent",
                recovery_id,
                ..
            }) if recovery_id == fixture.intent.effect_id
        ));
        fs::remove_file(&hardlink).expect("remove dispatch hardening fault");
        let recovered = fixture
            .ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("reload committed effect without execution authority");
        assert!(recovered.observation.is_none());
        assert!(matches!(
            fixture.ledger.record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            ),
            Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect intent",
                ..
            })
        ));
    }

    #[test]
    fn terminal_commit_wins_over_stale_fresh_dispatch_permit_across_ledgers() {
        let mut fixture = prepare_fresh_dispatch_input("terminal-wins");
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint stale-race fresh permit");

        let observation = effect_observation(
            &fixture.intent,
            "terminal-wins-observation",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("terminal sequence"),
            "terminal-wins-finished",
        );
        let mut competing =
            EventLedger::open(&fixture.database.path).expect("open competing ledger");
        competing
            .record_effect_observation(&observation, EFFECT_EVIDENCE_BYTES, &terminal)
            .expect("terminal transaction wins first");
        drop(competing);

        assert!(matches!(
            fixture
                .ledger
                .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner effect dispatch claim",
                ..
            })
        ));
        assert_eq!(
            row_count(&fixture.ledger, "runner_effect_dispatch_claims"),
            0
        );
        let durable = fixture
            .ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("load terminal winner");
        assert!(durable.dispatch_claim.is_none());
        assert_eq!(durable.observation, Some(observation));
    }

    #[test]
    fn durable_claim_wins_and_legacy_observation_cannot_terminalize_it() {
        let mut fixture = prepare_fresh_dispatch_input("claim-wins");
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint claim-winner permit");
        let (claimed, transport_permit) = fixture
            .ledger
            .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("claim transaction wins first");
        let claim = claimed
            .dispatch_claim
            .clone()
            .expect("claimed effect carries durable record");

        let observation = effect_observation(
            &fixture.intent,
            "claim-wins-observation",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("terminal sequence"),
            "claim-wins-finished",
        );
        let mut competing =
            EventLedger::open(&fixture.database.path).expect("open competing ledger");
        let events_before = row_count(&fixture.ledger, "agent_events");
        assert!(matches!(
            competing.record_effect_observation(&observation, EFFECT_EVIDENCE_BYTES, &terminal,),
            Err(LedgerError::Sql(_))
        ));
        drop(competing);
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
        assert_eq!(row_count(&fixture.ledger, "agent_events"), events_before);

        let authority = transport_permit
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate exact opaque transport bytes");
        let terminalized = fixture
            .ledger
            .record_claimed_effect_observation(
                authority,
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
            )
            .expect("claimed observation carries exact claim");
        assert_eq!(terminalized.dispatch_claim.as_ref(), Some(&claim));
        assert_eq!(terminalized.observation, Some(observation));
        let stored_claim_id: Option<String> = fixture
            .ledger
            .connection
            .query_row(
                "SELECT dispatch_claim_id FROM effect_observations WHERE effect_id = ?1",
                [&fixture.intent.effect_id],
                |row| row.get(0),
            )
            .expect("load terminal claim binding");
        assert_eq!(
            stored_claim_id.as_deref(),
            Some(claim.dispatch_claim_id.as_str())
        );
    }

    #[test]
    fn transport_permit_rejects_crossed_opaque_bytes_and_observation_authority() {
        let mut fixture = prepare_fresh_dispatch_input("crossed-observation-authority");
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint crossed transport permit");
        let (_, transport_permit) = fixture
            .ledger
            .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("claim crossed transport effect");
        assert!(matches!(
            transport_permit.validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                b"crossed opaque transport bytes",
            ),
            Err(LedgerError::EffectDigestMismatch {
                entity: "opaque runner transport request",
                ..
            })
        ));

        let mut second = prepare_fresh_dispatch_input("crossed-observation-source");
        let (_, second_fresh) = second
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &second.intent,
                EFFECT_REQUEST_BYTES,
                &second.proposal,
                &second.session.session_id,
            )
            .expect("mint second permit");
        let (_, second_transport) = second
            .ledger
            .claim_runner_effect_dispatch(second_fresh, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("claim second effect");
        let crossed_authority = second_transport
            .validate_transport_request(
                &second.intent,
                EFFECT_REQUEST_BYTES,
                &second.launch,
                &second.session,
                Some(&second.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("create move-only authority to cross");
        let crossed_observation = effect_observation(
            &fixture.intent,
            "crossed-authority-observation",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let crossed_terminal = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &crossed_observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("crossed terminal sequence"),
            "crossed-authority-finished",
        );
        assert!(matches!(
            fixture.ledger.record_claimed_effect_observation(
                crossed_authority,
                &crossed_observation,
                EFFECT_EVIDENCE_BYTES,
                &crossed_terminal,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner effect observation authority",
                ..
            })
        ));
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
    }

    #[test]
    fn retry_aware_claimed_observation_returns_exact_custody_before_commit() {
        let mut fixture = prepare_fresh_dispatch_input("claimed-observation-retry");
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint retry-test permit");
        let (_, transport_permit) = fixture
            .ledger
            .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("claim retry-test effect");
        let authority = transport_permit
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("derive sole retry-test observation authority");
        let observation = effect_observation(
            &fixture.intent,
            "claimed-observation-retry-observation",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("retry-test terminal sequence"),
            "claimed-observation-retry-finished",
        );

        let failure = fixture
            .ledger
            .try_record_claimed_effect_observation(
                authority,
                &observation,
                b"intentionally wrong evidence bytes",
                &terminal,
            )
            .expect_err("pre-commit evidence validation must retain exact custody");
        assert!(matches!(
            failure.error(),
            LedgerError::EffectDigestMismatch {
                entity: "effect evidence",
                ..
            }
        ));
        assert!(failure.has_retry_authority());
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
        let (_, retry_authority) = failure.into_parts();
        let persisted = fixture
            .ledger
            .try_record_claimed_effect_observation(
                retry_authority.expect("same authority is retained before commit"),
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
            )
            .expect("the retained authority terminalizes exactly once");
        assert_eq!(persisted.observation, Some(observation));
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 1);
    }

    #[test]
    fn wrong_ledger_rejects_retry_aware_authority_without_reminting_it() {
        let mut fixture = prepare_fresh_dispatch_input("claimed-observation-wrong-ledger");
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint wrong-ledger permit");
        let (_, transport_permit) = fixture
            .ledger
            .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("claim wrong-ledger effect");
        let authority = transport_permit
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("derive source-ledger authority");
        let observation = effect_observation(
            &fixture.intent,
            "claimed-observation-wrong-ledger-observation",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("wrong-ledger terminal sequence"),
            "claimed-observation-wrong-ledger-finished",
        );
        let mut crossed =
            EventLedger::open(&fixture.database.path).expect("open crossed ledger instance");
        let failure = crossed
            .try_record_claimed_effect_observation(
                authority,
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
            )
            .expect_err("another open ledger instance cannot consume authority");
        assert!(matches!(
            failure.error(),
            LedgerError::ReferenceMismatch {
                entity: "runner effect observation authority",
                ..
            }
        ));
        let (_, retry_authority) = failure.into_parts();
        drop(crossed);
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
        fixture
            .ledger
            .try_record_claimed_effect_observation(
                retry_authority.expect("wrong ledger returns the original authority"),
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
            )
            .expect("only the originating ledger can consume the original authority");
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 1);
    }

    #[cfg(unix)]
    #[test]
    fn claimed_observation_postcommit_hardening_returns_no_retry_custody() {
        let mut fixture = prepare_fresh_dispatch_input("claimed-observation-postcommit");
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint post-commit permit");
        let (_, transport_permit) = fixture
            .ledger
            .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("claim post-commit effect");
        let authority = transport_permit
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("derive post-commit authority");
        let observation = effect_observation(
            &fixture.intent,
            "claimed-observation-postcommit-observation",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("post-commit terminal sequence"),
            "claimed-observation-postcommit-finished",
        );
        let hardlink = fixture
            .database
            .directory
            .join("claimed-observation-postcommit-hardlink.sqlite3");
        fs::hard_link(&fixture.database.path, &hardlink)
            .expect("inject post-commit hardening fault");
        let failure = fixture
            .ledger
            .try_record_claimed_effect_observation(
                authority,
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
            )
            .expect_err("post-commit hardening is reconciliation-only");
        fs::remove_file(&hardlink).expect("remove post-commit hardening fault");
        assert!(matches!(
            failure.error(),
            LedgerError::PostCommitStateUncertain {
                operation: "claimed effect observation",
                recovery_id,
                ..
            } if recovery_id == &fixture.intent.effect_id
        ));
        assert!(!failure.has_retry_authority());
        assert!(failure.into_parts().1.is_none());
        assert_eq!(
            fixture
                .ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("reconcile committed terminal observation")
                .observation,
            Some(observation)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The exact claimed mutation retry fixture must carry all bound artifacts.
    fn claimed_mutation_observation_commits_artifacts_and_exact_claim_together() {
        let mut fixture = prepare_fresh_dispatch_input("claimed-mutation");
        fixture.intent.kind = EffectKind::CreateRegularFile;
        fixture.proposal = effect_proposal_event(
            &fixture.intent,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("mutation proposal sequence"),
            "claimed-mutation-proposal",
        );
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint mutation permit");
        let (_, transport_permit) = fixture
            .ledger
            .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("claim mutation dispatch");
        let authority = transport_permit
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate mutation transport");
        let observation = effect_observation(
            &fixture.intent,
            "claimed-mutation-observation",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("mutation terminal sequence"),
            "claimed-mutation-finished",
        );
        let snapshot = WorkspaceSnapshot {
            snapshot_id: digest('c'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_250,
        };
        let change_set = ChangeSet {
            change_set_id: "claimed-mutation-change-set".into(),
            base_snapshot: fixture.intent.input_snapshot.clone(),
            result_snapshot: snapshot.snapshot_id.clone(),
            operations: vec![operation_for(EffectKind::CreateRegularFile, "claimed.txt")],
        };
        let link = MutationArtifactLink {
            contract_version: CONTRACT_VERSION,
            sprint_id: fixture.intent.sprint_id.clone(),
            effect_id: fixture.intent.effect_id.clone(),
            observation_id: observation.observation_id.clone(),
            input_snapshot: fixture.intent.input_snapshot.clone(),
            result_snapshot: snapshot.snapshot_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
        };
        let failure = fixture
            .ledger
            .try_record_claimed_mutation_effect_observation(
                authority,
                &observation,
                b"intentionally wrong mutation evidence bytes",
                &terminal,
                &snapshot,
                &change_set,
                &link,
            )
            .expect_err("definite mutation pre-commit failure retains exact custody");
        assert!(matches!(
            failure.error(),
            LedgerError::EffectDigestMismatch {
                entity: "effect evidence",
                ..
            }
        ));
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
        let (_, retry_authority) = failure.into_parts();
        let persisted = fixture
            .ledger
            .try_record_claimed_mutation_effect_observation(
                retry_authority.expect("same mutation authority remains available"),
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
                &snapshot,
                &change_set,
                &link,
            )
            .expect("commit claimed mutation bundle exactly once");
        assert!(persisted.dispatch_claim.is_some());
        assert!(matches!(
            persisted.mutation_artifact,
            PersistedMutationArtifact::Linked { .. }
        ));
        assert_eq!(persisted.observation, Some(observation));
    }

    #[test]
    fn dispatch_claim_rejects_empty_and_oversized_opaque_transport_bytes() {
        for (suffix, bytes) in [
            ("empty-transport", Vec::new()),
            (
                "oversized-transport",
                vec![0_u8; MAX_RUNNER_TRANSPORT_REQUEST_BYTES + 1],
            ),
        ] {
            let mut fixture = prepare_fresh_dispatch_input(suffix);
            let (_, fresh_permit) = fixture
                .ledger
                .record_runner_effect_intent_for_dispatch(
                    &fixture.intent,
                    EFFECT_REQUEST_BYTES,
                    &fixture.proposal,
                    &fixture.session.session_id,
                )
                .expect("mint bounded transport permit");
            assert!(matches!(
                fixture
                    .ledger
                    .claim_runner_effect_dispatch(fresh_permit, &bytes),
                Err(LedgerError::EffectPayloadSize {
                    entity: "opaque runner transport request",
                    ..
                })
            ));
            assert_eq!(
                row_count(&fixture.ledger, "runner_effect_dispatch_claims"),
                0
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn dispatch_claim_postcommit_uncertainty_returns_no_transport_capability() {
        let mut fixture = prepare_fresh_dispatch_input("claim-postcommit-uncertain");
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint pre-claim permit");
        let hardlink = fixture
            .database
            .directory
            .join("dispatch-claim-postcommit-hardlink.sqlite3");
        fs::hard_link(&fixture.database.path, &hardlink)
            .expect("inject claim post-commit hardening fault");
        assert!(matches!(
            fixture.ledger.claim_runner_effect_dispatch(
                fresh_permit,
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            ),
            Err(LedgerError::PostCommitStateUncertain {
                operation: "runner effect dispatch claim",
                recovery_id,
                ..
            }) if recovery_id == fixture.intent.effect_id
        ));
        fs::remove_file(&hardlink).expect("remove claim hardening fault");
        let recovered = fixture
            .ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("reload uncertain committed claim");
        assert!(recovered.dispatch_claim.is_some());
        assert!(recovered.observation.is_none());
        assert_eq!(
            recovered.reconciliation(),
            EffectReconciliation::EvidenceRequired
        );
        assert!(matches!(
            fixture.ledger.record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            ),
            Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect intent",
                ..
            })
        ));
    }

    #[test]
    fn dispatch_claim_is_immutable_and_corrupt_binding_fails_readback() {
        let mut fixture = prepare_fresh_dispatch_input("claim-corruption");
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint corruption-test permit");
        let (_, transport_permit) = fixture
            .ledger
            .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("commit corruption-test claim");
        drop(transport_permit);
        for statement in [
            "UPDATE runner_effect_dispatch_claims SET request_digest = request_digest",
            "DELETE FROM runner_effect_dispatch_claims",
        ] {
            assert!(fixture.ledger.connection.execute_batch(statement).is_err());
        }
        fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER runner_effect_dispatch_claims_no_update;")
            .expect("disable update fence for corruption injection");
        fixture
            .ledger
            .connection
            .execute(
                "UPDATE runner_effect_dispatch_claims
                 SET request_digest = ?2 WHERE effect_id = ?1",
                params![fixture.intent.effect_id, digest('f').as_str()],
            )
            .expect("inject crossed request digest");
        assert!(matches!(
            fixture.ledger.load_effect(&fixture.intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "runner effect dispatch claim",
                ..
            })
        ));
    }

    #[test]
    fn unknown_quarantine_on_competing_ledger_invalidates_fresh_claim_authority() {
        let mut fixture = prepare_fresh_dispatch_input("quarantine-before-claim");
        let (_, fresh_permit) = fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
            )
            .expect("mint pre-quarantine permit");
        let attempt = fixture.running.attempt.clone();
        let mut competing =
            EventLedger::open(&fixture.database.path).expect("open quarantine competitor");
        let (metadata, transition) = v15_unknown_metadata(
            &competing,
            &attempt,
            "pre-claim-quarantine-disposition",
            "pre-claim-quarantine-transition",
            1_300,
        );
        let marker = v15_unknown_marker(&metadata);
        let uncertain = crate::TaskAttemptUncertainEvidence {
            uncertainty_id: "pre-claim-uncertain-authority".into(),
            authority_reference_ids: vec![fixture.intent.effect_id.clone()],
            evidence: crate::TaskAttemptEvidence::new(
                "pre-claim-uncertain-evidence".into(),
                crate::TaskAttemptEvidenceKind::UncertainAuthority,
                b"runner effect may remain live before dispatch claim".to_vec(),
            )
            .expect("construct pre-claim uncertainty"),
        };
        assert!(matches!(
            competing
                .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
                .expect("competing quarantine wins"),
            TaskAttemptDisposition::UnknownQuarantined(_)
        ));
        drop(competing);

        assert!(matches!(
            fixture
                .ledger
                .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner effect dispatch claim",
                ..
            })
        ));
        assert_eq!(
            row_count(&fixture.ledger, "runner_effect_dispatch_claims"),
            0
        );

        let stale_claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&fixture.intent.effect_id),
            effect_id: fixture.intent.effect_id.clone(),
            sprint_id: fixture.intent.sprint_id.clone(),
            launch_id: fixture.launch.launch_id.clone(),
            session_id: fixture.session.session_id.clone(),
            running_boundary_id: Some(fixture.running.boundary_id.clone()),
            authority: RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id: fixture.running.boundary_id.clone(),
            },
            request_digest: fixture.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES),
            policy_hash: fixture.intent.policy_hash.clone(),
            input_snapshot: fixture.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        let transaction = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct stale claim");
        assert!(matches!(
            insert_runner_effect_dispatch_claim(&transaction, &stale_claim),
            Err(LedgerError::Sql(_))
        ));
        transaction
            .rollback()
            .expect("rollback rejected stale claim");
    }

    #[test]
    fn terminal_launch_cleanup_on_competing_ledger_invalidates_fresh_claim_authority() {
        let database = TestDatabase::new();
        let mut ledger = open_v21_test_ledger(&database);
        let fixture = prepare_v21_final_verification_fixture(&mut ledger);
        let SprintFinalVerificationDispatchAdmission::Fresh { permit, .. } = ledger
            .admit_sprint_final_verification_for_dispatch(
                &fixture.admission,
                &fixture.phase_event,
                &fixture.intent,
                &fixture.proposed_event,
            )
            .expect("mint phase-typed pre-cleanup permit")
        else {
            panic!("new final-verification admission must be Fresh")
        };

        let mut competing = open_v21_test_ledger(&database);
        competing
            .with_runner_launch_cleanup_exclusion(
                &fixture.launch.sprint_id,
                &fixture.launch.launch_id,
                |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "cleanup-before-claim",
                        2_400,
                    ))
                },
            )
            .expect("terminal cleanup wins before claim");
        drop(competing);

        assert!(matches!(
            ledger.claim_runner_effect_dispatch(
                FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner launch cleanup admission",
                ..
            })
        ));
        assert_eq!(
            ledger
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM runner_effect_dispatch_claims WHERE effect_id = ?1",
                    [&fixture.intent.effect_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count rejected final-verification claim"),
            0
        );

        let stale_claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&fixture.intent.effect_id),
            effect_id: fixture.intent.effect_id.clone(),
            sprint_id: fixture.intent.sprint_id.clone(),
            launch_id: fixture.launch.launch_id.clone(),
            session_id: fixture.session.session_id.clone(),
            running_boundary_id: None,
            authority: RunnerEffectRequestAuthority::SprintFinalVerification {
                sprint_phase_event_id: fixture.phase_event.event_id.clone(),
            },
            request_digest: fixture.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES),
            policy_hash: fixture.intent.policy_hash.clone(),
            input_snapshot: fixture.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start direct post-cleanup claim");
        assert!(matches!(
            insert_runner_effect_dispatch_claim(&transaction, &stale_claim),
            Err(LedgerError::Sql(_))
        ));
        transaction
            .rollback()
            .expect("rollback rejected post-cleanup claim");
    }

    #[test]
    fn fresh_and_observation_authorities_are_bound_to_one_open_ledger_instance() {
        let mut claim_fixture = prepare_fresh_dispatch_input("cross-ledger-claim");
        let (_, fresh_permit) = claim_fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &claim_fixture.intent,
                EFFECT_REQUEST_BYTES,
                &claim_fixture.proposal,
                &claim_fixture.session.session_id,
            )
            .expect("mint ledger-bound fresh permit");
        let mut crossed_claim_ledger = EventLedger::open(&claim_fixture.database.path)
            .expect("open second claim ledger instance");
        assert!(matches!(
            crossed_claim_ledger
                .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner effect dispatch claim",
                ..
            })
        ));
        assert_eq!(
            row_count(&claim_fixture.ledger, "runner_effect_dispatch_claims"),
            0
        );

        let mut observation_fixture = prepare_fresh_dispatch_input("cross-ledger-observation");
        let (_, fresh_permit) = observation_fixture
            .ledger
            .record_runner_effect_intent_for_dispatch(
                &observation_fixture.intent,
                EFFECT_REQUEST_BYTES,
                &observation_fixture.proposal,
                &observation_fixture.session.session_id,
            )
            .expect("mint observation-source permit");
        let (_, transport_permit) = observation_fixture
            .ledger
            .claim_runner_effect_dispatch(fresh_permit, OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES)
            .expect("claim on originating ledger");
        let authority = transport_permit
            .validate_transport_request(
                &observation_fixture.intent,
                EFFECT_REQUEST_BYTES,
                &observation_fixture.launch,
                &observation_fixture.session,
                Some(&observation_fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("derive ledger-bound observation authority");
        let observation = effect_observation(
            &observation_fixture.intent,
            "cross-ledger-observation",
            EffectOutcome::FailedBeforeEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &observation_fixture.intent,
            &observation_fixture.proposal.event_id,
            &observation,
            observation_fixture
                .ledger
                .next_sequence(&observation_fixture.intent.sprint_id)
                .expect("cross-ledger observation sequence"),
            "cross-ledger-observation-finished",
        );
        let mut crossed_observation_ledger = EventLedger::open(&observation_fixture.database.path)
            .expect("open second observation ledger instance");
        assert!(matches!(
            crossed_observation_ledger.record_claimed_effect_observation(
                authority,
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "runner effect observation authority",
                ..
            })
        ));
        assert_eq!(
            row_count(&observation_fixture.ledger, "effect_observations"),
            0
        );
    }

    struct V15CandidateFixture {
        database: TestDatabase,
        ledger: EventLedger,
        spec: SprintSpec,
        result_snapshot: WorkspaceSnapshot,
        change_set: ChangeSet,
        launch: RunnerLaunchIntent,
        attempt: TaskAttempt,
        running: TaskAttemptRunningBoundary,
        verification: TaskAttemptVerificationBoundary,
        formal_checks: Vec<TaskAttemptFormalCheck>,
        candidate: TaskAttemptCandidateBoundary,
        prior_attempt: Option<TaskAttempt>,
        prior_disposition: Option<TaskAttemptDisposition>,
        prior_launch: Option<RunnerLaunchIntent>,
        candidate_required: bool,
    }

    #[derive(Clone)]
    struct V15SnapshotOverrides {
        base_snapshot_id: Digest,
        result_snapshot_id: Digest,
    }

    #[derive(Clone, Copy)]
    enum CandidateTaskRequirement {
        Required,
        Optional,
    }

    fn optional_task(task_id: &str, base_snapshot: Digest) -> crate::TaskSpec {
        crate::TaskSpec {
            task_id: task_id.into(),
            goal: format!("Exercise optional completion semantics for {task_id}"),
            dependencies: Vec::new(),
            path_scopes: vec![PathScope::Workspace],
            acceptance_checks: vec!["tests".into()],
            base_snapshot,
            required: false,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v15_candidate_fixture(automated: bool) -> V15CandidateFixture {
        prepare_v15_candidate_fixture_with_result(automated, false)
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v15_candidate_fixture_with_result(
        automated: bool,
        verified_no_op: bool,
    ) -> V15CandidateFixture {
        prepare_v15_candidate_fixture_with_options(automated, verified_no_op, false, false)
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v15_candidate_fixture_with_retry() -> V15CandidateFixture {
        prepare_v15_candidate_fixture_with_options(true, true, false, true)
    }

    #[allow(clippy::fn_params_excessive_bools, clippy::too_many_lines)]
    fn prepare_v15_candidate_fixture_with_options(
        automated: bool,
        verified_no_op: bool,
        include_bound_read: bool,
        include_retry: bool,
    ) -> V15CandidateFixture {
        prepare_v15_candidate_fixture_with_graph_options(
            automated,
            verified_no_op,
            include_bound_read,
            include_retry,
            CandidateTaskRequirement::Required,
            None,
        )
    }

