    #[test]
    #[allow(clippy::too_many_lines)]
    fn v31_restart_terminal_prepared_unknown_requires_and_persists_exact_same_head_clean_authority()
    {
        let (mut fixture, capture_intent, dispatch_permit, _) =
            v27_prepare_stale_capture_permit("v27-restart-terminal-prepared-unknown");
        let acquired = v27_test_capture_acquired_at_generation(
            &capture_intent,
            dispatch_permit
                .expected_output_capture_dispatch_claim_id()
                .expect("TerminalPrepared-Unknown dispatch identity"),
            "v27-restart-terminal-prepared-unknown",
            2,
            1_240,
        );
        let (_, transport) = fixture
            .ledger
            .claim_command_output_capture_dispatch(
                dispatch_permit,
                acquired.clone(),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("commit TerminalPrepared-Unknown acquisition and dispatch");
        drop(transport);
        let (reconciliation_permit, reconciliation_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-restart-terminal-prepared-unknown-claim").as_str(),
                "desktop-restart-owner",
                1_300,
                1_700,
            )
            .expect("claim TerminalPrepared-Unknown capture")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh TerminalPrepared-Unknown claim returned {other:?}"),
        };
        let launch = CommandOutputCaptureRestartLaunchEvidenceV1::try_new(
            "runner-launch-binding/v1",
            br#"{"pid":7171,"launch":"terminal-prepared-unknown"}"#.to_vec(),
            CommandOutputCaptureStoreHeadV1 {
                generation: 4,
                record_digest: Digest::sha256(b"v27-terminal-prepared-unknown-launch"),
            },
        )
        .expect("construct TerminalPrepared-Unknown launch");
        let retained_but_semantically_unusable_terminal = [0xff, 0x00, 0x80, b'{'];
        let terminal_prepared = CommandOutputCapturePhysicalTerminalEvidenceV1 {
            schema: "runner-terminal-record/v1".into(),
            canonical_bytes_digest: Digest::sha256(&retained_but_semantically_unusable_terminal),
            store_head: CommandOutputCaptureStoreHeadV1 {
                generation: 7,
                record_digest: Digest::sha256(b"v27-terminal-prepared-unknown-head"),
            },
        };
        let artifacts =
            v27_test_artifact_reference(&capture_intent, "v27-restart-terminal-prepared-unknown");
        let states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureRestartStateV1::LaunchIntended,
            CommandOutputCaptureRestartStateV1::Finished,
            CommandOutputCaptureRestartStateV1::Published,
            CommandOutputCaptureRestartStateV1::TerminalPrepared,
        ];
        let physical = v27_test_physical_reconciliation(
            &capture_intent,
            &reconciliation_claim,
            "v27-restart-terminal-prepared-unknown",
            &states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::TerminalPrepared),
            CommandOutputCapturePendingResolutionV1::None,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence { evidence: launch },
            Some(artifacts),
            Some(terminal_prepared),
            1_500,
        )
        .expect("construct exact unusable TerminalPrepared physical cut");
        let observation = effect_observation(
            &fixture.intent,
            "v27-restart-terminal-prepared-unknown-observation",
            EffectOutcome::Unknown {
                evidence_digest: physical
                    .effect_evidence_digest()
                    .expect("TerminalPrepared-Unknown evidence digest"),
            },
            1_490,
        );
        let event = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("TerminalPrepared-Unknown terminal sequence"),
            "v27-restart-terminal-prepared-unknown-event",
        );
        fixture
            .ledger
            .record_reconciled_claimed_command_output_capture_unknown(
                reconciliation_permit,
                &observation,
                &event,
                &physical,
            )
            .expect("conservatively record exact TerminalPrepared cut as Unknown");
        let capture = fixture
            .ledger
            .load_command_output_capture(&capture_intent.capture_id)
            .expect("load TerminalPrepared-Unknown capture");
        let terminal = capture
            .terminal
            .as_ref()
            .expect("TerminalPrepared-Unknown terminal");
        assert_eq!(
            terminal.observation_class,
            CommandOutputCaptureObservationClassV1::Unknown
        );
        assert_eq!(
            terminal.disposition,
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
        );
        assert!(terminal.artifact_reference.is_none());
        assert!(capture.reconciliation_obligation_closure.is_none());
        assert_eq!(
            row_count(&fixture.ledger, "command_domain_cleanup_proofs"),
            0
        );
        assert!(matches!(
            fixture
                .ledger
                .classify_command_output_capture_recovery(&capture_intent.capture_id)
                .expect("classify TerminalPrepared downgrade"),
            CommandOutputCaptureRecovery::ReconciliationRequired(_)
        ));

        let command_cleanup = v27_test_command_cleanup(
            &fixture.intent,
            &observation,
            &fixture.launch,
            &fixture.session,
            "v27-restart-terminal-prepared-unknown-resolution",
            1_520,
        );
        fixture
            .ledger
            .record_command_domain_cleanup_proof(&command_cleanup)
            .expect("persist TerminalPrepared-Unknown command cleanup");
        let unknown_evidence = crate::TaskAttemptUnknownEvidence {
            effect_id: fixture.intent.effect_id.clone(),
            observation_id: observation.observation_id.clone(),
            evidence: crate::TaskAttemptEvidence::new(
                "v27-terminal-prepared-unknown-source".into(),
                crate::TaskAttemptEvidenceKind::UnknownTerminalEffect,
                physical
                    .canonical_evidence_bytes()
                    .expect("encode TerminalPrepared-Unknown evidence"),
            )
            .expect("construct TerminalPrepared-Unknown source evidence"),
        };
        let disposition = fixture
            .ledger
            .with_task_command_unknown_cleaned_disposition_derived_timestamps(
                &command_cleanup,
                &fixture.running.attempt,
                TaskState::Running,
                "v27-terminal-prepared-unknown-disposition",
                &unknown_evidence,
                "v27-terminal-prepared-unknown-release",
                "v27-terminal-prepared-unknown-marker",
                "v27-terminal-prepared-unknown-transition",
                1_530,
                |claim| {
                    Ok(cleanup_terminal_from_live_claim(
                        claim,
                        "v27-terminal-prepared-unknown-runner-cleanup",
                        1_550,
                    ))
                },
            )
            .expect("persist TerminalPrepared-Unknown runner cleanup");
        let runner_cleanup_receipt_id = match disposition {
            TaskAttemptDisposition::UnknownCleaned(value) => {
                value.cleanup_release.cleanup_receipt.receipt_id
            }
            other => panic!("expected UnknownCleaned disposition, got {other:?}"),
        };
        let restart_receipt =
            command_output_capture_authority::load_restart_claimed_unresolved_receipt_for_terminal(
                &fixture.ledger.connection,
                &terminal.terminal_anchor_digest,
            )
            .expect("load TerminalPrepared-Unknown restart receipt")
            .expect("TerminalPrepared-Unknown receipt exists");
        let (resolution_permit, resolution_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-terminal-prepared-same-head-resolution-claim").as_str(),
                "desktop-resolution-owner",
                1_560,
                1_800,
            )
            .expect("claim TerminalPrepared-Unknown same-head resolution")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh TerminalPrepared resolution claim returned {other:?}"),
        };
        assert!(
            CommandOutputCaptureReconciliationResolutionV1::try_new_restart_same_head(
                &capture_intent,
                &acquired,
                terminal,
                &resolution_claim,
                &restart_receipt,
                CommandOutputCaptureTerminalDispositionV1::Abandoned,
                1_570,
            )
            .is_err(),
            "TerminalPrepared cannot substitute abandonment for retained publication"
        );
        let resolution = CommandOutputCaptureReconciliationResolutionV1::try_new_restart_same_head(
            &capture_intent,
            &acquired,
            terminal,
            &resolution_claim,
            &restart_receipt,
            CommandOutputCaptureTerminalDispositionV1::Published,
            1_570,
        )
        .expect("construct TerminalPrepared same-head Published resolution");
        let crossed_artifact =
            v27_test_artifact_reference(&capture_intent, "v27-same-head-crossed-artifact");
        let crossed_resolution =
            command_output_capture_authority::reconciliation_resolution_with_artifact_for_test(
                &resolution,
                crossed_artifact,
            )
            .expect("construct canonical crossed-artifact resolution");
        let raw = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw same-head artifact substitution");
        raw.execute(
            "INSERT INTO command_output_capture_reconciliation_claim_releases (
                claim_id, capture_id, claim_epoch, fencing_token, release_kind,
                released_at_unix_ms, terminal_anchor_digest, successor_claim_id,
                successor_fencing_token, successor_claim_digest, contract_version
             ) VALUES (?1, ?2, ?3, ?4, 'ConsumedTerminal', ?5, ?6,
                       NULL, NULL, NULL, ?7)",
            params![
                resolution_claim.claim_id,
                resolution_claim.capture_id,
                sqlite_integer("test same-head claim epoch", resolution_claim.claim_epoch)
                    .expect("same-head claim epoch fits SQLite"),
                resolution_claim.fencing_token.as_str(),
                sqlite_integer(
                    "test same-head release time",
                    crossed_resolution.resolved_at_unix_ms,
                )
                .expect("same-head release time fits SQLite"),
                terminal.terminal_anchor_digest.as_str(),
                i64::from(resolution_claim.contract_version),
            ],
        )
        .expect("stage exact consumed claim for raw artifact substitution");
        let crossed_reference = crossed_resolution
            .artifact_reference
            .as_ref()
            .expect("crossed Published resolution has artifacts");
        let raw_error = raw
            .execute(
                "INSERT INTO command_output_capture_reconciliation_resolutions (
                    resolution_anchor_digest, capture_id, effect_id, observation_id,
                    terminal_anchor_digest, reconciliation_claim_id,
                    reconciliation_fencing_token, disposition, store_head_generation,
                    store_head_digest, resolution_record_digest, artifact_manifest_digest,
                    artifact_reference_json, command_domain_cleanup_proof_id,
                    runner_cleanup_receipt_id, physical_recovery_receipt_digest,
                    resolved_at_unix_ms, layout_version, contract_version, resolution_json
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'Published', ?8, ?9, ?10, ?11,
                    ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19
                 )",
                params![
                    crossed_resolution.resolution_anchor_digest.as_str(),
                    crossed_resolution.capture_id,
                    crossed_resolution.effect_id,
                    crossed_resolution.observation_id,
                    crossed_resolution.terminal_anchor_digest.as_str(),
                    crossed_resolution.reconciliation_claim_id,
                    crossed_resolution.reconciliation_fencing_token.as_str(),
                    sqlite_integer(
                        "test crossed resolution generation",
                        crossed_resolution.store_head.generation,
                    )
                    .expect("crossed resolution generation fits SQLite"),
                    crossed_resolution.store_head.record_digest.as_str(),
                    crossed_resolution.resolution_record_digest.as_str(),
                    crossed_reference.manifest_digest.as_str(),
                    encode("test crossed resolution artifact", crossed_reference)
                        .expect("encode crossed resolution artifact"),
                    command_cleanup.proof_id,
                    runner_cleanup_receipt_id,
                    restart_receipt.reconciliation_digest.as_str(),
                    sqlite_integer(
                        "test crossed resolution time",
                        crossed_resolution.resolved_at_unix_ms,
                    )
                    .expect("crossed resolution time fits SQLite"),
                    i64::from(crossed_resolution.layout_version),
                    i64::from(crossed_resolution.contract_version),
                    encode("test crossed same-head resolution", &crossed_resolution)
                        .expect("encode crossed same-head resolution"),
                ],
            )
            .expect_err("raw SQL cannot substitute same-head Published artifacts");
        assert!(raw_error.to_string().contains(
            "current-policy Unknown publication requires exact clean-scan resolution receipt"
        ));
        drop(raw);
        let failure = fixture
            .ledger
            .resolve_claimed_command_output_capture_unknown(
                resolution_permit,
                &resolution,
                None,
                None,
                &command_cleanup,
                &runner_cleanup_receipt_id,
            )
            .expect_err("v1-only TerminalPrepared receipt cannot publish current-policy output");
        assert!(failure.has_retry_permit());
        let (_, retry_permit) = failure.into_parts();
        fixture
            .ledger
            .release_command_output_capture_reconciliation(
                retry_permit.expect("v1-only rejection returns exact retry permit"),
                1_571,
            )
            .expect("release rejected v1-only resolution claim");
        let unresolved = fixture
            .ledger
            .load_command_output_capture(&capture_intent.capture_id)
            .expect("reload still-open current Unknown capture");
        assert!(unresolved.reconciliation_resolution.is_none());
        assert!(unresolved.reconciliation_obligation_closure.is_none());
        assert!(matches!(
            fixture
                .ledger
                .load_effect(&fixture.intent.effect_id)
                .expect("reload immutable TerminalPrepared-Unknown effect")
                .observation
                .expect("TerminalPrepared-Unknown observation")
                .outcome,
            EffectOutcome::Unknown { .. }
        ));

        let (resolution_permit, resolution_claim) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v31-terminal-prepared-same-head-resolution-claim").as_str(),
                "desktop-resolution-owner-v31",
                1_572,
                1_900,
            )
            .expect("claim TerminalPrepared-Unknown for current same-head resolution")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (permit, claim),
            other => panic!("fresh v31 same-head resolution claim returned {other:?}"),
        };
        let resolution = CommandOutputCaptureReconciliationResolutionV1::try_new_restart_same_head(
            &capture_intent,
            &acquired,
            terminal,
            &resolution_claim,
            &restart_receipt,
            CommandOutputCaptureTerminalDispositionV1::Published,
            1_580,
        )
        .expect("construct current same-head Published resolution");
        assert_eq!(restart_receipt, physical);

        let physical_head = |state| {
            physical
                .lifecycle_history
                .iter()
                .find(|entry| entry.state == state)
                .expect("restart receipt contains the complete clean lifecycle")
                .store_head
                .clone()
        };
        let mut clean_runner = v29_test_clean_runner_reference(
            &capture_intent,
            &acquired,
            &terminal.store_head,
            &physical
                .terminal_prepared
                .as_ref()
                .expect("same-head restart has retained terminal evidence")
                .canonical_bytes_digest,
            CommandTerminationV1::Exited { code: 0 },
            command_cleanup.backend,
            "v31-restart-terminal-prepared-same-head",
            1_569,
        );
        clean_runner.writer_attached_store_head =
            physical_head(CommandOutputCaptureRestartStateV1::WriterAttached);
        clean_runner.launch_intended_store_head =
            physical_head(CommandOutputCaptureRestartStateV1::LaunchIntended);
        clean_runner.finished_store_head =
            physical_head(CommandOutputCaptureRestartStateV1::Finished);
        clean_runner.published_store_head =
            physical_head(CommandOutputCaptureRestartStateV1::Published);
        clean_runner.terminal_prepared_store_head =
            physical_head(CommandOutputCaptureRestartStateV1::TerminalPrepared);
        clean_runner
            .canonicalize_journal_heads_for_test()
            .expect("recompute clean journal after exact physical-head binding");
        clean_runner
            .validate()
            .expect("validate exact same-head clean runner reference");

        let clean_resolution =
            CommandOutputCleanScanResolutionReceiptV1::try_new_from_runner_reference(
                &capture_intent,
                &acquired,
                terminal,
                &resolution_claim,
                &resolution,
                Some(&restart_receipt),
                SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
                &clean_runner,
            )
            .expect("construct self-contained same-head clean resolution authority");
        let mut missing_restart = clean_resolution.clone();
        missing_restart.restart_same_head_receipt = None;
        assert!(
            missing_restart
                .validate()
                .expect_err("same-head receipt cannot omit restart physical authority")
                .to_string()
                .contains("same-head publication requires")
        );

        let crossed = v29_unknown_clean_resolution_fixture("v31-crossed-physical");
        assert!(
            CommandOutputCleanScanResolutionReceiptV1::try_new_from_runner_reference(
                &capture_intent,
                &acquired,
                terminal,
                &resolution_claim,
                &resolution,
                Some(&crossed.physical),
                SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
                &clean_runner,
            )
            .is_err(),
            "same-head receipt cannot cross another capture's physical authority"
        );
        let mut advancing_with_restart = crossed.receipt.clone();
        advancing_with_restart.restart_same_head_receipt = Some(restart_receipt.clone());
        assert!(
            advancing_with_restart
                .validate()
                .expect_err("advancing receipt cannot borrow same-head authority")
                .to_string()
                .contains("cannot borrow restart same-head authority")
        );
        drop(crossed);

        let persisted = fixture
            .ledger
            .resolve_claimed_command_output_capture_unknown(
                resolution_permit,
                &resolution,
                None,
                Some(&clean_resolution),
                &command_cleanup,
                &runner_cleanup_receipt_id,
            )
            .expect("persist exact v31 same-head clean Published resolution");
        assert_eq!(
            persisted.reconciliation_resolution.as_ref(),
            Some(&resolution)
        );
        assert_eq!(
            fixture
                .ledger
                .load_command_output_clean_scan_resolution_receipt_for_effect(
                    &fixture.intent.effect_id,
                )
                .expect("load exact same-head clean resolution authority"),
            clean_resolution
        );
        assert_eq!(
            fixture
                .ledger
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM command_output_clean_scan_resolution_exact_v29
                     WHERE effect_id = ?1 AND resolution_anchor_digest = ?2",
                    params![
                        fixture.intent.effect_id,
                        resolution.resolution_anchor_digest.as_str(),
                    ],
                    |row| row.get::<_, i64>(0),
                )
                .expect("query exact same-head clean resolution view"),
            1
        );
        assert!(matches!(
            fixture
                .ledger
                .claim_command_output_capture_reconciliation(
                    &capture_intent.capture_id,
                    Digest::sha256(b"v31-replayed-same-head-physical").as_str(),
                    "desktop-replay-owner-v31",
                    1_590,
                    1_950,
                )
                .expect("classify replay after same-head completion"),
            CommandOutputCaptureReconciliationAdmission::Terminal(replay)
                if replay.reconciliation_resolution.as_ref() == Some(&resolution)
        ));

        let database_path = fixture.database.path.clone();
        drop(fixture.ledger);
        let reopened = EventLedger::open(&database_path).expect("reopen v31 same-head ledger");
        assert_eq!(
            reopened
                .load_command_output_clean_scan_resolution_receipt_for_effect(
                    &capture_intent.source.effect_id,
                )
                .expect("read back same-head authority after restart"),
            clean_resolution
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v27_physical_pending_recovery_actions_accept_only_exact_finished_terminal_and_torn_cuts() {
        let mut fixture = prepare_fresh_command_dispatch_input("v27-physical-pending-actions");
        let capture_intent = v27_test_capture_intent(
            &fixture.intent,
            &fixture.launch,
            &fixture.session,
            "v27-physical-pending-actions",
        );
        let dispatch_permit = match fixture
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
                &capture_intent,
            )
            .expect("admit pending-actions capture")
        {
            CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh pending-actions admission returned {other:?}"),
        };
        drop(dispatch_permit);
        let claim = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-physical-pending-actions-claim").as_str(),
                "desktop-restart-owner",
                1_300,
                1_700,
            )
            .expect("claim pending-actions capture")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => {
                drop(permit);
                claim
            }
            other => panic!("fresh pending-actions reconciliation returned {other:?}"),
        };
        let acquired = v27_test_capture_acquired_at_generation(
            &capture_intent,
            runner_effect_dispatch_claim_id(&fixture.intent.effect_id),
            "v27-physical-pending-actions",
            2,
            1_240,
        );
        let launch = CommandOutputCaptureRestartLaunchEvidenceV1::try_new(
            "runner-launch-binding/v1",
            br#"{"pid":6262,"launch":"pending-actions"}"#.to_vec(),
            CommandOutputCaptureStoreHeadV1 {
                generation: 4,
                record_digest: Digest::sha256(b"v27-physical-pending-actions-launch"),
            },
        )
        .expect("construct pending-actions launch");
        let artifact = v27_test_artifact_reference(&capture_intent, "v27-physical-pending-actions");

        let published_states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureRestartStateV1::LaunchIntended,
            CommandOutputCaptureRestartStateV1::Finished,
            CommandOutputCaptureRestartStateV1::Published,
        ];
        let published_history =
            v27_test_physical_history("v27-physical-pending-actions-finished", &published_states);
        let finished_head = published_history[4].store_head.clone();
        let finished_recovered = v27_test_physical_reconciliation(
            &capture_intent,
            &claim,
            "v27-physical-pending-actions-finished",
            &published_states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::LaunchIntended),
            CommandOutputCapturePendingResolutionV1::RolledForward {
                sequence: finished_head.generation,
                state: CommandOutputCaptureRestartStateV1::Finished,
                record_digest: finished_head.record_digest,
            },
            CommandOutputCapturePhysicalResolutionActionV1::FinishedPublicationRecovered,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
                evidence: launch.clone(),
            },
            Some(artifact.clone()),
            None,
            1_500,
        )
        .expect("accept exact pending Finished roll-forward and publication");
        assert_eq!(
            finished_recovered.final_state,
            CommandOutputCaptureRestartStateV1::Published
        );

        let pending_published_label = "v27-physical-pending-actions-published";
        let pending_published_history =
            v27_test_physical_history(pending_published_label, &published_states);
        let published_head = pending_published_history[5].store_head.clone();
        let pending_published = v27_test_physical_reconciliation(
            &capture_intent,
            &claim,
            pending_published_label,
            &published_states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::Finished),
            CommandOutputCapturePendingResolutionV1::RolledForward {
                sequence: published_head.generation,
                state: CommandOutputCaptureRestartStateV1::Published,
                record_digest: published_head.record_digest.clone(),
            },
            CommandOutputCapturePhysicalResolutionActionV1::FinishedPublicationRecovered,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
                evidence: launch.clone(),
            },
            Some(artifact.clone()),
            None,
            1_505,
        )
        .expect("accept exact pending Published roll-forward from Finished");
        assert_eq!(pending_published.final_store_head, published_head);

        let torn_published_label = "v27-physical-pending-actions-published-torn";
        let torn_published_history =
            v27_test_physical_history(torn_published_label, &published_states);
        let torn_published_head = torn_published_history[5].store_head.clone();
        let torn_published = v27_test_physical_reconciliation(
            &capture_intent,
            &claim,
            torn_published_label,
            &published_states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::Finished),
            CommandOutputCapturePendingResolutionV1::RemovedTorn {
                sequence: torn_published_head.generation,
                name_digest: Digest::sha256(b"pending.6.published.torn"),
            },
            CommandOutputCapturePhysicalResolutionActionV1::FinishedPublicationRecovered,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
                evidence: launch.clone(),
            },
            Some(artifact.clone()),
            None,
            1_507,
        )
        .expect("accept torn pending Published removal and canonical successor append");
        assert_eq!(torn_published.final_store_head, torn_published_head);

        assert!(
            v27_test_physical_reconciliation(
                &capture_intent,
                &claim,
                "v27-physical-pending-actions-published-wrong-initial",
                &published_states,
                Some(acquired.store_head.clone()),
                Some(CommandOutputCaptureRestartStateV1::LaunchIntended),
                CommandOutputCapturePendingResolutionV1::RolledForward {
                    sequence: 6,
                    state: CommandOutputCaptureRestartStateV1::Published,
                    record_digest: v27_test_physical_history(
                        "v27-physical-pending-actions-published-wrong-initial",
                        &published_states,
                    )[5]
                    .store_head
                    .record_digest
                    .clone(),
                },
                CommandOutputCapturePhysicalResolutionActionV1::FinishedPublicationRecovered,
                Some(acquired.clone()),
                CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
                    evidence: launch.clone(),
                },
                Some(artifact.clone()),
                None,
                1_508,
            )
            .is_err(),
            "pending Published cannot substitute a LaunchIntended initial cut"
        );
        assert!(
            v27_test_physical_reconciliation(
                &capture_intent,
                &claim,
                "v27-physical-pending-actions-published-torn-wrong-sequence",
                &published_states,
                Some(acquired.store_head.clone()),
                Some(CommandOutputCaptureRestartStateV1::Finished),
                CommandOutputCapturePendingResolutionV1::RemovedTorn {
                    sequence: 7,
                    name_digest: Digest::sha256(b"pending.7.published.substituted"),
                },
                CommandOutputCapturePhysicalResolutionActionV1::FinishedPublicationRecovered,
                Some(acquired.clone()),
                CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
                    evidence: launch.clone(),
                },
                Some(artifact.clone()),
                None,
                1_509,
            )
            .is_err(),
            "torn Published candidate must name the exact successor generation"
        );

        let terminal_states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureRestartStateV1::LaunchIntended,
            CommandOutputCaptureRestartStateV1::Finished,
            CommandOutputCaptureRestartStateV1::Published,
            CommandOutputCaptureRestartStateV1::TerminalPrepared,
        ];
        let terminal_bytes = br#"{"terminal":"pending-valid"}"#;
        let terminal_head = CommandOutputCaptureStoreHeadV1 {
            generation: 7,
            record_digest: Digest::sha256(b"v27-physical-pending-actions-terminal"),
        };
        let terminal_evidence = CommandOutputCapturePhysicalTerminalEvidenceV1 {
            schema: "runner-terminal-record/v1".into(),
            canonical_bytes_digest: Digest::sha256(terminal_bytes),
            store_head: terminal_head.clone(),
        };
        let terminal_recovered = v27_test_physical_reconciliation(
            &capture_intent,
            &claim,
            "v27-physical-pending-actions-terminal",
            &terminal_states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::Published),
            CommandOutputCapturePendingResolutionV1::RolledForward {
                sequence: terminal_head.generation,
                state: CommandOutputCaptureRestartStateV1::TerminalPrepared,
                record_digest: terminal_head.record_digest.clone(),
            },
            CommandOutputCapturePhysicalResolutionActionV1::TerminalPreparedRecovered,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence {
                evidence: launch.clone(),
            },
            Some(artifact.clone()),
            Some(terminal_evidence),
            1_510,
        )
        .expect("accept exact pending TerminalPrepared roll-forward");
        assert_eq!(
            terminal_recovered.final_state,
            CommandOutputCaptureRestartStateV1::TerminalPrepared
        );

        let torn = v27_test_physical_reconciliation(
            &capture_intent,
            &claim,
            "v27-physical-pending-actions-torn",
            &published_states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::Published),
            CommandOutputCapturePendingResolutionV1::RemovedTorn {
                sequence: 7,
                name_digest: Digest::sha256(b"pending.7.torn"),
            },
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback,
            Some(acquired.clone()),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence { evidence: launch },
            Some(artifact),
            None,
            1_520,
        )
        .expect("accept exact torn TerminalPrepared removal as Published readback");
        assert_eq!(
            torn.final_state,
            CommandOutputCaptureRestartStateV1::Published
        );
        assert!(torn.terminal_prepared.is_none());

        assert!(
            v27_test_physical_reconciliation(
                &capture_intent,
                &claim,
                "v27-physical-pending-actions-torn-wrong-sequence",
                &published_states,
                Some(acquired.store_head.clone()),
                Some(CommandOutputCaptureRestartStateV1::Published),
                CommandOutputCapturePendingResolutionV1::RemovedTorn {
                    sequence: 8,
                    name_digest: Digest::sha256(b"pending.8.substituted"),
                },
                CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback,
                Some(acquired),
                torn.launch_history.clone(),
                torn.artifact_reference.clone(),
                None,
                1_530,
            )
            .is_err()
        );

        let intent_only_states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::CleanupIntended,
            CommandOutputCaptureRestartStateV1::Cleaned,
        ];
        assert!(
            v27_test_physical_reconciliation(
                &capture_intent,
                &claim,
                "v27-physical-pending-actions-sequence-one",
                &intent_only_states,
                None,
                None,
                CommandOutputCapturePendingResolutionV1::RemovedTorn {
                    sequence: 1,
                    name_digest: Digest::sha256(b"pending.1.torn"),
                },
                CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned,
                None,
                CommandOutputCaptureLaunchHistoryV1::NoneBeforeLaunch,
                None,
                None,
                1_540,
            )
            .is_ok()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v27_sql_rejects_restart_receipt_selector_spoofing_and_cross_kind_reuse() {
        let mut fixture = prepare_fresh_command_dispatch_input("v27-receipt-sql-parity");
        let capture_intent = v27_test_capture_intent(
            &fixture.intent,
            &fixture.launch,
            &fixture.session,
            "v27-receipt-sql-parity",
        );
        let dispatch_permit = match fixture
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
                &capture_intent,
            )
            .expect("admit SQL-parity capture")
        {
            CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh SQL-parity admission returned {other:?}"),
        };
        let acquired = v27_test_capture_acquired_at_generation(
            &capture_intent,
            dispatch_permit
                .expected_output_capture_dispatch_claim_id()
                .expect("SQL-parity dispatch identity"),
            "v27-receipt-sql-parity",
            2,
            1_240,
        );
        drop(dispatch_permit);
        let claim = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-receipt-sql-parity-claim").as_str(),
                "desktop-restart-owner",
                1_300,
                1_700,
            )
            .expect("claim SQL-parity capture")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => {
                drop(permit);
                claim
            }
            other => panic!("fresh SQL-parity reconciliation returned {other:?}"),
        };
        let launch = CommandOutputCaptureRestartLaunchEvidenceV1::try_new(
            "runner-launch-binding/v1",
            br#"{"pid":7373,"launch":"sql-parity"}"#.to_vec(),
            CommandOutputCaptureStoreHeadV1 {
                generation: 4,
                record_digest: Digest::sha256(b"v27-receipt-sql-parity-launch"),
            },
        )
        .expect("construct SQL-parity launch evidence");
        let states = [
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureRestartStateV1::LaunchIntended,
            CommandOutputCaptureRestartStateV1::CleanupIntended,
            CommandOutputCaptureRestartStateV1::Cleaned,
        ];
        let receipt = v27_test_physical_reconciliation(
            &capture_intent,
            &claim,
            "v27-receipt-sql-parity",
            &states,
            Some(acquired.store_head.clone()),
            Some(CommandOutputCaptureRestartStateV1::LaunchIntended),
            CommandOutputCapturePendingResolutionV1::None,
            CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned,
            Some(acquired),
            CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence { evidence: launch },
            None,
            None,
            1_500,
        )
        .expect("construct exact launched Cleaned receipt");

        for mutation in [
            V27RestartReceiptSelectorMutation::ObservedState,
            V27RestartReceiptSelectorMutation::ResolutionAction,
            V27RestartReceiptSelectorMutation::AcquiredAnchor,
            V27RestartReceiptSelectorMutation::LaunchSchema,
            V27RestartReceiptSelectorMutation::LaunchBytes,
            V27RestartReceiptSelectorMutation::LaunchDigest,
            V27RestartReceiptSelectorMutation::LaunchHead,
            V27RestartReceiptSelectorMutation::CleanedDigest,
        ] {
            assert!(
                v27_insert_raw_restart_receipt(
                    &fixture.ledger.connection,
                    &receipt,
                    Some(mutation),
                )
                .is_err(),
                "raw SQL must reject each selector substituted against canonical receipt_json"
            );
        }
        assert_eq!(
            row_count(
                &fixture.ledger,
                "command_output_capture_restart_recovery_receipts"
            ),
            0
        );
        v27_insert_raw_restart_receipt(&fixture.ledger.connection, &receipt, None)
            .expect("raw SQL accepts one selector-exact canonical receipt");

        for validation_kind in [
            "RestartIntentAbandoned",
            "RestartClaimedBeforeLaunchAbandoned",
            "RestartTerminalPreparedPublished",
        ] {
            let error = fixture
                .ledger
                .connection
                .execute(
                    "INSERT INTO command_output_capture_terminal_validations (
                        terminal_anchor_digest, capture_id, effect_id, observation_id,
                        validation_kind, command_domain_cleanup_proof_id,
                        reconciliation_claim_id, reconciliation_fencing_token,
                        runner_cleanup_receipt_id, restart_recovery_receipt_digest,
                        terminal_anchored_at_unix_ms, sprint_id, contract_version
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9,
                               ?10, ?11, ?12)",
                    params![
                        Digest::sha256(format!("terminal:{validation_kind}").as_bytes()).as_str(),
                        capture_intent.capture_id,
                        capture_intent.source.effect_id,
                        format!("observation-{validation_kind}"),
                        validation_kind,
                        format!("cleanup-{validation_kind}"),
                        claim.claim_id,
                        claim.fencing_token.as_str(),
                        receipt.reconciliation_digest.as_str(),
                        sqlite_integer(
                            "test crossed validation terminal time",
                            receipt.reconciled_at_unix_ms,
                        )
                        .expect("crossed validation terminal time fits SQLite"),
                        capture_intent.source.sprint_id,
                        i64::from(capture_intent.contract_version),
                    ],
                )
                .expect_err("launched Cleaned receipt cannot cross validation families");
            assert!(error.to_string().contains(
                "capture terminal validation must bind exact live or recovery authority"
            ));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One end-to-end proof keeps move-only custody and both fencing branches visible.
    fn v27_direct_terminal_requires_released_reconciliation_claim_and_commits_exactly() {
        let mut fixture = prepare_fresh_command_dispatch_input("v27-direct-terminal");
        let source = CommandOutputArtifactSourceV1 {
            sprint_id: fixture.intent.sprint_id.clone(),
            runner_launch_id: fixture.launch.launch_id.clone(),
            runner_session_id: fixture.session.session_id.clone(),
            effect_id: fixture.intent.effect_id.clone(),
            request_digest: fixture.intent.request_digest.clone(),
        };
        let capture_intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(b"v27-direct-terminal-capture").as_str(),
            source.clone(),
            fixture.launch.private_state_digest.clone(),
            MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES,
            fixture.intent.created_at_unix_ms,
        )
        .expect("construct exact v27 capture intent");
        let permit = match fixture
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
                &capture_intent,
            )
            .expect("atomically admit v27 capture intent")
        {
            CommandOutputCaptureIntentAdmission::Fresh {
                effect,
                capture,
                permit,
            } => {
                assert_eq!(effect.intent, fixture.intent);
                assert_eq!(capture.intent, capture_intent);
                permit
            }
            other => panic!("fresh v27 admission returned {other:?}"),
        };
        let dispatch_claim_id = permit
            .expected_output_capture_dispatch_claim_id()
            .expect("fresh command exposes deterministic capture claim");
        let acquired = CommandOutputCaptureAcquiredV1::try_new(
            &capture_intent,
            dispatch_claim_id,
            CommandOutputCaptureStoreHeadV1 {
                generation: 1,
                record_digest: Digest::sha256(b"v27-acquired-record"),
            },
            CommandOutputCaptureDirectoryIdentityV1 {
                device_id: 7,
                inode: 70,
                owner_uid: 501,
                mode: 0o700,
                link_count: 2,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 7,
                inode: 71,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 7,
                inode: 72,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            1_210,
        )
        .expect("construct exact acquired anchor");
        let (_, transport) = fixture
            .ledger
            .claim_command_output_capture_dispatch(
                permit,
                acquired.clone(),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("atomically acquire capture and claim dispatch");
        let observation_authority = transport
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate exact runner transport");

        let (reconciliation_claim, reconciliation_permit) = match fixture
            .ledger
            .claim_command_output_capture_reconciliation(
                &capture_intent.capture_id,
                Digest::sha256(b"v27-short-reconciliation-claim").as_str(),
                "desktop-live-terminal-fence",
                1_220,
                1_400,
            )
            .expect("acquire short reconciliation fence")
        {
            CommandOutputCaptureReconciliationAdmission::Fresh { claim, permit } => (claim, permit),
            other => panic!("fresh reconciliation claim returned {other:?}"),
        };

        let observation = effect_observation(
            &fixture.intent,
            "v27-direct-terminal-observation",
            EffectOutcome::FailedAfterKnownEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_240,
        );
        let event = effect_terminal_event(
            &fixture.intent,
            &fixture.proposal.event_id,
            &observation,
            fixture
                .ledger
                .next_sequence(&fixture.intent.sprint_id)
                .expect("direct terminal sequence"),
            "v27-direct-terminal-event",
        );
        let stdout = b"captured-known-output";
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
        .expect("construct exact published stream reference");
        let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture_intent,
            Some(&acquired),
            &observation,
            CommandOutputCaptureTerminalDispositionV1::Published,
            CommandOutputCaptureStoreHeadV1 {
                generation: acquired.store_head.generation + 5,
                record_digest: Digest::sha256(b"v27-published-record"),
            },
            Digest::sha256(b"v27-terminal-record"),
            Some(artifacts),
            1_260,
        )
        .expect("construct exact published terminal anchor");
        let clean_scan = v29_test_clean_scan_receipt_for_backend(
            &capture_intent,
            &acquired,
            &terminal,
            CommandTerminationV1::Exited { code: 1 },
            CommandDomainBackend::MacOsDedicatedIdentity,
            "v27-direct-terminal",
        );
        let platform_proof_bytes = b"validated-v27-direct-terminal-cleanup".to_vec();
        let cleanup = CommandDomainCleanupProof {
            contract_version: CONTRACT_VERSION,
            proof_id: "v27-direct-terminal-cleanup-proof".into(),
            sprint_id: fixture.intent.sprint_id.clone(),
            launch_id: fixture.launch.launch_id.clone(),
            session_id: fixture.session.session_id.clone(),
            effect_id: fixture.intent.effect_id.clone(),
            observation_id: Some(observation.observation_id.clone()),
            request_digest: fixture.intent.request_digest.clone(),
            backend: CommandDomainBackend::MacOsDedicatedIdentity,
            disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            surviving_processes: 0,
            platform_proof_digest: Digest::sha256(&platform_proof_bytes),
            platform_proof_bytes,
            cleaned_at_unix_ms: 1_250,
        };

        let crossed_release = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start rollback-only crossed consumed-terminal release");
        crossed_release
            .execute_batch(
                "DROP TRIGGER command_output_capture_reconciliation_releases_exact_claim;",
            )
            .expect("bypass release insert guard inside rollback-only corruption test");
        v27_insert_raw_consumed_reconciliation_release(
            &crossed_release,
            &reconciliation_claim,
            &terminal.terminal_anchor_digest,
            terminal.anchored_at_unix_ms,
        )
        .expect("inject an unbound consumed-terminal release");
        let load_error = command_output_capture_authority::load_from_id(
            &crossed_release,
            &capture_intent.capture_id,
        )
        .expect_err("typed capture load must reject an unbound consumed-terminal release");
        assert!(matches!(load_error, LedgerError::Corrupt { .. }));
        let direct_error = command_output_capture_authority::insert_direct_terminal_validation(
            &crossed_release,
            &terminal,
            &cleanup.proof_id,
        )
        .expect_err("an unbound consumed-terminal release cannot unlock direct terminalization");
        assert!(matches!(direct_error, LedgerError::Corrupt { .. }));
        drop(crossed_release);

        let failed = fixture
            .ledger
            .record_claimed_command_effect_observation_with_output_capture(
                observation_authority,
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &event,
                &terminal,
                Some(&clean_scan),
                &cleanup,
            )
            .expect_err("active restart claim must fence direct terminalization");
        let (error, retry_authority) = failed.into_parts();
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch {
                entity: "command output capture direct terminal",
                ..
            }
        ));
        assert_eq!(row_count(&fixture.ledger, "effect_observations"), 0);
        fixture
            .ledger
            .release_command_output_capture_reconciliation(reconciliation_permit, 1_255)
            .expect("release exact short reconciliation fence");

        let persisted = fixture
            .ledger
            .record_claimed_command_effect_observation_with_output_capture(
                retry_authority.expect("definite precommit failure returns original custody"),
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &event,
                &terminal,
                Some(&clean_scan),
                &cleanup,
            )
            .expect("released claim permits exact direct terminal transaction");
        assert_eq!(persisted.observation.as_ref(), Some(&observation));
        let by_effect = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.intent.effect_id)
            .expect("load exact capture by effect identity");
        assert_eq!(by_effect.intent.capture_id, capture_intent.capture_id);
        assert_eq!(by_effect.acquired.as_ref(), Some(&acquired));
        assert_eq!(by_effect.terminal.as_ref(), Some(&terminal));
        assert_eq!(
            by_effect.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        assert!(matches!(
            fixture
                .ledger
                .classify_command_output_capture_recovery(&capture_intent.capture_id)
                .expect("classify exact closed direct terminal"),
            CommandOutputCaptureRecovery::Terminal(_)
        ));

        let capture_id = capture_intent.capture_id.clone();
        let effect_id = fixture.intent.effect_id.clone();
        let sprint_id = fixture.intent.sprint_id.clone();
        let completion_event_id = event.event_id.clone();
        let terminal_at_unix_ms = event.occurred_at_unix_ms;
        let assert_corruption = |ledger: &mut EventLedger,
                                 drop_sql: &str,
                                 mutation_sql: &str,
                                 expected_source_rows: i64,
                                 expected_dispatch_rows: i64| {
            assert_v27_source_dispatch_corruption_blocks_completion(
                ledger,
                &capture_id,
                &effect_id,
                &sprint_id,
                &completion_event_id,
                terminal_at_unix_ms,
                drop_sql,
                |transaction| {
                    transaction
                        .execute(mutation_sql, [&effect_id])
                        .expect("apply rollback-only v27 source/dispatch corruption");
                },
                expected_source_rows,
                expected_dispatch_rows,
            );
        };
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER effect_intents_no_update;",
            "UPDATE effect_intents
             SET intent_json = CAST(CAST(intent_json AS TEXT) || ' ' AS BLOB)
             WHERE effect_id = ?1",
            0,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER runner_launch_intents_no_update;",
            "UPDATE runner_launch_intents
             SET intent_json = CAST(CAST(intent_json AS TEXT) || ' ' AS BLOB)
             WHERE launch_id = (
                 SELECT launch_id FROM effect_session_bindings WHERE effect_id = ?1
             )",
            0,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER runner_launch_intents_no_update;",
            "UPDATE runner_launch_intents
             SET execution_policy_json =
                 CAST(CAST(execution_policy_json AS TEXT) || ' ' AS BLOB)
             WHERE launch_id = (
                 SELECT launch_id FROM effect_session_bindings WHERE effect_id = ?1
             )",
            0,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER runner_session_policies_no_update;",
            "UPDATE runner_session_policies
             SET record_json = CAST(CAST(record_json AS TEXT) || ' ' AS BLOB)
             WHERE session_id = (
                 SELECT session_id FROM effect_session_bindings WHERE effect_id = ?1
             )",
            0,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER runner_session_policies_no_update;",
            "UPDATE runner_session_policies
             SET execution_policy_json =
                 CAST(CAST(execution_policy_json AS TEXT) || ' ' AS BLOB)
             WHERE session_id = (
                 SELECT session_id FROM effect_session_bindings WHERE effect_id = ?1
             )",
            0,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER runner_launch_intents_no_update;",
            "UPDATE runner_launch_intents
             SET policy_hash =
                 '0000000000000000000000000000000000000000000000000000000000000000'
             WHERE launch_id = (
                 SELECT launch_id FROM effect_session_bindings WHERE effect_id = ?1
             )",
            0,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER runner_session_policies_no_update;",
            "UPDATE runner_session_policies
             SET private_state_digest =
                 '0000000000000000000000000000000000000000000000000000000000000000'
             WHERE session_id = (
                 SELECT session_id FROM effect_session_bindings WHERE effect_id = ?1
             )",
            0,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER task_attempt_running_boundaries_no_update;",
            "UPDATE task_attempt_running_boundaries
             SET boundary_json = CAST(CAST(boundary_json AS TEXT) || ' ' AS BLOB)
             WHERE runner_launch_id = (
                 SELECT launch_id FROM effect_session_bindings WHERE effect_id = ?1
             )",
            0,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER runner_effect_dispatch_claims_no_update;",
            "UPDATE runner_effect_dispatch_claims
             SET policy_hash =
                 '0000000000000000000000000000000000000000000000000000000000000000'
             WHERE effect_id = ?1",
            1,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER runner_effect_dispatch_claims_no_update;",
            "UPDATE runner_effect_dispatch_claims
             SET input_snapshot =
                 '0000000000000000000000000000000000000000000000000000000000000000'
             WHERE effect_id = ?1",
            1,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "DROP TRIGGER runner_effect_dispatch_claims_no_update;",
            "UPDATE runner_effect_dispatch_claims
             SET running_boundary_id = NULL WHERE effect_id = ?1",
            1,
            0,
        );
        assert_v27_source_dispatch_corruption_blocks_completion(
            &mut fixture.ledger,
            &capture_id,
            &effect_id,
            &sprint_id,
            &completion_event_id,
            terminal_at_unix_ms,
            "DROP TRIGGER runner_effect_dispatch_claim_authorities_no_delete;",
            |transaction| {
                transaction
                    .execute(
                        "DELETE FROM runner_effect_dispatch_claim_authorities
                         WHERE dispatch_claim_id = (
                             SELECT dispatch_claim_id
                             FROM runner_effect_dispatch_claims WHERE effect_id = ?1
                         )",
                        [&effect_id],
                    )
                    .expect("remove exact dispatch companion");
            },
            1,
            0,
        );
        assert_corruption(
            &mut fixture.ledger,
            "PRAGMA ignore_check_constraints = ON;
             DROP TRIGGER runner_effect_dispatch_claim_authorities_no_update;",
            "UPDATE runner_effect_dispatch_claim_authorities
             SET running_boundary_id = NULL
             WHERE dispatch_claim_id = (
                 SELECT dispatch_claim_id
                 FROM runner_effect_dispatch_claims WHERE effect_id = ?1
             )",
            1,
            0,
        );

        let swapped_validation_completion = fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start raw validation-kind completion attempt");
        isolate_v27_completion_fence(&swapped_validation_completion);
        swapped_validation_completion
            .execute_batch("DROP TRIGGER command_output_capture_terminal_validations_no_update;")
            .expect("allow rollback-only validation-kind substitution");
        swapped_validation_completion
            .execute(
                "UPDATE command_output_capture_terminal_validations
                 SET validation_kind = 'DirectClaimedUnresolved',
                     command_domain_cleanup_proof_id = NULL
                 WHERE terminal_anchor_digest = ?1",
                [terminal.terminal_anchor_digest.as_str()],
            )
            .expect("make a CHECK-valid but semantically crossed validation row");
        let swapped_completion_error = swapped_validation_completion
            .execute(
                "INSERT INTO sprint_completion_proof_states (
                    sprint_id, proof_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'ProvenV9', ?2, ?3, ?4, ?5)",
                params![
                    fixture.intent.sprint_id,
                    "v27-raw-swapped-validation-completion-receipt",
                    event.event_id,
                    i64::from(CONTRACT_VERSION),
                    sqlite_integer(
                        "test raw swapped validation completion time",
                        event.occurred_at_unix_ms,
                    )
                    .expect("swapped validation completion time fits SQLite"),
                ],
            )
            .expect_err("CHECK-valid validation-kind swaps cannot admit raw completion");
        assert!(
            swapped_completion_error
                .to_string()
                .contains("completion requires every capture obligation and claim closed"),
            "unexpected swapped-validation completion rejection: {swapped_completion_error}"
        );
        drop(swapped_validation_completion);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One closed FinalVerifier fixture drives each finite rollback-only authority corruption.
    fn v27_final_verification_source_and_dispatch_views_reject_crossed_authority() {
        let (mut candidate, fixture) =
            prepare_current_unadmitted_final_verifier_fixture(true, digest('b'));
        let ledger = &mut candidate.ledger;
        let permit = admit_test_final_verification(ledger, &fixture);
        let (authority, acquired) = claim_test_final_verification(ledger, &fixture, permit);
        let (observation, event, evidence) = v21_final_verification_terminal(ledger, &fixture);
        complete_test_final_verification(
            ledger,
            &fixture,
            authority,
            acquired.as_ref(),
            &observation,
            &event,
            &evidence,
        );

        let capture_id = fixture.capture_intent.capture_id.clone();
        let effect_id = fixture.intent.effect_id.clone();
        let sprint_id = fixture.intent.sprint_id.clone();
        let completion_event_id = event.event_id.clone();
        let terminal_at_unix_ms = event.occurred_at_unix_ms;
        let assert_corruption = |ledger: &mut EventLedger,
                                 drop_sql: &str,
                                 mutation_sql: &str,
                                 expected_source_rows: i64,
                                 expected_dispatch_rows: i64| {
            assert_v27_source_dispatch_corruption_blocks_completion(
                ledger,
                &capture_id,
                &effect_id,
                &sprint_id,
                &completion_event_id,
                terminal_at_unix_ms,
                drop_sql,
                |transaction| {
                    transaction
                        .execute(mutation_sql, [&effect_id])
                        .expect("apply rollback-only final-verification corruption");
                },
                expected_source_rows,
                expected_dispatch_rows,
            );
        };
        assert_corruption(
            ledger,
            "DROP TRIGGER sprint_final_verification_admissions_no_update;",
            "UPDATE sprint_final_verification_admissions
             SET admission_json = CAST(CAST(admission_json AS TEXT) || ' ' AS BLOB)
             WHERE effect_id = ?1",
            0,
            0,
        );
        assert_corruption(
            ledger,
            "DROP TRIGGER sprint_final_verification_admissions_no_update;",
            "UPDATE sprint_final_verification_admissions
             SET command_bytes = CAST(CAST(command_bytes AS TEXT) || ' ' AS BLOB)
             WHERE effect_id = ?1",
            0,
            0,
        );
        assert_corruption(
            ledger,
            "DROP TRIGGER sprint_final_verification_admissions_no_update;",
            "UPDATE sprint_final_verification_admissions
             SET command_digest =
                 '0000000000000000000000000000000000000000000000000000000000000000'
             WHERE effect_id = ?1",
            0,
            0,
        );
        assert_corruption(
            ledger,
            "DROP TRIGGER sprint_final_verification_admissions_no_update;",
            "UPDATE sprint_final_verification_admissions
             SET runner_session_id = (
                 SELECT session_id FROM runner_session_policies
                 WHERE sprint_id = sprint_final_verification_admissions.sprint_id
                   AND session_id != sprint_final_verification_admissions.runner_session_id
                 ORDER BY session_id LIMIT 1
             )
             WHERE effect_id = ?1",
            0,
            0,
        );
        assert_corruption(
            ledger,
            "PRAGMA defer_foreign_keys = ON;
             DROP TRIGGER sprint_final_verification_admissions_no_update;",
            "UPDATE sprint_final_verification_admissions
             SET final_snapshot =
                 '0000000000000000000000000000000000000000000000000000000000000000'
             WHERE effect_id = ?1",
            0,
            0,
        );
        assert_corruption(
            ledger,
            "DROP TRIGGER agent_events_no_update;",
            "UPDATE agent_events
             SET event_json = CAST(CAST(event_json AS TEXT) || ' ' AS BLOB)
             WHERE event_id = (
                 SELECT sprint_phase_event_id
                 FROM sprint_final_verification_admissions WHERE effect_id = ?1
             )",
            0,
            0,
        );
        assert_corruption(
            ledger,
            "DROP TRIGGER runner_effect_dispatch_claim_authorities_no_update;",
            "UPDATE runner_effect_dispatch_claim_authorities
             SET sprint_phase_event_id = (
                 SELECT event_id FROM agent_events
                 WHERE sprint_id = (
                     SELECT sprint_id FROM effect_intents WHERE effect_id = ?1
                 )
                   AND event_id != runner_effect_dispatch_claim_authorities.sprint_phase_event_id
                 ORDER BY sequence LIMIT 1
             )
             WHERE dispatch_claim_id = (
                 SELECT dispatch_claim_id FROM runner_effect_dispatch_claims
                 WHERE effect_id = ?1
             )",
            1,
            0,
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Full acquired/claimed/no-domain chain is one focused acceptance proof.
    fn v27_claimed_failed_before_effect_accepts_acquired_abandoned_no_domain_proof() {
        let mut fixture = prepare_fresh_command_dispatch_input("v27-failed-before");
        let capture_intent = v27_test_capture_intent(
            &fixture.intent,
            &fixture.launch,
            &fixture.session,
            "v27-failed-before",
        );
        let permit = match fixture
            .ledger
            .admit_runner_command_output_capture_intent_for_dispatch(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.proposal,
                &fixture.session.session_id,
                &capture_intent,
            )
            .expect("admit failed-before capture")
        {
            CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => permit,
            other => panic!("fresh failed-before admission returned {other:?}"),
        };
        let acquired = v27_test_capture_acquired(
            &capture_intent,
            permit
                .expected_output_capture_dispatch_claim_id()
                .expect("failed-before dispatch claim identity"),
            "v27-failed-before",
            1_210,
        );
        let (_, transport) = fixture
            .ledger
            .claim_command_output_capture_dispatch(
                permit,
                acquired.clone(),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("claim failed-before command dispatch");
        let authority = transport
            .validate_transport_request(
                &fixture.intent,
                EFFECT_REQUEST_BYTES,
                &fixture.launch,
                &fixture.session,
                Some(&fixture.running),
                OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
            )
            .expect("validate failed-before transport");
        let observation = effect_observation(
            &fixture.intent,
            "v27-failed-before-observation",
            EffectOutcome::FailedBeforeEffect {
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
                .expect("failed-before terminal sequence"),
            "v27-failed-before-event",
        );
        let terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
            &capture_intent,
            Some(&acquired),
            &observation,
            CommandOutputCaptureTerminalDispositionV1::Abandoned,
            CommandOutputCaptureStoreHeadV1 {
                generation: 2,
                record_digest: Digest::sha256(b"v27-failed-before-cleaned-head"),
            },
            Digest::sha256(b"v27-failed-before-cleanup-record"),
            None,
            1_240,
        )
        .expect("construct acquired Abandoned terminal");
        let mut cleanup = v27_test_command_cleanup(
            &fixture.intent,
            &observation,
            &fixture.launch,
            &fixture.session,
            "v27-failed-before",
            1_230,
        );
        cleanup.disposition = CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect;
        let persisted = fixture
            .ledger
            .record_claimed_command_effect_observation_with_output_capture(
                authority,
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &event,
                &terminal,
                None,
                &cleanup,
            )
            .expect("commit acquired FailedBeforeEffect abandonment");
        assert_eq!(persisted.observation.as_ref(), Some(&observation));
        let capture = fixture
            .ledger
            .load_command_output_capture_for_effect(&fixture.intent.effect_id)
            .expect("load acquired failed-before capture");
        assert_eq!(capture.acquired.as_ref(), Some(&acquired));
        assert_eq!(capture.terminal.as_ref(), Some(&terminal));
        assert_eq!(
            capture.reconciliation_obligation_closure.as_ref(),
            Some(&terminal.terminal_anchor_digest)
        );
        assert_eq!(
            fixture
                .ledger
                .load_command_domain_cleanup_proof(&fixture.intent.effect_id)
                .expect("load no-domain proof")
                .proof
                .disposition,
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
        );
    }

