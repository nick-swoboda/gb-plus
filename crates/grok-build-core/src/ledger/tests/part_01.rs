    #[test]
    fn opaque_runner_authorities_stay_within_five_kib_layout_budget() {
        // Existing task-attempt admissions are intentionally retained inline;
        // five KiB catches re-inlining the application admission (5,272 B)
        // while leaving a narrow ceiling above the boxed 4,864 B layout.
        const MAX_OPAQUE_AUTHORITY_BYTES: usize = 5 * 1_024;
        let transport_size = std::mem::size_of::<RunnerEffectTransportPermit>();
        let observation_size = std::mem::size_of::<RunnerEffectObservationAuthority>();
        assert!(
            transport_size <= MAX_OPAQUE_AUTHORITY_BYTES,
            "transport permit grew to {transport_size} bytes"
        );
        assert!(
            observation_size <= MAX_OPAQUE_AUTHORITY_BYTES,
            "observation authority grew to {observation_size} bytes"
        );
    }

    #[test]
    fn ledger_connections_enable_recursive_triggers_and_reject_replace_deletes() {
        let database = TestDatabase::new();
        let ledger = EventLedger::open(&database.path).expect("open guarded ledger");
        let recursive_triggers: i64 = ledger
            .connection
            .pragma_query_value(None, "recursive_triggers", |row| row.get(0))
            .expect("read writable recursive-trigger setting");
        assert_eq!(recursive_triggers, 1);

        ledger
            .connection
            .execute(
                "INSERT INTO sprints (
                    sprint_id, contract_version, spec_json, graph_json,
                    created_at_unix_ms
                 ) VALUES (?1, 1, ?2, ?3, 1)",
                params!["replace-guard-sprint", b"{}".as_slice(), b"".as_slice()],
            )
            .expect("insert immutable test row");
        let replacement = ledger.connection.execute(
            "INSERT OR REPLACE INTO sprints (
                sprint_id, contract_version, spec_json, graph_json,
                created_at_unix_ms
             ) VALUES (?1, 1, ?2, ?3, 2)",
            params!["replace-guard-sprint", b"{}".as_slice(), b"".as_slice()],
        );
        assert!(
            matches!(replacement, Err(rusqlite::Error::SqliteFailure(_, Some(ref message)))
                if message.contains("persisted sprints cannot be deleted")),
            "INSERT OR REPLACE must not bypass immutable-row delete guards: {replacement:?}"
        );
        let created_at: i64 = ledger
            .connection
            .query_row(
                "SELECT created_at_unix_ms FROM sprints WHERE sprint_id = ?1",
                ["replace-guard-sprint"],
                |row| row.get(0),
            )
            .expect("read unchanged immutable row");
        assert_eq!(created_at, 1);
        drop(ledger);

        let reader = EventLedger::open_read_only(&database.path).expect("open guarded reader");
        let reader_recursive_triggers: i64 = reader
            .connection
            .pragma_query_value(None, "recursive_triggers", |row| row.get(0))
            .expect("read recovery recursive-trigger setting");
        assert_eq!(reader_recursive_triggers, 1);
    }

    const EFFECT_REQUEST_BYTES: &[u8] = br#"{"program":"cargo","arguments":["test","--locked"]}"#;
    const OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES: &[u8] =
        br#"{"type":"runner_request","effect":"exact"}"#;
    const EFFECT_EVIDENCE_BYTES: &[u8] =
        br#"{"termination":{"exit":0},"stdout_digest":"verified"}"#;

    fn effect_evidence_digest() -> Digest {
        Digest::sha256(EFFECT_EVIDENCE_BYTES)
    }

    fn v27_test_capture_intent(
        intent: &EffectIntent,
        launch: &RunnerLaunchIntent,
        session: &RunnerSessionPolicyRecord,
        label: &str,
    ) -> CommandOutputCaptureIntentV1 {
        CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(format!("capture:{label}").as_bytes()).as_str(),
            CommandOutputArtifactSourceV1 {
                sprint_id: intent.sprint_id.clone(),
                runner_launch_id: launch.launch_id.clone(),
                runner_session_id: session.session_id.clone(),
                effect_id: intent.effect_id.clone(),
                request_digest: intent.request_digest.clone(),
            },
            launch.private_state_digest.clone(),
            MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES,
            intent.created_at_unix_ms,
        )
        .expect("construct exact v27 test capture intent")
    }

    fn v27_test_capture_acquired(
        intent: &CommandOutputCaptureIntentV1,
        dispatch_claim_id: String,
        label: &str,
        acquired_at_unix_ms: u64,
    ) -> CommandOutputCaptureAcquiredV1 {
        v27_test_capture_acquired_at_generation(
            intent,
            dispatch_claim_id,
            label,
            1,
            acquired_at_unix_ms,
        )
    }

    fn v27_test_capture_acquired_at_generation(
        intent: &CommandOutputCaptureIntentV1,
        dispatch_claim_id: String,
        label: &str,
        generation: u64,
        acquired_at_unix_ms: u64,
    ) -> CommandOutputCaptureAcquiredV1 {
        let digest = Digest::sha256(format!("capture-inodes:{label}").as_bytes());
        let inode_seed = u64::from_str_radix(&digest.as_str()[..12], 16)
            .expect("test capture inode seed is hexadecimal")
            .max(10);
        CommandOutputCaptureAcquiredV1::try_new(
            intent,
            dispatch_claim_id,
            CommandOutputCaptureStoreHeadV1 {
                generation,
                record_digest: Digest::sha256(format!("acquired:{label}").as_bytes()),
            },
            CommandOutputCaptureDirectoryIdentityV1 {
                device_id: 1,
                inode: inode_seed,
                owner_uid: 501,
                mode: 0o700,
                link_count: 2,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 1,
                inode: inode_seed + 1,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 1,
                inode: inode_seed + 2,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            acquired_at_unix_ms,
        )
        .expect("construct exact v27 test capture acquisition")
    }

    fn v27_test_published_capture_terminal(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        observation: &EffectObservation,
        artifacts: CommandOutputArtifactSetReferenceV1,
        label: &str,
        anchored_at_unix_ms: u64,
    ) -> CommandOutputCaptureTerminalAnchorV1 {
        CommandOutputCaptureTerminalAnchorV1::try_new(
            intent,
            Some(acquired),
            observation,
            CommandOutputCaptureTerminalDispositionV1::Published,
            CommandOutputCaptureStoreHeadV1 {
                generation: acquired.store_head.generation + 5,
                record_digest: Digest::sha256(format!("published:{label}").as_bytes()),
            },
            Digest::sha256(format!("terminal-record:{label}").as_bytes()),
            Some(artifacts),
            anchored_at_unix_ms,
        )
        .expect("construct exact v27 published test terminal")
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the fixture mirrors every independently crossed clean-runner boundary without introducing a second test-only aggregate"
    )]
    fn v29_test_clean_runner_reference(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        terminal_store_head: &CommandOutputCaptureStoreHeadV1,
        terminal_record_digest: &Digest,
        termination: CommandTerminationV1,
        backend: CommandDomainBackend,
        label: &str,
        terminal_prepared_at_unix_ms: u64,
    ) -> SensitiveOutputCleanRunnerReferenceV1 {
        assert!(
            terminal_store_head.generation >= acquired.store_head.generation + 5,
            "clean runner test fixture needs five store transitions after acquisition"
        );
        assert!(terminal_prepared_at_unix_ms >= acquired.acquired_at_unix_ms + 4);
        let store_head = |generation, state: &str| CommandOutputCaptureStoreHeadV1 {
            generation,
            record_digest: Digest::sha256(
                format!("clean-store:{label}:{state}:{generation}").as_bytes(),
            ),
        };
        let journal_head = |generation, state: &str| SensitiveOutputJournalHeadV1 {
            generation,
            record_digest: Digest::sha256(
                format!("clean-journal:{label}:{state}:{generation}").as_bytes(),
            ),
        };
        let mut reference = SensitiveOutputCleanRunnerReferenceV1 {
            journal_id: format!("clean-journal-{label}"),
            capture_id: intent.capture_id.clone(),
            runner_session_id: intent.source.runner_session_id.clone(),
            effect_id: intent.source.effect_id.clone(),
            request_digest: intent.source.request_digest.clone(),
            intent_digest: intent.intent_digest.clone(),
            acquired: acquired.clone(),
            acquired_anchor_digest: acquired.acquired_anchor_digest.clone(),
            acquired_store_head: acquired.store_head.clone(),
            writer_attached_store_head: store_head(
                acquired.store_head.generation + 1,
                "writer-attached",
            ),
            launch_intended_store_head: store_head(
                acquired.store_head.generation + 2,
                "launch-intended",
            ),
            launch_intended_journal_head: journal_head(4, "launch-intended"),
            core_dump_suppression: match backend {
                CommandDomainBackend::LinuxCgroupV2 => {
                    SensitiveOutputCoreDumpSuppressionV1::linux()
                }
                CommandDomainBackend::MacOsDedicatedIdentity => {
                    SensitiveOutputCoreDumpSuppressionV1::macos()
                }
            },
            detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            intent_bound_journal_head: journal_head(1, "intent-bound"),
            acquired_bound_journal_head: journal_head(2, "acquired-bound"),
            writer_attached_journal_head: journal_head(3, "writer-attached"),
            scanned_clean_journal_head: journal_head(5, "scanned-clean"),
            finished_journal_head: journal_head(6, "finished"),
            published_journal_head: journal_head(7, "published"),
            terminal_prepared_journal_head: journal_head(8, "terminal-prepared"),
            finished_store_head: store_head(acquired.store_head.generation + 3, "finished"),
            published_store_head: store_head(acquired.store_head.generation + 4, "published"),
            terminal_prepared_store_head: terminal_store_head.clone(),
            terminal_record_digest: terminal_record_digest.clone(),
            termination,
            scanned_clean_at_unix_ms: acquired.acquired_at_unix_ms + 1,
            finished_at_unix_ms: acquired.acquired_at_unix_ms + 2,
            published_at_unix_ms: acquired.acquired_at_unix_ms + 3,
            terminal_prepared_at_unix_ms,
        };
        reference
            .canonicalize_journal_heads_for_test()
            .expect("compute exact v29 clean runner journal chain");
        reference
            .validate()
            .expect("construct exact v29 clean runner test reference");
        reference
    }

    fn v29_test_clean_scan_receipt(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        termination: CommandTerminationV1,
        label: &str,
    ) -> CommandOutputCleanScanPublicationReceiptV1 {
        v29_test_clean_scan_receipt_for_backend(
            intent,
            acquired,
            terminal,
            termination,
            CommandDomainBackend::LinuxCgroupV2,
            label,
        )
    }

    fn v29_test_clean_scan_receipt_for_backend(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        termination: CommandTerminationV1,
        backend: CommandDomainBackend,
        label: &str,
    ) -> CommandOutputCleanScanPublicationReceiptV1 {
        let runner = v29_test_clean_runner_reference(
            intent,
            acquired,
            &terminal.store_head,
            &terminal.terminal_record_digest,
            termination,
            backend,
            label,
            terminal.anchored_at_unix_ms - 1,
        );
        CommandOutputCleanScanPublicationReceiptV1::try_new_from_runner_reference(
            intent, &runner, terminal,
        )
        .expect("construct exact v29 clean-scan publication test receipt")
    }

    fn v27_test_command_cleanup(
        intent: &EffectIntent,
        observation: &EffectObservation,
        launch: &RunnerLaunchIntent,
        session: &RunnerSessionPolicyRecord,
        label: &str,
        cleaned_at_unix_ms: u64,
    ) -> CommandDomainCleanupProof {
        let platform_proof_bytes = format!("validated-v27-command-cleanup:{label}").into_bytes();
        CommandDomainCleanupProof {
            contract_version: CONTRACT_VERSION,
            proof_id: format!("command-cleanup-{label}"),
            sprint_id: intent.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: session.session_id.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: Some(observation.observation_id.clone()),
            request_digest: intent.request_digest.clone(),
            backend: CommandDomainBackend::LinuxCgroupV2,
            disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            surviving_processes: 0,
            platform_proof_digest: Digest::sha256(&platform_proof_bytes),
            platform_proof_bytes,
            cleaned_at_unix_ms,
        }
    }

    fn v27_test_physical_history(
        label: &str,
        states: &[CommandOutputCaptureRestartStateV1],
    ) -> Vec<CommandOutputCapturePhysicalHistoryEntryV1> {
        states
            .iter()
            .enumerate()
            .map(
                |(index, state)| CommandOutputCapturePhysicalHistoryEntryV1 {
                    state: *state,
                    store_head: CommandOutputCaptureStoreHeadV1 {
                        generation: u64::try_from(index + 1)
                            .expect("test physical history generation fits u64"),
                        record_digest: Digest::sha256(
                            format!("physical:{label}:{index}:{state:?}").as_bytes(),
                        ),
                    },
                },
            )
            .collect()
    }

    #[derive(Clone, Copy)]
    enum V27RestartReceiptSelectorMutation {
        ObservedState,
        ResolutionAction,
        AcquiredAnchor,
        LaunchSchema,
        LaunchBytes,
        LaunchDigest,
        LaunchHead,
        CleanedDigest,
    }

    fn v27_insert_raw_reconciliation_claim(
        connection: &Connection,
        claim: &CommandOutputCaptureReconciliationClaimV1,
    ) -> Result<(), LedgerError> {
        connection.execute(
            "INSERT INTO command_output_capture_reconciliation_claims (
                claim_id, capture_id, owner_id, claim_epoch, previous_claim_id,
                fencing_token, acquired_at_unix_ms, expires_at_unix_ms,
                claim_digest, contract_version, claim_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                claim.claim_id,
                claim.capture_id,
                claim.owner_id,
                sqlite_integer("test reconciliation claim epoch", claim.claim_epoch)?,
                claim.previous_claim_id,
                claim.fencing_token.as_str(),
                sqlite_integer(
                    "test reconciliation claim acquisition",
                    claim.acquired_at_unix_ms,
                )?,
                sqlite_integer("test reconciliation claim expiry", claim.expires_at_unix_ms,)?,
                claim.claim_digest.as_str(),
                i64::from(claim.contract_version),
                encode("test command output reconciliation claim", claim)?,
            ],
        )?;
        Ok(())
    }

    fn v27_insert_raw_reconciliation_release(
        connection: &Connection,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        release_kind: &str,
        released_at_unix_ms: u64,
        successor: Option<&CommandOutputCaptureReconciliationClaimV1>,
    ) -> Result<(), LedgerError> {
        connection.execute(
            "INSERT INTO command_output_capture_reconciliation_claim_releases (
                claim_id, capture_id, claim_epoch, fencing_token, release_kind,
                released_at_unix_ms, terminal_anchor_digest, successor_claim_id,
                successor_fencing_token, successor_claim_digest, contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?10)",
            params![
                claim.claim_id,
                claim.capture_id,
                sqlite_integer("test reconciliation release epoch", claim.claim_epoch)?,
                claim.fencing_token.as_str(),
                release_kind,
                sqlite_integer("test reconciliation release time", released_at_unix_ms)?,
                successor.map(|next| next.claim_id.as_str()),
                successor.map(|next| next.fencing_token.as_str()),
                successor.map(|next| next.claim_digest.as_str()),
                i64::from(claim.contract_version),
            ],
        )?;
        Ok(())
    }

    fn v27_insert_raw_consumed_reconciliation_release(
        connection: &Connection,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        terminal_anchor_digest: &Digest,
        released_at_unix_ms: u64,
    ) -> Result<(), LedgerError> {
        connection.execute(
            "INSERT INTO command_output_capture_reconciliation_claim_releases (
                claim_id, capture_id, claim_epoch, fencing_token, release_kind,
                released_at_unix_ms, terminal_anchor_digest, successor_claim_id,
                successor_fencing_token, successor_claim_digest, contract_version
             ) VALUES (?1, ?2, ?3, ?4, 'ConsumedTerminal', ?5, ?6,
                       NULL, NULL, NULL, ?7)",
            params![
                claim.claim_id,
                claim.capture_id,
                sqlite_integer("test consumed reconciliation epoch", claim.claim_epoch)?,
                claim.fencing_token.as_str(),
                sqlite_integer("test consumed reconciliation time", released_at_unix_ms)?,
                terminal_anchor_digest.as_str(),
                i64::from(claim.contract_version),
            ],
        )?;
        Ok(())
    }

    fn v27_insert_raw_reconciliation_resolution(
        connection: &Connection,
        resolution: &CommandOutputCaptureReconciliationResolutionV1,
        physical_recovery_receipt_digest: &Digest,
        command_domain_cleanup_proof_id: &str,
        runner_cleanup_receipt_id: &str,
    ) -> Result<(), LedgerError> {
        let artifact_manifest_digest = resolution
            .artifact_reference
            .as_ref()
            .map(|reference| reference.manifest_digest.as_str());
        let artifact_reference_json = resolution
            .artifact_reference
            .as_ref()
            .map(|reference| encode("test resolution artifact", reference))
            .transpose()?;
        connection.execute(
            "INSERT INTO command_output_capture_reconciliation_resolutions (
                resolution_anchor_digest, capture_id, effect_id, observation_id,
                terminal_anchor_digest, reconciliation_claim_id,
                reconciliation_fencing_token, disposition, store_head_generation,
                store_head_digest, resolution_record_digest, artifact_manifest_digest,
                artifact_reference_json, command_domain_cleanup_proof_id,
                runner_cleanup_receipt_id, physical_recovery_receipt_digest,
                resolved_at_unix_ms, layout_version, contract_version, resolution_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20
             )",
            params![
                resolution.resolution_anchor_digest.as_str(),
                resolution.capture_id,
                resolution.effect_id,
                resolution.observation_id,
                resolution.terminal_anchor_digest.as_str(),
                resolution.reconciliation_claim_id,
                resolution.reconciliation_fencing_token.as_str(),
                resolution.disposition.storage_name(),
                sqlite_integer(
                    "test resolution generation",
                    resolution.store_head.generation
                )?,
                resolution.store_head.record_digest.as_str(),
                resolution.resolution_record_digest.as_str(),
                artifact_manifest_digest,
                artifact_reference_json,
                command_domain_cleanup_proof_id,
                runner_cleanup_receipt_id,
                physical_recovery_receipt_digest.as_str(),
                sqlite_integer("test resolution time", resolution.resolved_at_unix_ms)?,
                i64::from(resolution.layout_version),
                i64::from(resolution.contract_version),
                encode("test command output capture resolution", resolution)?,
            ],
        )?;
        Ok(())
    }

    fn v27_insert_raw_direct_unresolved_terminal(
        connection: &Connection,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        sprint_id: &str,
    ) -> Result<(), LedgerError> {
        connection.execute(
            "INSERT INTO command_output_capture_terminal_validations (
                terminal_anchor_digest, capture_id, effect_id, observation_id,
                validation_kind, command_domain_cleanup_proof_id,
                reconciliation_claim_id, reconciliation_fencing_token,
                runner_cleanup_receipt_id, restart_recovery_receipt_digest,
                terminal_anchored_at_unix_ms, sprint_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4, 'DirectClaimedUnresolved', NULL, NULL,
                       NULL, NULL, NULL, ?5, ?6, ?7)",
            params![
                terminal.terminal_anchor_digest.as_str(),
                terminal.capture_id,
                terminal.effect_id,
                terminal.observation_id,
                sqlite_integer(
                    "test unresolved terminal validation time",
                    terminal.anchored_at_unix_ms,
                )?,
                sprint_id,
                i64::from(terminal.contract_version),
            ],
        )?;
        connection.execute(
            "INSERT INTO command_output_capture_terminal_anchors (
                capture_id, effect_id, observation_id, dispatch_claim_id,
                intent_digest, acquired_anchor_digest, observation_class,
                disposition, store_head_generation, store_head_digest,
                terminal_record_digest, artifact_manifest_digest,
                artifact_reference_json, anchored_at_unix_ms,
                terminal_anchor_digest, layout_version, contract_version,
                terminal_anchor_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, 'Unknown', 'ReconciliationRequired',
                ?7, ?8, ?9, NULL, NULL, ?10, ?11, ?12, ?13, ?14
             )",
            params![
                terminal.capture_id,
                terminal.effect_id,
                terminal.observation_id,
                terminal.dispatch_claim_id,
                terminal.intent_digest.as_str(),
                terminal.acquired_anchor_digest.as_ref().map(Digest::as_str),
                sqlite_integer(
                    "test unresolved terminal generation",
                    terminal.store_head.generation,
                )?,
                terminal.store_head.record_digest.as_str(),
                terminal.terminal_record_digest.as_str(),
                sqlite_integer(
                    "test unresolved terminal time",
                    terminal.anchored_at_unix_ms,
                )?,
                terminal.terminal_anchor_digest.as_str(),
                i64::from(terminal.layout_version),
                i64::from(terminal.contract_version),
                encode("test direct unresolved terminal", terminal)?,
            ],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn v27_insert_raw_restart_receipt(
        connection: &Connection,
        receipt: &CommandOutputCapturePhysicalReconciliationV1,
        mutation: Option<V27RestartReceiptSelectorMutation>,
    ) -> Result<(), LedgerError> {
        let launch = receipt.launch_history.evidence();
        let wrong_digest = Digest::sha256(b"v27-raw-receipt-selector-substitution");
        let mut observed_state = receipt.final_state.storage_name();
        let mut resolution_action = receipt.resolution_action.storage_name();
        let mut acquired_anchor_digest = receipt
            .physical_acquired
            .as_ref()
            .map(|acquired| acquired.acquired_anchor_digest.as_str());
        let mut launch_schema = launch.map(|evidence| evidence.schema.as_str());
        let mut launch_bytes = launch.map(|evidence| evidence.canonical_bytes.as_slice());
        let mut launch_digest = launch.map(|evidence| evidence.canonical_bytes_digest.as_str());
        let mut launch_generation = launch
            .map(|evidence| {
                sqlite_integer(
                    "test restart receipt launch generation",
                    evidence.store_head.generation,
                )
            })
            .transpose()?;
        let mut launch_head_digest =
            launch.map(|evidence| evidence.store_head.record_digest.as_str());
        let mut cleaned_record_digest = receipt
            .cleaned_store_head
            .as_ref()
            .map(|head| head.record_digest.as_str());
        match mutation {
            None => {}
            Some(V27RestartReceiptSelectorMutation::ObservedState) => {
                observed_state = "Published";
            }
            Some(V27RestartReceiptSelectorMutation::ResolutionAction) => {
                resolution_action = "TerminalReadback";
            }
            Some(V27RestartReceiptSelectorMutation::AcquiredAnchor) => {
                acquired_anchor_digest = Some(wrong_digest.as_str());
            }
            Some(V27RestartReceiptSelectorMutation::LaunchSchema) => {
                launch_schema = Some("substituted-launch/v1");
            }
            Some(V27RestartReceiptSelectorMutation::LaunchBytes) => {
                launch_bytes = Some(b"substituted launch bytes");
            }
            Some(V27RestartReceiptSelectorMutation::LaunchDigest) => {
                launch_digest = Some(wrong_digest.as_str());
            }
            Some(V27RestartReceiptSelectorMutation::LaunchHead) => {
                launch_generation =
                    launch_generation.and_then(|generation| generation.checked_add(1));
                launch_head_digest = Some(wrong_digest.as_str());
            }
            Some(V27RestartReceiptSelectorMutation::CleanedDigest) => {
                cleaned_record_digest = Some(wrong_digest.as_str());
            }
        }
        connection.execute(
            "INSERT INTO command_output_capture_restart_recovery_receipts (
                receipt_digest, capture_id, effect_id, intent_digest,
                reconciliation_claim_id, reconciliation_fencing_token,
                recovery_fence_claim_digest, physical_fence_chain_length,
                physical_fence_digest, observed_state, resolution_action,
                store_head_generation, store_head_digest, journal_history_digest,
                acquired_anchor_digest, launch_schema, launch_canonical_bytes,
                launch_canonical_bytes_digest, launch_store_head_generation,
                launch_store_head_digest, cleaned_record_digest,
                pending_record_present, recovered_at_unix_ms, layout_version,
                contract_version, receipt_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25,
                ?26
             )",
            params![
                receipt.reconciliation_digest.as_str(),
                receipt.capture_id,
                receipt.effect_id,
                receipt.intent_digest.as_str(),
                receipt.reconciliation_claim.claim_id,
                receipt.reconciliation_claim.fencing_token.as_str(),
                receipt.reconciliation_claim.claim_digest.as_str(),
                sqlite_integer(
                    "test restart receipt fence chain length",
                    receipt.physical_fence_chain_length,
                )?,
                receipt.physical_fence_digest.as_str(),
                observed_state,
                resolution_action,
                sqlite_integer(
                    "test restart receipt final generation",
                    receipt.final_store_head.generation,
                )?,
                receipt.final_store_head.record_digest.as_str(),
                receipt.lifecycle_history_digest.as_str(),
                acquired_anchor_digest,
                launch_schema,
                launch_bytes,
                launch_digest,
                launch_generation,
                launch_head_digest,
                cleaned_record_digest,
                false,
                sqlite_integer(
                    "test restart receipt recovered time",
                    receipt.reconciled_at_unix_ms,
                )?,
                i64::from(receipt.layout_version),
                i64::from(receipt.contract_version),
                encode("test command output capture restart receipt", receipt)?,
            ],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn v27_test_physical_reconciliation(
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        label: &str,
        states: &[CommandOutputCaptureRestartStateV1],
        requested_store_head: Option<CommandOutputCaptureStoreHeadV1>,
        initial_state: Option<CommandOutputCaptureRestartStateV1>,
        pending_resolution: CommandOutputCapturePendingResolutionV1,
        resolution_action: CommandOutputCapturePhysicalResolutionActionV1,
        physical_acquired: Option<CommandOutputCaptureAcquiredV1>,
        launch_history: CommandOutputCaptureLaunchHistoryV1,
        artifact_reference: Option<CommandOutputArtifactSetReferenceV1>,
        terminal_prepared: Option<CommandOutputCapturePhysicalTerminalEvidenceV1>,
        reconciled_at_unix_ms: u64,
    ) -> Result<CommandOutputCapturePhysicalReconciliationV1, ContractError> {
        let mut lifecycle_history = v27_test_physical_history(label, states);
        if let Some(acquired) = physical_acquired.as_ref()
            && let Some(entry) = lifecycle_history
                .iter_mut()
                .find(|entry| entry.state == CommandOutputCaptureRestartStateV1::Acquired)
        {
            entry.store_head = acquired.store_head.clone();
        }
        if let Some(launch) = launch_history.evidence()
            && let Some(entry) = lifecycle_history
                .iter_mut()
                .find(|entry| entry.state == CommandOutputCaptureRestartStateV1::LaunchIntended)
        {
            entry.store_head = launch.store_head.clone();
        }
        if let Some(terminal) = terminal_prepared.as_ref()
            && let Some(entry) = lifecycle_history
                .iter_mut()
                .find(|entry| entry.state == CommandOutputCaptureRestartStateV1::TerminalPrepared)
        {
            entry.store_head = terminal.store_head.clone();
        }
        let initial_store_head = initial_state.and_then(|state| {
            lifecycle_history
                .iter()
                .find(|entry| entry.state == state)
                .map(|entry| entry.store_head.clone())
        });
        let cleanup_completion_proof_digest = states
            .contains(&CommandOutputCaptureRestartStateV1::Cleaned)
            .then(|| Digest::sha256(format!("physical-cleanup:{label}").as_bytes()));
        CommandOutputCapturePhysicalReconciliationV1::try_new(
            intent,
            claim,
            None,
            1,
            requested_store_head,
            initial_state,
            initial_store_head,
            pending_resolution,
            resolution_action,
            lifecycle_history,
            physical_acquired,
            launch_history,
            artifact_reference,
            terminal_prepared,
            cleanup_completion_proof_digest,
            reconciled_at_unix_ms,
        )
    }

    fn v27_test_artifact_reference(
        intent: &CommandOutputCaptureIntentV1,
        label: &str,
    ) -> CommandOutputArtifactSetReferenceV1 {
        let stdout = format!("stdout:{label}").into_bytes();
        let stderr = format!("stderr:{label}").into_bytes();
        CommandOutputArtifactSetReferenceV1::try_new(
            intent.source.clone(),
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stdout,
                byte_length: u64::try_from(stdout.len()).expect("stdout length fits u64"),
                content_digest: Digest::sha256(&stdout),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stderr,
                byte_length: u64::try_from(stderr.len()).expect("stderr length fits u64"),
                content_digest: Digest::sha256(&stderr),
            },
        )
        .expect("construct exact v27 artifact reference")
    }

    fn sprint_fixture() -> (SprintSpec, TaskGraph) {
        let spec = SprintSpec {
            sprint_id: "sprint-1".into(),
            objective: "Persist and resume safely".into(),
            acceptance_criteria: vec![AcceptanceCriterion {
                criterion_id: "tests".into(),
                description: "Focused tests pass".into(),
                kind: AcceptanceKind::Automated(CommandSpec {
                    program: "cargo".into(),
                    arguments: vec!["test".into()],
                    working_directory: PathBuf::new(),
                }),
            }],
            provider: ProviderProfile {
                backend_id: "fake".into(),
                model_id: "deterministic".into(),
                execution_origin: ExecutionOrigin::HostIsolated,
            },
            budget: SprintBudget {
                max_tasks: 3,
                max_attempts_per_task: 2,
                max_tool_calls: 20,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: WorkspaceGrant {
                grant_id: "grant-1".into(),
                canonical_root: PathBuf::from("/work/project"),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                grant_hash: digest('a'),
            },
            base_snapshot: digest('b'),
        };
        let graph = TaskGraph {
            graph_id: "graph-1".into(),
            tasks: vec![TaskSpec {
                task_id: "task-1".into(),
                goal: "Implement the persistence slice".into(),
                dependencies: Vec::new(),
                path_scopes: vec![PathScope::Workspace],
                acceptance_checks: vec!["tests".into()],
                base_snapshot: digest('b'),
                required: true,
            }],
        };
        (spec, graph)
    }

    fn current_v2_sprint_fixture(sprint_id: &str) -> (SprintSpecV2, TaskGraphV2) {
        let graph_id = format!("graph-{sprint_id}");
        let criterion = AcceptanceCriterion {
            criterion_id: "tests".into(),
            description: "Focused tests pass".into(),
            kind: AcceptanceKind::Automated(CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            }),
        };
        let mut graph = TaskGraphV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            graph_id: graph_id.clone(),
            sprint_id: sprint_id.into(),
            sprint_spec_digest: digest('0'),
            repair_slot_reserve_digest: digest('0'),
            tasks: vec![TaskSpecV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                task_id: "task-1".into(),
                purpose: TaskPurposeV2::Ordinary,
                goal: "Exercise current rollback fencing".into(),
                dependencies: Vec::new(),
                path_scopes: vec![PathScope::Workspace],
                acceptance_checks: vec![criterion.criterion_id.clone()],
                base_snapshot: digest('b'),
                required: true,
            }],
        };
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("compute empty repair reserve");
        let mut spec = SprintSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: sprint_id.into(),
            objective: "Exercise current rollback fencing".into(),
            acceptance_criteria: vec![criterion],
            provider: ProviderProfile {
                backend_id: "fake".into(),
                model_id: "deterministic".into(),
                execution_origin: ExecutionOrigin::HostIsolated,
            },
            budget: SprintBudgetV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                max_tasks: 1,
                max_attempts_per_task: 1,
                max_final_verification_attempts: 1,
                max_tool_calls: 10,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: WorkspaceGrant {
                grant_id: format!("grant-{sprint_id}"),
                canonical_root: PathBuf::from("/work/project"),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                grant_hash: digest('a'),
            },
            base_snapshot: digest('b'),
            task_graph_id: graph_id,
            task_graph_payload_digest: graph.payload_digest().expect("graph payload digest"),
            repair_slot_reserve_digest: graph.repair_slot_reserve_digest.clone(),
        };
        graph.sprint_spec_digest = spec.canonical_digest().expect("current sprint digest");
        spec.task_graph_payload_digest = graph.payload_digest().expect("stable graph payload");
        graph
            .validate_for_sprint(&spec)
            .expect("construct current V2 sprint fixture");
        (spec, graph)
    }

    fn current_v2_rollback_contracts(
        sprint_id: &str,
    ) -> (
        EffectIntent,
        Vec<u8>,
        AgentEvent,
        EffectObservation,
        AgentEvent,
        RollbackEvidence,
    ) {
        let request = RollbackRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: sprint_id.into(),
            application_receipt_id: "application-current-v2".into(),
            application_transaction_id: "transaction-current-v2".into(),
            rollback_reference_id: "rollback-reference-current-v2".into(),
        };
        let request_bytes =
            encode("current V2 rollback request", &request).expect("encode rollback request");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-current-v2-rollback".into(),
            idempotency_key: "key-current-v2-rollback".into(),
            sprint_id: sprint_id.into(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-current-v2-rollback".into(),
            kind: EffectKind::RollbackChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: digest('5'),
            input_snapshot: digest('b'),
            created_at_unix_ms: 20,
        };
        let proposal = effect_proposal_event(&intent, 1, "event-current-v2-rollback-proposed");
        let evidence = RollbackEvidence {
            contract_version: CONTRACT_VERSION,
            receipt: RollbackReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: "receipt-current-v2-rollback".into(),
                sprint_id: sprint_id.into(),
                effect_id: intent.effect_id.clone(),
                observation_id: "observation-current-v2-rollback".into(),
                application_receipt_id: request.application_receipt_id,
                application_transaction_id: request.application_transaction_id,
                restored_base_snapshot: digest('b'),
                restored_endpoints_digest: digest('c'),
                live_manifest_digest: digest('b'),
                unresolved_conflicts: 0,
                completed_at_unix_ms: 30,
            },
            validation: crate::RollbackValidationEvidence {
                mode: RollbackValidationMode::DirectEffectResponse,
                runner_launch_id: "launch-current-v2-rollback".into(),
                runner_session_id: "session-current-v2-rollback".into(),
                policy_hash: intent.policy_hash.clone(),
                grant_hash: digest('a'),
                policy_version: 1,
                private_state_digest: digest('d'),
            },
        };
        let evidence_bytes =
            encode("current V2 rollback evidence", &evidence).expect("encode rollback evidence");
        let observation = effect_observation(
            &intent,
            &evidence.receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            evidence.receipt.completed_at_unix_ms,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "event-current-v2-rollback-finished",
        );
        (
            intent,
            request_bytes,
            proposal,
            observation,
            terminal,
            evidence,
        )
    }

    fn test_worker_lease_for(worker_id: &str, acquired_at_unix_ms: u64) -> WorkerLease {
        WorkerLease::new(
            "sprint-1".into(),
            1,
            "task-1".into(),
            worker_id.into(),
            vec![PathScope::Workspace],
            acquired_at_unix_ms,
        )
        .expect("canonical test worker lease")
    }

    fn draft_base_snapshot() -> WorkspaceSnapshot {
        WorkspaceSnapshot {
            snapshot_id: digest('b'),
            grant_hash: digest('a'),
            created_at_unix_ms: 900,
        }
    }

    fn event(sequence: u64, event_id: &str, causation_id: Option<&str>) -> AgentEvent {
        AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence,
            event_id: event_id.into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            causation_id: causation_id.map(str::to_owned),
            correlation_id: "correlation-1".into(),
            policy_hash: None,
            occurred_at_unix_ms: sequence,
            payload: AgentEventKind::Diagnostic(format!("event {sequence}")),
        }
    }

    fn terminal_evidence(
        record_id: &str,
        state: NonSuccessTerminalState,
    ) -> SprintTerminalEvidence {
        SprintTerminalEvidence {
            contract_version: CONTRACT_VERSION,
            record_id: record_id.into(),
            sprint_id: "sprint-1".into(),
            state,
            reason: format!("Sprint ended as {state:?}"),
            terminal_at_unix_ms: 2_000,
        }
    }

    fn unchanged_terminal_proof(evidence: &SprintTerminalEvidence) -> SprintTerminalProof {
        SprintTerminalProof::LiveWorkspaceUnchanged(LiveWorkspaceUnchangedReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: format!("unchanged-{}", evidence.record_id),
            sprint_id: evidence.sprint_id.clone(),
            base_snapshot: digest('b'),
            live_manifest_digest: digest('b'),
            grant_hash: digest('a'),
            captured_at_unix_ms: evidence.terminal_at_unix_ms,
        })
    }

    fn record_test_terminal_outcome(
        ledger: &mut EventLedger,
        evidence: &SprintTerminalEvidence,
    ) -> Result<PersistedTerminalOutcome, LedgerError> {
        if evidence.state == NonSuccessTerminalState::Unknown {
            ledger.record_unsuccessful_terminal_outcome(evidence)
        } else {
            ledger.record_unsuccessful_terminal_outcome_with_proof(
                evidence,
                &unchanged_terminal_proof(evidence),
            )
        }
    }

    fn prepare_terminal_sprint(ledger: &mut EventLedger) {
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist terminal test sprint");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-1", &base)
            .expect("persist terminal base snapshot");
    }

    fn prepare_terminal_effect(
        ledger: &mut EventLedger,
        outcome: Option<EffectOutcome>,
    ) -> EffectIntent {
        prepare_terminal_sprint(ledger);
        let intent = effect_intent("terminal-effect", "terminal-key", 1_400);
        let proposal = effect_proposal_event(&intent, 1, "terminal-proposed");
        record_test_effect_intent(ledger, &intent, &proposal).expect("persist terminal intent");
        if let Some(outcome) = outcome {
            let observation = effect_observation(&intent, "terminal-observed", outcome, 1_500);
            let terminal =
                effect_terminal_event(&intent, &proposal.event_id, &observation, 2, "effect-done");
            record_test_effect_observation(ledger, &observation, &terminal)
                .expect("persist terminal observation");
        }
        intent
    }

    /// Generic, unclaimed effect used by ledger protocol tests.
    ///
    /// `RunCommand` is deliberately not the default: current-schema commands
    /// are meaningful only with their preallocated v27 output-capture and
    /// runner-dispatch authority. Command-specific fixtures construct that
    /// authority explicitly below.
    fn effect_intent(effect_id: &str, idempotency_key: &str, created_at: u64) -> EffectIntent {
        EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: effect_id.into(),
            idempotency_key: idempotency_key.into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: "correlation-effect".into(),
            kind: crate::EffectKind::SearchLiteral,
            request_digest: Digest::sha256(EFFECT_REQUEST_BYTES),
            policy_hash: digest('5'),
            input_snapshot: digest('b'),
            created_at_unix_ms: created_at,
        }
    }

    fn planning_effect_intent(
        effect_id: &str,
        idempotency_key: &str,
        created_at: u64,
    ) -> EffectIntent {
        let mut intent = effect_intent(effect_id, idempotency_key, created_at);
        intent.kind = EffectKind::ProviderRequest;
        intent
    }

    fn planning_response_bytes(spec: &SprintSpec, graph: &TaskGraph) -> Vec<u8> {
        encode(
            "provider response",
            &ProviderResponse {
                contract_version: CONTRACT_VERSION,
                sprint_id: spec.sprint_id.clone(),
                result: ProviderResponseResult::PlanningComplete {
                    task_graph: graph.clone(),
                },
            },
        )
        .expect("encode canonical planning response")
    }

    fn persist_successful_planning_effect(
        ledger: &mut EventLedger,
        spec: &SprintSpec,
        graph: &TaskGraph,
        effect_id: &str,
        idempotency_key: &str,
        created_at: u64,
        observed_at: u64,
    ) -> (EffectIntent, EffectObservation, Vec<u8>) {
        let intent = planning_effect_intent(effect_id, idempotency_key, created_at);
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&spec.sprint_id)
                .expect("proposal sequence"),
            &format!("{effect_id}-proposed"),
        );
        record_test_effect_intent(ledger, &intent, &proposal).expect("persist planning intent");
        let response_bytes = planning_response_bytes(spec, graph);
        let observation = effect_observation(
            &intent,
            &format!("{effect_id}-observed"),
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&response_bytes),
            },
            observed_at,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence(&spec.sprint_id)
                .expect("terminal sequence"),
            &format!("{effect_id}-finished"),
        );
        ledger
            .record_effect_observation(&observation, &response_bytes, &terminal)
            .expect("persist successful planning response");
        (intent, observation, response_bytes)
    }

    fn effect_proposal_event(intent: &EffectIntent, sequence: u64, event_id: &str) -> AgentEvent {
        AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence,
            event_id: event_id.into(),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            causation_id: intent.causation_event_id.clone(),
            correlation_id: intent.correlation_id.clone(),
            policy_hash: Some(intent.policy_hash.clone()),
            occurred_at_unix_ms: intent.created_at_unix_ms,
            payload: AgentEventKind::ToolProposed {
                tool_call_id: intent.idempotency_key.clone(),
                tool_name: intent.kind.tool_name().into(),
            },
        }
    }

    fn effect_observation(
        intent: &EffectIntent,
        observation_id: &str,
        outcome: EffectOutcome,
        observed_at: u64,
    ) -> EffectObservation {
        EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: observation_id.into(),
            effect_id: intent.effect_id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            worker_lease: intent.worker_lease.clone(),
            correlation_id: intent.correlation_id.clone(),
            kind: intent.kind,
            request_digest: intent.request_digest.clone(),
            policy_hash: intent.policy_hash.clone(),
            input_snapshot: intent.input_snapshot.clone(),
            outcome,
            observed_at_unix_ms: observed_at,
        }
    }

    fn effect_terminal_event(
        intent: &EffectIntent,
        proposed_event_id: &str,
        observation: &EffectObservation,
        sequence: u64,
        event_id: &str,
    ) -> AgentEvent {
        AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence,
            event_id: event_id.into(),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            causation_id: Some(proposed_event_id.into()),
            correlation_id: intent.correlation_id.clone(),
            policy_hash: Some(intent.policy_hash.clone()),
            occurred_at_unix_ms: observation.observed_at_unix_ms,
            payload: AgentEventKind::ToolFinished {
                tool_call_id: intent.idempotency_key.clone(),
                succeeded: observation.outcome.succeeded(),
            },
        }
    }

    fn prepare_effect_input(ledger: &mut EventLedger) {
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist effect sprint");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot("sprint-1", &base)
            .expect("persist effect input snapshot");
    }

    fn record_test_effect_intent(
        ledger: &mut EventLedger,
        intent: &EffectIntent,
        event: &AgentEvent,
    ) -> Result<PersistedEffect, LedgerError> {
        ledger.record_effect_intent(intent, EFFECT_REQUEST_BYTES, event)
    }

    fn record_test_effect_observation(
        ledger: &mut EventLedger,
        observation: &EffectObservation,
        event: &AgentEvent,
    ) -> Result<PersistedEffect, LedgerError> {
        ledger.record_effect_observation(observation, EFFECT_EVIDENCE_BYTES, event)
    }

    fn mutation_intent(
        sprint_id: &str,
        effect_id: &str,
        idempotency_key: &str,
        kind: EffectKind,
        input_snapshot: Digest,
        created_at: u64,
    ) -> EffectIntent {
        let mut intent = effect_intent(effect_id, idempotency_key, created_at);
        intent.sprint_id = sprint_id.into();
        intent.kind = kind;
        intent.input_snapshot = input_snapshot;
        intent
    }

    fn operation_for(kind: EffectKind, path: &str) -> FileOperation {
        match kind {
            EffectKind::CreateRegularFile => FileOperation::Create {
                path: path.into(),
                result_hash: digest('6'),
            },
            EffectKind::ReplaceRegularFile => FileOperation::Modify {
                path: path.into(),
                base_hash: digest('6'),
                result_hash: digest('7'),
            },
            EffectKind::DeleteRegularFile => FileOperation::Delete {
                path: path.into(),
                base_hash: digest('7'),
            },
            _ => panic!("test helper requires a regular-file mutation"),
        }
    }

    fn record_test_mutation(
        ledger: &mut EventLedger,
        intent: &EffectIntent,
        result_snapshot: &WorkspaceSnapshot,
        change_set_id: &str,
        path: &str,
        observed_at: u64,
    ) -> PersistedEffect {
        let proposal = effect_proposal_event(
            intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("proposal sequence"),
            &format!("{}-proposed", intent.effect_id),
        );
        record_test_effect_intent(ledger, intent, &proposal).expect("record mutation intent");
        let observation = effect_observation(
            intent,
            &format!("{}-observed", intent.effect_id),
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            observed_at,
        );
        let terminal = effect_terminal_event(
            intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("terminal sequence"),
            &format!("{}-finished", intent.effect_id),
        );
        let change_set = ChangeSet {
            change_set_id: change_set_id.into(),
            base_snapshot: intent.input_snapshot.clone(),
            result_snapshot: result_snapshot.snapshot_id.clone(),
            operations: vec![operation_for(intent.kind, path)],
        };
        let link = MutationArtifactLink {
            contract_version: CONTRACT_VERSION,
            sprint_id: intent.sprint_id.clone(),
            effect_id: intent.effect_id.clone(),
            observation_id: observation.observation_id.clone(),
            input_snapshot: intent.input_snapshot.clone(),
            result_snapshot: result_snapshot.snapshot_id.clone(),
            change_set_id: change_set.change_set_id.clone(),
        };
        ledger
            .record_mutation_effect_observation(
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
                result_snapshot,
                &change_set,
                &link,
            )
            .expect("record atomic mutation artifacts")
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One end-to-end recurrence and cross-sprint scenario.
    fn mutation_artifacts_round_trip_with_recurring_results_and_sprint_scoped_ids() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);

        let create = mutation_intent(
            "sprint-1",
            "mutation-create-1",
            "mutation-key-1",
            EffectKind::CreateRegularFile,
            digest('b'),
            1_200,
        );
        let result_c = WorkspaceSnapshot {
            snapshot_id: digest('c'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_250,
        };
        let first = record_test_mutation(
            &mut ledger,
            &create,
            &result_c,
            "shared-change-id",
            "probe.txt",
            1_300,
        );
        let PersistedMutationArtifact::Linked {
            link,
            snapshot,
            change_set,
        } = &first.mutation_artifact
        else {
            panic!("create must have linked artifacts");
        };
        assert_eq!(link.effect_id, create.effect_id);
        assert_eq!(link.observation_id, "mutation-create-1-observed");
        assert_eq!(link.input_snapshot, digest('b'));
        assert_eq!(link.result_snapshot, digest('c'));
        assert_eq!(link.change_set_id, "shared-change-id");
        assert_eq!(snapshot, &result_c);
        assert_eq!(change_set.base_snapshot, digest('b'));
        assert_eq!(change_set.result_snapshot, digest('c'));
        assert!(matches!(
            change_set.operations.as_slice(),
            [FileOperation::Create { .. }]
        ));
        assert_eq!(first.evidence_bytes.as_deref(), Some(EFFECT_EVIDENCE_BYTES));
        assert_eq!(
            first
                .terminal_event
                .as_ref()
                .map(|event| event.event_id.as_str()),
            Some("mutation-create-1-finished")
        );

        let delete = mutation_intent(
            "sprint-1",
            "mutation-delete",
            "mutation-key-2",
            EffectKind::DeleteRegularFile,
            digest('c'),
            1_400,
        );
        let recurring_base = WorkspaceSnapshot {
            snapshot_id: digest('b'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_450,
        };
        let deleted = record_test_mutation(
            &mut ledger,
            &delete,
            &recurring_base,
            "delete-change",
            "probe.txt",
            1_500,
        );
        let PersistedMutationArtifact::Linked { snapshot, .. } = deleted.mutation_artifact else {
            panic!("delete must have linked artifacts");
        };
        assert_eq!(snapshot.snapshot_id, digest('b'));
        assert_eq!(snapshot.created_at_unix_ms, 1_100);

        let recreate = mutation_intent(
            "sprint-1",
            "mutation-create-2",
            "mutation-key-3",
            EffectKind::CreateRegularFile,
            digest('b'),
            1_600,
        );
        let recurring_c = WorkspaceSnapshot {
            snapshot_id: digest('c'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_650,
        };
        let recreated = record_test_mutation(
            &mut ledger,
            &recreate,
            &recurring_c,
            "recreate-change",
            "probe.txt",
            1_700,
        );
        let PersistedMutationArtifact::Linked { snapshot, .. } = recreated.mutation_artifact else {
            panic!("recreate must have linked artifacts");
        };
        assert_eq!(snapshot.created_at_unix_ms, 1_250);

        let replace = mutation_intent(
            "sprint-1",
            "mutation-replace",
            "mutation-key-4",
            EffectKind::ReplaceRegularFile,
            digest('c'),
            1_800,
        );
        let result_d = WorkspaceSnapshot {
            snapshot_id: digest('d'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_850,
        };
        record_test_mutation(
            &mut ledger,
            &replace,
            &result_d,
            "replace-change",
            "probe.txt",
            1_900,
        );
        assert_eq!(row_count(&ledger, "workspace_snapshots"), 3);
        assert_eq!(row_count(&ledger, "change_sets"), 4);
        assert_eq!(row_count(&ledger, "mutation_artifact_links"), 4);
        let repeated_c: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM mutation_artifact_links
                 WHERE result_snapshot = ?1",
                [digest('c').as_str()],
                |row| row.get(0),
            )
            .expect("count recurring result links");
        assert_eq!(repeated_c, 2, "result snapshots must not be unique");

        let (mut second_spec, mut second_graph) = sprint_fixture();
        second_spec.sprint_id = "sprint-2".into();
        second_graph.graph_id = "graph-2".into();
        ledger
            .create_sprint(&second_spec, &second_graph, 2_000)
            .expect("create second sprint");
        ledger
            .persist_workspace_snapshot(
                "sprint-2",
                &WorkspaceSnapshot {
                    snapshot_id: digest('b'),
                    grant_hash: digest('a'),
                    created_at_unix_ms: 2_050,
                },
            )
            .expect("persist second sprint base");
        let second_create = mutation_intent(
            "sprint-2",
            "mutation-second-sprint",
            "mutation-key-second-sprint",
            EffectKind::CreateRegularFile,
            digest('b'),
            2_100,
        );
        record_test_mutation(
            &mut ledger,
            &second_create,
            &WorkspaceSnapshot {
                snapshot_id: digest('c'),
                grant_hash: digest('a'),
                created_at_unix_ms: 2_150,
            },
            "shared-change-id",
            "probe.txt",
            2_200,
        );
        let shared_change_ids: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM change_sets WHERE change_set_id = 'shared-change-id'",
                [],
                |row| row.get(0),
            )
            .expect("count sprint-scoped change ids");
        assert_eq!(shared_change_ids, 2);

        drop(ledger);
        let reader = EventLedger::open_read_only(&database.path).expect("restart read-only");
        assert_eq!(
            reader
                .load_effects("sprint-1")
                .expect("reload effects")
                .len(),
            4
        );
        assert!(matches!(
            reader
                .load_effect("mutation-second-sprint")
                .expect("reload cross-sprint mutation")
                .mutation_artifact,
            PersistedMutationArtifact::Linked { .. }
        ));
    }

    #[test]
    fn successful_mutations_reject_the_ordinary_and_direct_sql_observation_paths() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = mutation_intent(
            "sprint-1",
            "mutation-required",
            "mutation-required-key",
            EffectKind::CreateRegularFile,
            digest('b'),
            1_200,
        );
        let proposal = effect_proposal_event(&intent, 1, "mutation-required-proposed");
        record_test_effect_intent(&mut ledger, &intent, &proposal).expect("record intent");
        let observation = effect_observation(
            &intent,
            "mutation-required-observed",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "mutation-required-finished",
        );
        assert!(matches!(
            ledger.record_effect_observation(
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal
            ),
            Err(LedgerError::MutationArtifactRequired(effect_id))
                if effect_id == intent.effect_id
        ));
        assert_eq!(row_count(&ledger, "effect_observations"), 0);
        assert_eq!(row_count(&ledger, "effect_evidence_payloads"), 0);
        assert_eq!(row_count(&ledger, "mutation_artifact_links"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 1);

        {
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start bypass transaction");
            insert_agent_event(&transaction, &terminal).expect("insert paired terminal event");
            insert_effect_evidence_payload(&transaction, &observation, EFFECT_EVIDENCE_BYTES)
                .expect("insert paired evidence");
            assert!(matches!(
                insert_effect_observation(&transaction, &observation, &terminal.event_id),
                Err(LedgerError::Sql(_))
            ));
        }
        assert_eq!(row_count(&ledger, "effect_observations"), 0);
        assert_eq!(row_count(&ledger, "effect_evidence_payloads"), 0);
        assert_eq!(row_count(&ledger, "agent_events"), 1);
        assert_eq!(
            ledger
                .load_effect(&intent.effect_id)
                .expect("pending intent remains readable")
                .mutation_artifact,
            PersistedMutationArtifact::NotRequired
        );
    }

    #[test]
    fn schema_rejects_a_mutation_link_with_the_wrong_operation_relationship() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = mutation_intent(
            "sprint-1",
            "mutation-schema-link",
            "mutation-schema-link-key",
            EffectKind::CreateRegularFile,
            digest('b'),
            1_200,
        );
        let proposal = effect_proposal_event(&intent, 1, "mutation-schema-link-proposed");
        record_test_effect_intent(&mut ledger, &intent, &proposal).expect("record intent");
        let result = WorkspaceSnapshot {
            snapshot_id: digest('c'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_250,
        };
        ledger
            .persist_workspace_snapshot("sprint-1", &result)
            .expect("persist result for bypass attempt");
        let wrong_change = ChangeSet {
            change_set_id: "wrong-operation-change".into(),
            base_snapshot: digest('b'),
            result_snapshot: digest('c'),
            operations: vec![operation_for(
                EffectKind::ReplaceRegularFile,
                "wrong-operation.txt",
            )],
        };
        ledger
            .persist_change_set("sprint-1", &wrong_change)
            .expect("ordinary change set is structurally valid");
        let link = MutationArtifactLink {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            effect_id: intent.effect_id.clone(),
            observation_id: "mutation-schema-link-observed".into(),
            input_snapshot: digest('b'),
            result_snapshot: digest('c'),
            change_set_id: wrong_change.change_set_id,
        };
        let error = ledger
            .connection
            .execute(
                "INSERT INTO mutation_artifact_links (
                    effect_id, sprint_id, link_status, observation_id,
                    input_snapshot, result_snapshot, change_set_id,
                    contract_version, link_json
                 ) VALUES (?1, ?2, 'Linked', ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    link.effect_id,
                    link.sprint_id,
                    link.observation_id,
                    link.input_snapshot.as_str(),
                    link.result_snapshot.as_str(),
                    link.change_set_id,
                    CONTRACT_VERSION,
                    encode("mutation artifact link", &link).expect("encode link"),
                ],
            )
            .expect_err("schema must reject the wrong operation kind");
        assert!(
            error
                .to_string()
                .contains("mutation link must match intent and artifacts")
        );
        assert_eq!(row_count(&ledger, "mutation_artifact_links"), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Assertions cover every rollback boundary in one fixture.
    fn mutation_bundle_mismatches_and_late_failures_leave_no_partial_artifacts() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = mutation_intent(
            "sprint-1",
            "mutation-atomic",
            "mutation-atomic-key",
            EffectKind::CreateRegularFile,
            digest('b'),
            1_200,
        );
        let proposal = effect_proposal_event(&intent, 1, "mutation-atomic-proposed");
        record_test_effect_intent(&mut ledger, &intent, &proposal).expect("record intent");
        let observation = effect_observation(
            &intent,
            "mutation-atomic-observed",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_400,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "mutation-atomic-finished",
        );
        let snapshot = WorkspaceSnapshot {
            snapshot_id: digest('c'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_300,
        };
        let change_set = ChangeSet {
            change_set_id: "mutation-atomic-change".into(),
            base_snapshot: digest('b'),
            result_snapshot: digest('c'),
            operations: vec![operation_for(EffectKind::CreateRegularFile, "atomic.txt")],
        };
        let link = MutationArtifactLink {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            effect_id: intent.effect_id.clone(),
            observation_id: observation.observation_id.clone(),
            input_snapshot: digest('b'),
            result_snapshot: digest('c'),
            change_set_id: change_set.change_set_id.clone(),
        };

        let mut wrong_operation = change_set.clone();
        wrong_operation.operations =
            vec![operation_for(EffectKind::ReplaceRegularFile, "atomic.txt")];
        assert!(matches!(
            ledger.record_mutation_effect_observation(
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
                &snapshot,
                &wrong_operation,
                &link,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "mutation artifact link",
                ..
            })
        ));

        let mut wrong_base = change_set.clone();
        wrong_base.base_snapshot = digest('d');
        assert!(matches!(
            ledger.record_mutation_effect_observation(
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
                &snapshot,
                &wrong_base,
                &link,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "mutation artifact link",
                ..
            })
        ));
        let mut wrong_link = link.clone();
        wrong_link.result_snapshot = digest('d');
        assert!(matches!(
            ledger.record_mutation_effect_observation(
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
                &snapshot,
                &change_set,
                &wrong_link,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "mutation artifact link",
                ..
            })
        ));
        for table in [
            "effect_observations",
            "effect_evidence_payloads",
            "mutation_artifact_links",
            "change_sets",
        ] {
            assert_eq!(row_count(&ledger, table), 0, "partial row in {table}");
        }
        assert_eq!(row_count(&ledger, "workspace_snapshots"), 1);
        assert_eq!(row_count(&ledger, "agent_events"), 1);

        ledger
            .connection
            .execute_batch(
                "CREATE TRIGGER test_abort_mutation_observation
                 BEFORE INSERT ON effect_observations
                 BEGIN SELECT RAISE(ABORT, 'injected mutation failure'); END;",
            )
            .expect("install failure injection");
        assert!(matches!(
            ledger.record_mutation_effect_observation(
                &observation,
                EFFECT_EVIDENCE_BYTES,
                &terminal,
                &snapshot,
                &change_set,
                &link,
            ),
            Err(LedgerError::Sql(_))
        ));
        for table in [
            "effect_observations",
            "effect_evidence_payloads",
            "mutation_artifact_links",
            "change_sets",
        ] {
            assert_eq!(row_count(&ledger, table), 0, "partial row in {table}");
        }
        assert_eq!(row_count(&ledger, "workspace_snapshots"), 1);
        assert_eq!(row_count(&ledger, "agent_events"), 1);

        ledger
            .connection
            .execute_batch("DROP TRIGGER test_abort_mutation_observation;")
            .expect("remove failure injection");
        assert!(matches!(
            ledger
                .record_mutation_effect_observation(
                    &observation,
                    EFFECT_EVIDENCE_BYTES,
                    &terminal,
                    &snapshot,
                    &change_set,
                    &link,
                )
                .expect("retry complete bundle")
                .mutation_artifact,
            PersistedMutationArtifact::Linked { .. }
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Keep the unresolved lifecycle and terminal proof contiguous.
    fn failed_after_known_mutation_requires_evidence_and_only_unknown_terminalization() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = mutation_intent(
            "sprint-1",
            "mutation-known-effect",
            "mutation-known-effect-key",
            EffectKind::ReplaceRegularFile,
            digest('b'),
            1_200,
        );
        let proposal = effect_proposal_event(&intent, 1, "mutation-known-effect-proposed");
        record_test_effect_intent(&mut ledger, &intent, &proposal).expect("record intent");
        let observation = effect_observation(
            &intent,
            "mutation-known-effect-observed",
            EffectOutcome::FailedAfterKnownEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "mutation-known-effect-finished",
        );
        let persisted = record_test_effect_observation(&mut ledger, &observation, &terminal)
            .expect("record known mutation effect without claiming a result snapshot");
        assert_eq!(
            persisted.mutation_artifact,
            PersistedMutationArtifact::NotRequired
        );
        assert_eq!(
            persisted.reconciliation(),
            EffectReconciliation::EvidenceRequired
        );

        assert!(matches!(
            ledger.append_event(&AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: 3,
                event_id: "work-after-unresolved-mutation".into(),
                sprint_id: "sprint-1".into(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: "correlation-after-unresolved".into(),
                policy_hash: None,
                occurred_at_unix_ms: 1_400,
                payload: AgentEventKind::Diagnostic("must be fenced".into()),
            }),
            Err(LedgerError::MutationArtifactUnresolved { effect_id, .. })
                if effect_id == intent.effect_id
        ));
        let next_intent = mutation_intent(
            "sprint-1",
            "mutation-after-unresolved",
            "mutation-after-unresolved-key",
            EffectKind::CreateRegularFile,
            digest('b'),
            1_400,
        );
        let next_proposal =
            effect_proposal_event(&next_intent, 3, "mutation-after-unresolved-proposed");
        assert!(matches!(
            record_test_effect_intent(&mut ledger, &next_intent, &next_proposal),
            Err(LedgerError::MutationArtifactUnresolved { .. })
        ));
        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO sprint_terminal_states (
                    sprint_id, terminal_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES ('sprint-1', 'Completed', 'missing', 'missing', ?1, 2000)",
                    [CONTRACT_VERSION],
                )
                .is_err()
        );
        for state in [
            NonSuccessTerminalState::Blocked,
            NonSuccessTerminalState::Failed,
            NonSuccessTerminalState::Canceled,
        ] {
            assert!(matches!(
                ledger.record_unsuccessful_terminal_outcome(&terminal_evidence(
                    &format!("known-terminal-{state:?}"),
                    state,
                )),
                Err(LedgerError::ReferenceMismatch {
                    entity: "sprint terminal evidence",
                    ..
                })
            ));
        }
        let outcome = ledger
            .record_unsuccessful_terminal_outcome(&terminal_evidence(
                "unknown-terminal-for-known-mutation",
                NonSuccessTerminalState::Unknown,
            ))
            .expect("truthful Unknown terminalizes unresolved mutation state");
        assert_eq!(outcome.terminal_state, SprintState::Unknown);

        drop(ledger);
        let reader = EventLedger::open_read_only(&database.path).expect("restart read-only");
        let restored = reader
            .load_sprint("sprint-1")
            .expect("inspect terminal sprint");
        assert_eq!(
            restored.effects[0].reconciliation(),
            EffectReconciliation::EvidenceRequired
        );
        assert_eq!(
            restored
                .terminal_outcome
                .expect("terminal outcome")
                .terminal_state,
            SprintState::Unknown
        );
    }

    #[test]
    fn unresolved_mutation_inspection_preserves_prior_linked_artifacts() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let create = mutation_intent(
            "sprint-1",
            "mutation-before-unresolved",
            "mutation-before-unresolved-key",
            EffectKind::CreateRegularFile,
            digest('b'),
            1_200,
        );
        record_test_mutation(
            &mut ledger,
            &create,
            &WorkspaceSnapshot {
                snapshot_id: digest('c'),
                grant_hash: digest('a'),
                created_at_unix_ms: 1_250,
            },
            "mutation-before-unresolved-change",
            "mixed.txt",
            1_300,
        );
        let failed = mutation_intent(
            "sprint-1",
            "mutation-unresolved-after-link",
            "mutation-unresolved-after-link-key",
            EffectKind::ReplaceRegularFile,
            digest('c'),
            1_400,
        );
        let proposal = effect_proposal_event(&failed, 3, "mutation-unresolved-proposed");
        record_test_effect_intent(&mut ledger, &failed, &proposal).expect("record second intent");
        let observation = effect_observation(
            &failed,
            "mutation-unresolved-observed",
            EffectOutcome::FailedAfterKnownEffect {
                evidence_digest: effect_evidence_digest(),
            },
            1_500,
        );
        let terminal = effect_terminal_event(
            &failed,
            &proposal.event_id,
            &observation,
            4,
            "mutation-unresolved-finished",
        );
        record_test_effect_observation(&mut ledger, &observation, &terminal)
            .expect("record unresolved mutation");

        let sprint = ledger
            .load_sprint("sprint-1")
            .expect("inspection must remain available");
        assert_eq!(sprint.effects.len(), 2);
        assert!(matches!(
            sprint.effects[0].mutation_artifact,
            PersistedMutationArtifact::Linked { .. }
        ));
        assert_eq!(
            sprint.effects[1].reconciliation(),
            EffectReconciliation::EvidenceRequired
        );
        assert!(matches!(
            ledger.load_completion("sprint-1"),
            Err(LedgerError::MutationArtifactUnresolved { .. })
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Successive corruptions share one validated durable bundle.
    fn mutation_links_are_immutable_and_readback_rejects_relationship_corruption() {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open ledger");
        prepare_effect_input(&mut ledger);
        let intent = mutation_intent(
            "sprint-1",
            "mutation-corruption",
            "mutation-corruption-key",
            EffectKind::CreateRegularFile,
            digest('b'),
            1_200,
        );
        let persisted = record_test_mutation(
            &mut ledger,
            &intent,
            &WorkspaceSnapshot {
                snapshot_id: digest('c'),
                grant_hash: digest('a'),
                created_at_unix_ms: 1_250,
            },
            "mutation-corruption-change",
            "corrupt.txt",
            1_300,
        );
        let PersistedMutationArtifact::Linked {
            link, change_set, ..
        } = persisted.mutation_artifact
        else {
            panic!("mutation must have linked artifacts");
        };
        assert!(
            ledger
                .connection
                .execute_batch("UPDATE mutation_artifact_links SET link_json = link_json;")
                .is_err()
        );
        assert!(
            ledger
                .connection
                .execute_batch("DELETE FROM mutation_artifact_links;")
                .is_err()
        );

        ledger
            .connection
            .execute_batch("DROP TRIGGER mutation_artifact_links_no_update;")
            .expect("disable update fence for corruption test");
        let mut corrupt_link = (*link).clone();
        corrupt_link.change_set_id = "wrong-change-set".into();
        ledger
            .connection
            .execute(
                "UPDATE mutation_artifact_links SET link_json = ?1 WHERE effect_id = ?2",
                params![
                    encode("mutation artifact link", &corrupt_link).expect("encode corruption"),
                    intent.effect_id,
                ],
            )
            .expect("inject envelope corruption");
        assert!(matches!(
            ledger.load_effect(&intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "mutation artifact link",
                ..
            })
        ));
        ledger
            .connection
            .execute(
                "UPDATE mutation_artifact_links SET link_json = ?1 WHERE effect_id = ?2",
                params![
                    encode("mutation artifact link", link.as_ref()).expect("encode valid link"),
                    intent.effect_id,
                ],
            )
            .expect("restore link envelope");
        assert!(ledger.load_effect(&intent.effect_id).is_ok());

        ledger
            .connection
            .execute_batch("DROP TRIGGER change_sets_no_update;")
            .expect("disable change-set fence for corruption test");
        let mut corrupt_change_set = (*change_set).clone();
        corrupt_change_set.operations =
            vec![operation_for(EffectKind::ReplaceRegularFile, "corrupt.txt")];
        ledger
            .connection
            .execute(
                "UPDATE change_sets SET change_set_json = ?1
                 WHERE sprint_id = 'sprint-1' AND change_set_id = ?2",
                params![
                    encode("change set", &corrupt_change_set).expect("encode corruption"),
                    change_set.change_set_id,
                ],
            )
            .expect("inject operation relationship corruption");
        assert!(matches!(
            ledger.load_effect(&intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "mutation artifact link",
                ..
            })
        ));
        ledger
            .connection
            .execute(
                "UPDATE change_sets SET change_set_json = ?1
                 WHERE sprint_id = 'sprint-1' AND change_set_id = ?2",
                params![
                    encode("change set", change_set.as_ref()).expect("encode valid change set"),
                    change_set.change_set_id,
                ],
            )
            .expect("restore change set");
        assert!(ledger.load_effect(&intent.effect_id).is_ok());

        ledger
            .connection
            .execute_batch("DROP TRIGGER mutation_artifact_links_no_delete;")
            .expect("disable delete fence for corruption test");
        ledger
            .connection
            .execute(
                "DELETE FROM mutation_artifact_links WHERE effect_id = ?1",
                [&intent.effect_id],
            )
            .expect("delete required link");
        assert!(matches!(
            ledger.load_effect(&intent.effect_id),
            Err(LedgerError::Corrupt {
                entity: "mutation artifact link",
                ..
            })
        ));
    }

    #[test]
    fn non_mutation_failed_after_known_effect_remains_terminal_known() {
        let intent = effect_intent("command-known-effect", "command-known-key", 1_200);
        let mut persisted = PersistedEffect {
            intent: intent.clone(),
            request_bytes: EFFECT_REQUEST_BYTES.to_vec(),
            proposed_event: effect_proposal_event(&intent, 1, "command-known-proposed"),
            dispatch_claim: None,
            observation: Some(effect_observation(
                &intent,
                "command-known-observed",
                EffectOutcome::FailedAfterKnownEffect {
                    evidence_digest: effect_evidence_digest(),
                },
                1_300,
            )),
            evidence_bytes: Some(EFFECT_EVIDENCE_BYTES.to_vec()),
            terminal_event: None,
            mutation_artifact: PersistedMutationArtifact::NotRequired,
            finish_receipt: PersistedFinishReceipt::NotRequired,
        };
        assert_eq!(
            persisted.reconciliation(),
            EffectReconciliation::TerminalKnown
        );
        persisted.intent.kind = EffectKind::CreateRegularFile;
        assert_eq!(
            persisted.reconciliation(),
            EffectReconciliation::EvidenceRequired
        );
    }

    fn install_v4_planned_effect_database(
        database: &TestDatabase,
    ) -> (SprintSpec, TaskGraph, EffectIntent, EffectObservation) {
        let (spec, graph) = sprint_fixture();
        let intent = effect_intent("v4-effect", "v4-key", 1_200);
        let proposal = effect_proposal_event(&intent, 1, "v4-proposal");
        let observation = effect_observation(
            &intent,
            "v4-observation",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal =
            effect_terminal_event(&intent, "v4-proposal", &observation, 2, "v4-finished");
        schema_template::install_exact_database_at(4, &database.path);
        let mut connection = Connection::open(&database.path).expect("create v4 database");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .expect("configure v4 database");

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start v4 transaction");
        transaction
            .execute(
                "INSERT INTO sprints (
                    sprint_id, contract_version, spec_json, graph_json,
                    created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    spec.sprint_id,
                    i64::from(CONTRACT_VERSION),
                    encode("sprint specification", &spec).expect("encode spec"),
                    encode("task graph", &graph).expect("encode graph"),
                    1_000_i64
                ],
            )
            .expect("insert v4 sprint");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        insert_workspace_snapshot(&transaction, "sprint-1", &base).expect("insert v4 base");
        insert_agent_event(&transaction, &proposal).expect("insert v4 proposal");
        insert_effect_request_payload(&transaction, &intent, EFFECT_REQUEST_BYTES)
            .expect("insert v4 request bytes");
        insert_effect_intent(&transaction, &intent, &proposal.event_id).expect("insert v4 intent");
        insert_agent_event(&transaction, &terminal).expect("insert v4 terminal event");
        insert_effect_evidence_payload(&transaction, &observation, EFFECT_EVIDENCE_BYTES)
            .expect("insert v4 evidence bytes");
        insert_effect_observation(&transaction, &observation, &terminal.event_id)
            .expect("insert v4 observation");
        transaction.commit().expect("commit v4 data");
        connection
            .pragma_update(None, "user_version", 4_i64)
            .expect("mark v4 schema");
        (spec, graph, intent, observation)
    }

    fn install_v6_planned_database(database: &TestDatabase) -> (SprintSpec, TaskGraph) {
        let (spec, graph) = sprint_fixture();
        schema_template::install_exact_database_at(6, &database.path);
        let mut connection = Connection::open(&database.path).expect("create v6 database");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .expect("configure v6 database");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start v6 transaction");
        insert_sprint_definition(&transaction, &spec, 1_000).expect("insert v6 sprint");
        insert_sprint_planning_state(&transaction, &spec).expect("insert v6 planning state");
        insert_direct_graph_provenance(&transaction, &spec.sprint_id)
            .expect("insert v6 graph provenance");
        insert_sprint_task_graph(&transaction, &spec.sprint_id, &spec, &graph)
            .expect("insert v6 graph");
        transaction.commit().expect("commit v6 data");
        connection
            .pragma_update(None, "user_version", 6_i64)
            .expect("mark v6 schema");
        (spec, graph)
    }

    fn install_v7_successful_mutation_database(database: &TestDatabase) -> EffectIntent {
        let (spec, graph) = sprint_fixture();
        let intent = mutation_intent(
            "sprint-1",
            "legacy-successful-mutation",
            "legacy-successful-mutation-key",
            EffectKind::CreateRegularFile,
            digest('b'),
            1_200,
        );
        let proposal = effect_proposal_event(&intent, 1, "legacy-mutation-proposed");
        let observation = effect_observation(
            &intent,
            "legacy-mutation-observed",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "legacy-mutation-finished",
        );
        schema_template::install_exact_database_at(7, &database.path);
        let mut connection = Connection::open(&database.path).expect("create v7 database");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .expect("configure v7 database");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start v7 transaction");
        insert_sprint_definition(&transaction, &spec, 1_000).expect("insert v7 sprint");
        insert_sprint_planning_state(&transaction, &spec).expect("insert v7 planning state");
        insert_direct_graph_provenance(&transaction, &spec.sprint_id)
            .expect("insert v7 graph provenance");
        insert_sprint_task_graph(&transaction, &spec.sprint_id, &spec, &graph)
            .expect("insert v7 graph");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        insert_workspace_snapshot(&transaction, &spec.sprint_id, &base)
            .expect("insert v7 input snapshot");
        insert_agent_event(&transaction, &proposal).expect("insert v7 proposal");
        insert_effect_request_payload(&transaction, &intent, EFFECT_REQUEST_BYTES)
            .expect("insert v7 request bytes");
        insert_effect_intent(&transaction, &intent, &proposal.event_id)
            .expect("insert v7 mutation intent");
        insert_agent_event(&transaction, &terminal).expect("insert v7 terminal event");
        insert_effect_evidence_payload(&transaction, &observation, EFFECT_EVIDENCE_BYTES)
            .expect("insert v7 evidence bytes");
        insert_effect_observation(&transaction, &observation, &terminal.event_id)
            .expect("insert v7 successful mutation observation");
        transaction.commit().expect("commit v7 mutation");
        connection
            .pragma_update(None, "user_version", 7_i64)
            .expect("mark v7 schema");
        intent
    }

    fn install_v8_successful_integration_database(database: &TestDatabase) -> EffectIntent {
        let (spec, graph) = sprint_fixture();
        let mut intent = effect_intent(
            "legacy-successful-integration",
            "legacy-successful-integration-key",
            1_200,
        );
        intent.kind = EffectKind::IntegrateChangeSet;
        let proposal = effect_proposal_event(&intent, 1, "legacy-integration-proposed");
        let observation = effect_observation(
            &intent,
            "legacy-integration-observed",
            EffectOutcome::Succeeded {
                evidence_digest: effect_evidence_digest(),
            },
            1_300,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            2,
            "legacy-integration-finished",
        );
        schema_template::install_exact_database_at(8, &database.path);
        let mut connection = Connection::open(&database.path).expect("create v8 database");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .expect("configure v8 database");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start v8 transaction");
        insert_sprint_definition(&transaction, &spec, 1_000).expect("insert v8 sprint");
        insert_sprint_planning_state(&transaction, &spec).expect("insert v8 planning state");
        insert_direct_graph_provenance(&transaction, &spec.sprint_id)
            .expect("insert v8 graph provenance");
        insert_sprint_task_graph(&transaction, &spec.sprint_id, &spec, &graph)
            .expect("insert v8 graph");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        insert_workspace_snapshot(&transaction, &spec.sprint_id, &base)
            .expect("insert v8 input snapshot");
        insert_agent_event(&transaction, &proposal).expect("insert v8 proposal");
        insert_effect_request_payload(&transaction, &intent, EFFECT_REQUEST_BYTES)
            .expect("insert v8 request");
        insert_effect_intent(&transaction, &intent, &proposal.event_id)
            .expect("insert v8 integration intent");
        insert_agent_event(&transaction, &terminal).expect("insert v8 terminal event");
        insert_effect_evidence_payload(&transaction, &observation, EFFECT_EVIDENCE_BYTES)
            .expect("insert v8 evidence");
        insert_effect_observation(&transaction, &observation, &terminal.event_id)
            .expect("insert v8 observation");
        transaction.commit().expect("commit v8 data");
        connection
            .pragma_update(None, "user_version", 8_i64)
            .expect("mark v8 schema");
        intent
    }

    fn install_v8_completed_database(
        database: &TestDatabase,
    ) -> (FinalReport, Vec<u8>, AgentEvent) {
        let (spec, graph) = sprint_fixture();
        let (base, final_snapshot, _, _, _, report, receipt, mut event) = completion_artifacts();
        event.sequence = 1;
        let receipt_bytes =
            encode_legacy_completion_receipt(&receipt).expect("encode legacy receipt bytes");
        schema_template::install_exact_database_at(8, &database.path);
        let mut connection =
            Connection::open(&database.path).expect("create completed v8 database");
        connection
            .execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .expect("configure completed v8 database");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start completed v8 transaction");
        insert_sprint_definition(&transaction, &spec, 1_000).expect("insert v8 sprint");
        insert_sprint_planning_state(&transaction, &spec).expect("insert v8 planning state");
        insert_direct_graph_provenance(&transaction, &spec.sprint_id)
            .expect("insert v8 graph provenance");
        insert_sprint_task_graph(&transaction, &spec.sprint_id, &spec, &graph)
            .expect("insert v8 graph");
        insert_workspace_snapshot(&transaction, &spec.sprint_id, &base)
            .expect("insert v8 base snapshot");
        insert_workspace_snapshot(&transaction, &spec.sprint_id, &final_snapshot)
            .expect("insert v8 final snapshot");
        insert_final_report(&transaction, &report).expect("insert v8 final report");
        transaction
            .execute(
                "INSERT INTO completion_receipts (
                    receipt_id, sprint_id, final_snapshot, rollback_snapshot,
                    final_report_id, provider_backend, provider_model,
                    contract_version, completed_at_unix_ms, receipt_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    receipt.receipt_id,
                    receipt.sprint_id,
                    receipt.final_snapshot.as_str(),
                    base.snapshot_id.as_str(),
                    receipt.final_report_id,
                    receipt.provider_backend,
                    receipt.provider_model,
                    i64::from(CONTRACT_VERSION),
                    sqlite_integer(
                        "completion_receipt.completed_at_unix_ms",
                        receipt.completed_at_unix_ms
                    )
                    .expect("timestamp fits"),
                    receipt_bytes,
                ],
            )
            .expect("insert v8 completion receipt");
        insert_agent_event(&transaction, &event).expect("insert v8 completion event");
        transaction
            .execute(
                "INSERT INTO sprint_terminal_states (
                    sprint_id, terminal_state, completion_receipt_id,
                    completion_event_id, contract_version, terminal_at_unix_ms
                 ) VALUES (?1, 'Completed', ?2, ?3, ?4, ?5)",
                params![
                    receipt.sprint_id,
                    receipt.receipt_id,
                    event.event_id,
                    i64::from(CONTRACT_VERSION),
                    sqlite_integer(
                        "completion_receipt.completed_at_unix_ms",
                        receipt.completed_at_unix_ms
                    )
                    .expect("timestamp fits"),
                ],
            )
            .expect("insert v8 terminal marker");
        transaction.commit().expect("commit completed v8 data");
        connection
            .pragma_update(None, "user_version", 8_i64)
            .expect("mark v8 schema");
        (report, receipt_bytes, event)
    }

    #[allow(clippy::too_many_lines)] // Complete authority fixtures are intentionally explicit.
    fn completion_artifacts() -> (
        WorkspaceSnapshot,
        WorkspaceSnapshot,
        ChangeSet,
        VerificationReceipt,
        AcceptanceReceipt,
        FinalReport,
        CompletionReceipt,
        AgentEvent,
    ) {
        let base = WorkspaceSnapshot {
            snapshot_id: digest('b'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_100,
        };
        let final_snapshot = WorkspaceSnapshot {
            snapshot_id: digest('c'),
            grant_hash: digest('a'),
            created_at_unix_ms: 1_200,
        };
        let change_set = ChangeSet {
            change_set_id: "change-1".into(),
            base_snapshot: base.snapshot_id.clone(),
            result_snapshot: final_snapshot.snapshot_id.clone(),
            operations: vec![crate::FileOperation::Create {
                path: PathBuf::from("report.txt"),
                result_hash: digest('d'),
            }],
        };
        let verification = VerificationReceipt {
            receipt_id: "verify-final".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            snapshot_id: final_snapshot.snapshot_id.clone(),
            command: CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            },
            policy_hash: digest('d'),
            exit_status: Some(0),
            termination: Some(CommandTerminationV1::Exited { code: 0 }),
            output_digest: digest('e'),
            duration_ms: 25,
            finished_at_unix_ms: 1_500,
        };
        let acceptance = AcceptanceReceipt {
            receipt_id: "acceptance-tests".into(),
            sprint_id: "sprint-1".into(),
            criterion_id: "tests".into(),
            snapshot_id: final_snapshot.snapshot_id.clone(),
            evidence: AcceptanceEvidence::Automated {
                verification_receipt_id: verification.receipt_id.clone(),
            },
            accepted_at_unix_ms: 1_600,
        };
        let body = "All declared checks passed against the applied snapshot.".to_owned();
        let report = FinalReport {
            report_id: "report-final".into(),
            sprint_id: "sprint-1".into(),
            final_snapshot: final_snapshot.snapshot_id.clone(),
            content_digest: FinalReport::digest_body(&body),
            body,
            created_at_unix_ms: 1_900,
        };
        let receipt = CompletionReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "completion-1".into(),
            sprint_id: "sprint-1".into(),
            grant_hash: digest('a'),
            policy_version: 1,
            final_snapshot: final_snapshot.snapshot_id.clone(),
            final_verification_receipt_id: verification.receipt_id.clone(),
            application: CompletionApplication::Applied {
                application_receipt_id: "application-1".into(),
                rollback_reference_id: "rollback-reference-1".into(),
            },
            worker_cleanup_receipt_ids: vec![
                "cleanup-applier".into(),
                "cleanup-final".into(),
                "cleanup-worker".into(),
            ],
            satisfied_criterion_ids: vec!["tests".into()],
            criterion_evidence_receipt_ids: vec![acceptance.receipt_id.clone()],
            task_integration_receipt_ids: vec!["integration-task-1".into()],
            verification_receipts: vec![verification.receipt_id.clone(), "verify-task-1".into()],
            provider_backend: "fake".into(),
            provider_model: "deterministic".into(),
            final_report_id: report.report_id.clone(),
            completed_at_unix_ms: 2_000,
        };
        let completion_event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: 1,
            event_id: "event-completed".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-1".into(),
            policy_hash: None,
            occurred_at_unix_ms: receipt.completed_at_unix_ms,
            payload: AgentEventKind::CompletionRecorded(receipt.receipt_id.clone()),
        };
        (
            base,
            final_snapshot,
            change_set,
            verification,
            acceptance,
            report,
            receipt,
            completion_event,
        )
    }

    fn compiled_test_policy_with_authority(
        policy_id: &str,
        mutation_mode: MutationMode,
        write_scopes: Vec<PathScope>,
    ) -> CompiledExecutionPolicy {
        let mut policy = ExecutionPolicy {
            policy_id: policy_id.into(),
            grant_hash: digest('a'),
            workspace_root: PathBuf::from("/work/project"),
            read_scopes: vec![PathScope::Workspace],
            write_scopes,
            environment: Vec::new(),
            network: ExecutionNetwork::None,
            mutation_mode,
            resource_limits: ResourceLimits {
                wall_time_ms: 30_000,
                max_output_bytes: 1_048_576,
                max_processes: 8,
                max_memory_bytes: Some(256 * 1_048_576),
            },
            approval_id: None,
            policy_hash: digest('0'),
        };
        policy.policy_hash = policy.computed_hash().expect("compute test policy hash");
        CompiledExecutionPolicy::from_test_contract(policy)
    }

    fn compiled_test_policy(policy_id: &str) -> CompiledExecutionPolicy {
        compiled_test_policy_with_authority(policy_id, MutationMode::ReadOnly, Vec::new())
    }

    fn compiled_shadow_test_policy(policy_id: &str) -> CompiledExecutionPolicy {
        compiled_test_policy_with_authority(
            policy_id,
            MutationMode::ShadowWorkspace,
            vec![PathScope::Workspace],
        )
    }

    fn runner_launch(
        launch_id: &str,
        session_id: &str,
        purpose: RunnerSessionPurpose,
        worker_id: Option<&str>,
        policy: &CompiledExecutionPolicy,
        created_at_unix_ms: u64,
    ) -> RunnerLaunchIntent {
        RunnerLaunchIntent {
            contract_version: CONTRACT_VERSION,
            launch_id: launch_id.into(),
            sprint_id: "sprint-1".into(),
            session_id: session_id.into(),
            purpose,
            worker_id: worker_id.map(str::to_owned),
            worker_lease: (purpose == RunnerSessionPurpose::TaskWorker).then(|| {
                test_worker_lease_for(
                    worker_id.expect("task-worker fixture identity"),
                    created_at_unix_ms.saturating_sub(1).max(1),
                )
            }),
            policy_hash: policy.contract().policy_hash.clone(),
            runner_binary_digest: digest('6'),
            protocol_digest: digest('7'),
            private_state_digest: Digest::sha256(launch_id.as_bytes()),
            grant_hash: digest('a'),
            policy_version: 1,
            created_at_unix_ms,
        }
    }

    fn runner_session(
        launch: &RunnerLaunchIntent,
        registered_at_unix_ms: u64,
    ) -> RunnerSessionPolicyRecord {
        RunnerSessionPolicyRecord {
            contract_version: CONTRACT_VERSION,
            sprint_id: launch.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: launch.session_id.clone(),
            purpose: launch.purpose,
            worker_id: launch.worker_id.clone(),
            worker_lease: launch.worker_lease.clone(),
            policy_hash: launch.policy_hash.clone(),
            session_nonce: Digest::sha256(format!("nonce:{}", launch.launch_id).as_bytes()),
            runner_binary_digest: launch.runner_binary_digest.clone(),
            protocol_digest: launch.protocol_digest.clone(),
            private_state_digest: launch.private_state_digest.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            registered_at_unix_ms,
        }
    }

