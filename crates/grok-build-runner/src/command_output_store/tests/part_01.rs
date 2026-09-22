    use std::cell::Cell;
    use std::fs::{self, OpenOptions as StdOpenOptions};
    use std::io::{self, Write as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use grok_build_core::{
        CommandOutputArtifactSetReferenceV1, CommandOutputArtifactSourceV1,
        CommandOutputCaptureIntentV1, CommandOutputCapturePhysicalResolutionActionV1,
        CommandOutputCaptureReconciliationClaimV1, CommandOutputCaptureReconciliationResolutionV1,
        CommandOutputCaptureTerminalAnchorV1, CommandOutputCaptureTerminalDispositionV1,
        CommandOutputStreamArtifactV1, CommandOutputStreamV1, Digest, EffectKind,
        EffectObservation, EffectOutcome,
    };
    use serde::Serialize;

    use super::{
        CapabilityCommandOutputStore, CommandOutputStoreError, FINAL_PREFIX, MANIFEST_FILE,
        MAX_COMMAND_OUTPUT_ARTIFACT_BYTES, ReservationCheckpoint, STDERR_FILE, STDOUT_FILE,
        TEMP_PREFIX, final_directory_name, source_name_digest,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        parent: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let requested_parent = std::env::temp_dir().join(format!(
                "grok-build-command-output-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let requested_state = requested_parent.join("state");
            fs::create_dir(&requested_parent).expect("create fixture parent");
            fs::create_dir(&requested_state).expect("create private state");
            let parent = fs::canonicalize(&requested_parent).expect("canonicalize fixture parent");
            let state = parent.join("state");
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
                .expect("set private-state mode");
            Self { parent, state }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.parent);
        }
    }

    fn source(label: &str) -> CommandOutputArtifactSourceV1 {
        CommandOutputArtifactSourceV1 {
            sprint_id: format!("sprint-{label}"),
            runner_launch_id: format!("launch-{label}"),
            runner_session_id: format!("session-{label}"),
            effect_id: format!("effect-{label}"),
            request_digest: Digest::sha256(format!("request-{label}").as_bytes()),
        }
    }

    fn capture_intent(
        fixture: &Fixture,
        label: &str,
        maximum: u64,
    ) -> CommandOutputCaptureIntentV1 {
        CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(format!("capture-{label}").as_bytes()).to_string(),
            source(label),
            crate::service::inspect_private_state_digest(&fixture.state)
                .expect("inspect private state"),
            maximum,
            1,
        )
        .expect("construct capture Intent")
    }

    #[derive(Serialize)]
    struct CanonicalClaim<'a> {
        contract_version: u32,
        claim_id: &'a str,
        capture_id: &'a str,
        owner_id: &'a str,
        claim_epoch: u64,
        previous_claim_id: Option<&'a str>,
        fencing_token: &'a Digest,
        acquired_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    }

    fn framed_digest(domain: &[u8], value: &[u8]) -> Digest {
        let mut preimage = Vec::with_capacity(domain.len() + 8 + value.len());
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(
            &u64::try_from(value.len())
                .expect("fixture byte length fits u64")
                .to_be_bytes(),
        );
        preimage.extend_from_slice(value);
        Digest::sha256(&preimage)
    }

    fn recovery_claim(
        capture_id: &str,
        epoch: u64,
        previous_claim_id: Option<String>,
    ) -> CommandOutputCaptureReconciliationClaimV1 {
        recovery_claim_for_owner(capture_id, epoch, previous_claim_id, "test-recovery-owner")
    }

    fn recovery_claim_for_owner(
        capture_id: &str,
        epoch: u64,
        previous_claim_id: Option<String>,
        owner_id: &str,
    ) -> CommandOutputCaptureReconciliationClaimV1 {
        let claim_id =
            Digest::sha256(format!("claim-{owner_id}-{capture_id}-{epoch}").as_bytes()).to_string();
        let owner_id = owner_id.to_string();
        let mut token_bytes = Vec::new();
        for value in [
            capture_id.as_bytes(),
            claim_id.as_bytes(),
            owner_id.as_bytes(),
        ] {
            token_bytes.extend_from_slice(
                &u64::try_from(value.len())
                    .expect("fixture byte length fits u64")
                    .to_be_bytes(),
            );
            token_bytes.extend_from_slice(value);
        }
        token_bytes.extend_from_slice(&epoch.to_be_bytes());
        let fencing_token = framed_digest(
            b"grok-build/command-output-capture-reconciliation-fencing-token/v1\0",
            &token_bytes,
        );
        let acquired_at_unix_ms = 10 + epoch;
        let expires_at_unix_ms = acquired_at_unix_ms + 1_000;
        let canonical = serde_json::to_vec(&CanonicalClaim {
            contract_version: grok_build_core::CONTRACT_VERSION,
            claim_id: &claim_id,
            capture_id,
            owner_id: &owner_id,
            claim_epoch: epoch,
            previous_claim_id: previous_claim_id.as_deref(),
            fencing_token: &fencing_token,
            acquired_at_unix_ms,
            expires_at_unix_ms,
        })
        .expect("encode canonical claim");
        let claim_digest = framed_digest(
            b"grok-build/command-output-capture-reconciliation-claim/v1\0",
            &canonical,
        );
        let claim = CommandOutputCaptureReconciliationClaimV1 {
            contract_version: grok_build_core::CONTRACT_VERSION,
            claim_id,
            capture_id: capture_id.to_string(),
            owner_id,
            claim_epoch: epoch,
            previous_claim_id,
            fencing_token,
            acquired_at_unix_ms,
            expires_at_unix_ms,
            claim_digest,
        };
        claim.validate().expect("valid fixture recovery claim");
        claim
    }

    fn assert_same_durable_capture(
        left: &super::CommandOutputCaptureRecovery,
        right: &super::CommandOutputCaptureRecovery,
    ) {
        assert_eq!(left.capture_id(), right.capture_id());
        assert_eq!(left.source(), right.source());
        assert_eq!(
            left.authenticated_maximum_bytes(),
            right.authenticated_maximum_bytes()
        );
        assert_eq!(left.state(), right.state());
        assert_eq!(left.store_head(), right.store_head());
        assert_eq!(left.acquired(), right.acquired());
        assert_eq!(left.expected_reference(), right.expected_reference());
        assert_eq!(left.launch_intended(), right.launch_intended());
        assert_eq!(
            left.launch_intended_store_head(),
            right.launch_intended_store_head()
        );
        assert_eq!(left.finished_store_head(), right.finished_store_head());
        assert_eq!(left.published_store_head(), right.published_store_head());
        assert_eq!(left.terminal(), right.terminal());
        assert_eq!(
            left.terminal_prepared_store_head(),
            right.terminal_prepared_store_head()
        );
        assert_eq!(
            left.cleanup_intended_store_head(),
            right.cleanup_intended_store_head()
        );
        assert_eq!(left.cleaned_store_head(), right.cleaned_store_head());
        assert_eq!(left.pending_record(), right.pending_record());
    }

    fn unknown_terminal(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &grok_build_core::CommandOutputCaptureAcquiredV1,
        store_head: grok_build_core::CommandOutputCaptureStoreHeadV1,
        suffix: &str,
    ) -> CommandOutputCaptureTerminalAnchorV1 {
        let observation = EffectObservation {
            contract_version: grok_build_core::CONTRACT_VERSION,
            observation_id: format!("unknown-observation-{suffix}"),
            effect_id: intent.source.effect_id.clone(),
            idempotency_key: format!("unknown-idempotency-{suffix}"),
            sprint_id: intent.source.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            correlation_id: format!("unknown-correlation-{suffix}"),
            kind: EffectKind::RunCommand,
            request_digest: intent.source.request_digest.clone(),
            policy_hash: Digest::sha256(b"unknown-policy"),
            input_snapshot: Digest::sha256(b"unknown-snapshot"),
            outcome: EffectOutcome::Unknown {
                evidence_digest: Digest::sha256(format!("unknown-evidence-{suffix}").as_bytes()),
            },
            observed_at_unix_ms: 2,
        };
        CommandOutputCaptureTerminalAnchorV1::try_new(
            intent,
            Some(acquired),
            &observation,
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
            store_head,
            Digest::sha256(format!("unknown-terminal-record-{suffix}").as_bytes()),
            None,
            3,
        )
        .expect("construct exact Unknown terminal")
    }

    fn assert_fenced_unknown_resolution_valid(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &grok_build_core::CommandOutputCaptureAcquiredV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        result: &super::CommandOutputCaptureFencedResolution,
        resolved_at_unix_ms: u64,
    ) {
        let receipt = result.physical_reconciliation();
        let disposition =
            if result.recovery().state() == super::CommandOutputCaptureJournalStateV1::Cleaned {
                CommandOutputCaptureTerminalDispositionV1::Abandoned
            } else {
                CommandOutputCaptureTerminalDispositionV1::Published
            };
        let resolution = CommandOutputCaptureReconciliationResolutionV1::try_new(
            intent,
            terminal,
            claim,
            disposition,
            receipt.final_store_head.clone(),
            receipt.final_store_head.record_digest.clone(),
            receipt.artifact_reference.clone(),
            resolved_at_unix_ms,
        )
        .expect("construct exact advancing Unknown resolution");
        receipt
            .validate_for_unknown_resolution(intent, acquired, terminal, claim, &resolution)
            .expect("physical receipt validates against exact core Unknown resolution");
        assert_eq!(result.recovery().store_head(), &receipt.final_store_head);
        assert_eq!(
            result.recovery().expected_reference(),
            receipt.artifact_reference.as_ref()
        );
    }

    fn artifact_path(state: &Path, source: &CommandOutputArtifactSourceV1) -> PathBuf {
        state.join(final_directory_name(
            &source_name_digest(source).expect("derive source name"),
        ))
    }

    fn publish(
        store: &CapabilityCommandOutputStore,
        source: CommandOutputArtifactSourceV1,
        stdout_bytes: &[u8],
        stderr_bytes: &[u8],
    ) -> CommandOutputArtifactSetReferenceV1 {
        let maximum = u64::try_from(stdout_bytes.len() + stderr_bytes.len())
            .expect("fixture length fits u64");
        let capture = store
            .reserve_capture(source, maximum)
            .expect("reserve output capture");
        let (mut stdout, mut stderr, publisher) = capture.split();
        stdout.append(stdout_bytes).expect("append stdout");
        stderr.append(stderr_bytes).expect("append stderr");
        let stdout = stdout.finish().expect("finish stdout");
        let stderr = stderr.finish().expect("finish stderr");
        let validated = publisher
            .publish(stdout, stderr)
            .expect("publish output artifact");
        validated.reference().clone()
    }

    #[test]
    fn reservation_fault_cuts_clean_exact_custody_or_return_reconciliation() {
        for checkpoint in [
            ReservationCheckpoint::DirectoryCreated,
            ReservationCheckpoint::DirectoryOpened,
            ReservationCheckpoint::DirectoryModeSet,
            ReservationCheckpoint::DirectoryMetadataValidated,
            ReservationCheckpoint::StdoutOpened,
            ReservationCheckpoint::StdoutModeSet,
            ReservationCheckpoint::StdoutMetadataValidated,
            ReservationCheckpoint::StderrOpened,
            ReservationCheckpoint::StderrModeSet,
            ReservationCheckpoint::StderrMetadataValidated,
        ] {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let expected_source = source(&format!("reservation-cut-{checkpoint:?}"));
            let error = store
                .reserve_capture_with_probe(expected_source.clone(), 0, |observed| {
                    if observed == checkpoint {
                        Err("injected reservation cut".into())
                    } else {
                        Ok(())
                    }
                })
                .err()
                .expect("injected checkpoint must fail reservation");

            let remaining = fs::read_dir(&fixture.state)
                .expect("enumerate state after reservation cut")
                .collect::<Result<Vec<_>, _>>()
                .expect("read state entries");
            if checkpoint == ReservationCheckpoint::DirectoryCreated {
                assert!(matches!(
                    error,
                    CommandOutputStoreError::ReconciliationRequired {
                        source,
                        expected_reference: None,
                        ..
                    } if source.as_ref() == &expected_source
                ));
                assert_eq!(remaining.len(), 1);
                assert!(
                    remaining[0]
                        .file_name()
                        .to_string_lossy()
                        .starts_with(TEMP_PREFIX)
                );
            } else {
                assert!(matches!(error, CommandOutputStoreError::Artifact(_)));
                assert!(remaining.is_empty(), "exact rollback must remove the temp");
            }
        }
    }

    #[test]
    fn reservation_cleanup_failure_retains_source_authority_and_unknown_entry() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let expected_source = source("reservation-cleanup-authority");
        let state = fixture.state.clone();
        let error = store
            .reserve_capture_with_probe(expected_source.clone(), 0, |checkpoint| {
                if checkpoint != ReservationCheckpoint::StdoutOpened {
                    return Ok(());
                }
                let temp = fs::read_dir(&state)
                    .expect("enumerate active reservation")
                    .next()
                    .expect("active reservation exists")
                    .expect("read active reservation")
                    .path();
                let unexpected = temp.join("unexpected");
                fs::write(&unexpected, b"do not remove").expect("inject unknown entry");
                fs::set_permissions(&unexpected, fs::Permissions::from_mode(0o600))
                    .expect("set injected entry mode");
                Err("injected failure with unsafe cleanup namespace".into())
            })
            .err()
            .expect("injected reservation failure must be returned");
        assert!(matches!(
            error,
            CommandOutputStoreError::ReconciliationRequired {
                source,
                expected_reference: None,
                ..
            } if source.as_ref() == &expected_source
        ));
        let temp = fs::read_dir(&fixture.state)
            .expect("enumerate retained reconciliation temp")
            .next()
            .expect("unsafe temp is retained")
            .expect("read retained temp")
            .path();
        assert_eq!(fs::read(temp.join("unexpected")).unwrap(), b"do not remove");
    }

    #[test]
    fn empty_binary_and_large_streams_round_trip_exactly() {
        for (label, stdout, stderr) in [
            ("empty", Vec::new(), Vec::new()),
            (
                "binary",
                vec![0, 0xff, b'\n', 0x80, 0, 1],
                vec![0xfe, 0, b'\r', b'\n'],
            ),
            (
                "large",
                (0..(2 * 1024 * 1024))
                    .map(|index| u8::try_from(index % 251).expect("fixture byte fits u8"))
                    .collect(),
                vec![0xa5; 1024 * 1024],
            ),
        ] {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let source = source(label);
            let reference = publish(&store, source.clone(), &stdout, &stderr);
            assert_eq!(
                reference.stdout.byte_length,
                u64::try_from(stdout.len()).expect("length fits")
            );
            assert_eq!(reference.stdout.content_digest, Digest::sha256(&stdout));
            assert_eq!(reference.stderr.content_digest, Digest::sha256(&stderr));
            let reopened = store.reopen(&reference).expect("reopen exact artifact");
            let mut observed_stdout = Vec::new();
            let mut observed_stderr = Vec::new();
            reopened
                .copy_stdout_to(&mut observed_stdout)
                .expect("copy stdout");
            reopened
                .copy_stderr_to(&mut observed_stderr)
                .expect("copy stderr");
            assert_eq!(observed_stdout, stdout);
            assert_eq!(observed_stderr, stderr);
            let path = artifact_path(&fixture.state, &source);
            assert_eq!(
                fs::metadata(path.join(STDOUT_FILE)).unwrap().len(),
                stdout.len() as u64
            );
            assert_eq!(
                fs::metadata(path.join(STDERR_FILE)).unwrap().len(),
                stderr.len() as u64
            );
        }
    }

    #[test]
    fn quota_failure_is_typed_reconciliation_and_never_truncates() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let capture = store
            .reserve_capture(source("quota"), 3)
            .expect("reserve bounded capture");
        let (mut stdout, stderr, publisher) = capture.split();
        stdout.append(b"abc").expect("append at boundary");
        let error = stdout.append(b"d").expect_err("reject overshoot");
        assert!(matches!(
            error,
            CommandOutputStoreError::ReconciliationRequired {
                expected_reference: None,
                ..
            }
        ));
        publisher
            .abandon_unpublished(stdout.into_custody(), stderr.into_custody())
            .expect("safely abandon poisoned temp");
        assert!(
            fs::read_dir(&fixture.state)
                .expect("read root")
                .next()
                .is_none()
        );
        assert_eq!(MAX_COMMAND_OUTPUT_ARTIFACT_BYTES, 128 * 1024 * 1024);
    }

    #[test]
    fn same_source_collision_requires_exact_complete_idempotence() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let source = source("collision");
        let first = publish(&store, source.clone(), b"first", b"stderr");
        assert_eq!(publish(&store, source.clone(), b"first", b"stderr"), first);

        let capture = store
            .reserve_capture(source.clone(), 12)
            .expect("reserve colliding capture");
        let (mut stdout, mut stderr, publisher) = capture.split();
        stdout.append(b"second").unwrap();
        stderr.append(b"stderr").unwrap();
        let Err(error) = publisher.publish(stdout.finish().unwrap(), stderr.finish().unwrap())
        else {
            panic!("different same-source bytes must not deduplicate")
        };
        assert!(matches!(
            error,
            CommandOutputStoreError::ReconciliationRequired {
                expected_reference: Some(_),
                ..
            }
        ));
        assert_eq!(store.reopen(&first).unwrap().reference(), &first);
    }

    #[test]
    fn crossed_source_content_and_roles_are_rejected() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let original_source = source("binding");
        let reference = publish(&store, original_source.clone(), b"stdout", b"stderr");

        let crossed_source = CommandOutputArtifactSetReferenceV1::try_new(
            source("other-binding"),
            reference.stdout.clone(),
            reference.stderr.clone(),
        )
        .expect("construct independently valid crossed source");
        assert!(store.reopen(&crossed_source).is_err());

        let crossed_content = CommandOutputArtifactSetReferenceV1::try_new(
            original_source,
            CommandOutputStreamArtifactV1 {
                content_digest: Digest::sha256(b"different stdout"),
                ..reference.stdout.clone()
            },
            reference.stderr.clone(),
        )
        .expect("construct independently valid crossed content");
        assert!(store.reopen(&crossed_content).is_err());

        let mut crossed_roles = reference;
        crossed_roles.stdout.stream = CommandOutputStreamV1::Stderr;
        crossed_roles.stderr.stream = CommandOutputStreamV1::Stdout;
        assert!(matches!(
            store.reopen(&crossed_roles),
            Err(CommandOutputStoreError::Reference(_))
        ));
    }

    #[test]
    fn publisher_rejects_crossed_capture_and_role_custody() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");

        let role_capture = store
            .reserve_capture(source("crossed-role-custody"), 2)
            .unwrap();
        let (mut stdout, mut stderr, publisher) = role_capture.split();
        stdout.append(b"o").unwrap();
        stderr.append(b"e").unwrap();
        let Err(role_error) = publisher.publish(stderr.finish().unwrap(), stdout.finish().unwrap())
        else {
            panic!("crossed role custody must fail")
        };
        assert!(matches!(role_error, CommandOutputStoreError::Artifact(_)));

        let first = store
            .reserve_capture(source("crossed-source-a"), 2)
            .unwrap();
        let second = store
            .reserve_capture(source("crossed-source-b"), 2)
            .unwrap();
        let (mut first_stdout, mut first_stderr, first_publisher) = first.split();
        let (mut second_stdout, second_stderr, _second_publisher) = second.split();
        first_stdout.append(b"a").unwrap();
        first_stderr.append(b"b").unwrap();
        second_stdout.append(b"c").unwrap();
        let Err(source_error) = first_publisher.publish(
            second_stdout.finish().unwrap(),
            first_stderr.finish().unwrap(),
        ) else {
            panic!("crossed source custody must fail")
        };
        assert!(matches!(source_error, CommandOutputStoreError::Artifact(_)));
        drop(first_stdout);
        drop(second_stderr);
    }

    #[test]
    fn abandonment_refuses_unrecognized_temp_entries_without_recursive_delete() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let capture = store.reserve_capture(source("abandon-extra"), 0).unwrap();
        let (stdout, stderr, publisher) = capture.split();
        let temp_path = fixture.state.join(&publisher.temp_name);
        let unexpected = temp_path.join("unexpected");
        fs::write(&unexpected, b"must survive refused cleanup").unwrap();
        fs::set_permissions(&unexpected, fs::Permissions::from_mode(0o600)).unwrap();
        let error = publisher
            .abandon_unpublished(stdout.into_custody(), stderr.into_custody())
            .expect_err("extra temp entry must block cleanup");
        assert!(matches!(
            error,
            CommandOutputStoreError::ReconciliationRequired { .. }
        ));
        assert_eq!(
            fs::read(&unexpected).unwrap(),
            b"must survive refused cleanup"
        );
    }

    #[test]
    fn unsafe_missing_and_extra_entries_all_fail_closed() {
        enum Corruption {
            Symlink,
            Hardlink,
            Special,
            Missing,
            Extra,
        }
        for (index, corruption) in [
            Corruption::Symlink,
            Corruption::Hardlink,
            Corruption::Special,
            Corruption::Missing,
            Corruption::Extra,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let source = source(&format!("unsafe-{index}"));
            let reference = publish(&store, source.clone(), b"stdout", b"stderr");
            let artifact = artifact_path(&fixture.state, &source);
            let raw = artifact.join(STDOUT_FILE);
            match corruption {
                Corruption::Symlink => {
                    let external = fixture.parent.join("external");
                    fs::write(&external, b"stdout").unwrap();
                    fs::remove_file(&raw).unwrap();
                    symlink(&external, &raw).unwrap();
                }
                Corruption::Hardlink => {
                    fs::hard_link(&raw, fixture.parent.join("second-link")).unwrap();
                }
                Corruption::Special => {
                    fs::remove_file(&raw).unwrap();
                    fs::create_dir(&raw).unwrap();
                    fs::set_permissions(&raw, fs::Permissions::from_mode(0o700)).unwrap();
                    assert!(store.reopen(&reference).is_err());
                    continue;
                }
                Corruption::Missing => {
                    fs::remove_file(&raw).unwrap();
                }
                Corruption::Extra => {
                    let extra = artifact.join("extra");
                    fs::write(&extra, b"unexpected").unwrap();
                    fs::set_permissions(&extra, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            assert!(store.reopen(&reference).is_err());
        }
    }

    #[test]
    fn publication_enforces_exact_owner_modes_links_and_distinct_inodes() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let source = source("metadata");
        let reference = publish(&store, source.clone(), b"stdout", b"stderr");
        let artifact = artifact_path(&fixture.state, &source);
        let directory = fs::metadata(&artifact).unwrap();
        let stdout = fs::metadata(artifact.join(STDOUT_FILE)).unwrap();
        let stderr = fs::metadata(artifact.join(STDERR_FILE)).unwrap();
        let manifest = fs::metadata(artifact.join(MANIFEST_FILE)).unwrap();
        assert_eq!(directory.mode() & 0o7777, 0o700);
        assert_eq!(directory.uid(), rustix::process::geteuid().as_raw());
        for metadata in [&stdout, &stderr, &manifest] {
            assert!(metadata.is_file());
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
            assert_eq!(metadata.nlink(), 1);
        }
        assert_ne!((stdout.dev(), stdout.ino()), (stderr.dev(), stderr.ino()));
        assert_eq!(
            fs::read_dir(&artifact).unwrap().count(),
            3,
            "final directory has exactly the three fixed children"
        );
        fs::set_permissions(
            artifact.join(STDERR_FILE),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(store.reopen(&reference).is_err());
    }

    #[test]
    fn noncanonical_manifest_is_rejected_even_when_semantically_equal() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let source = source("noncanonical");
        let reference = publish(&store, source.clone(), b"stdout", b"stderr");
        let manifest_path = artifact_path(&fixture.state, &source).join(MANIFEST_FILE);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        let mut file = StdOpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&manifest_path)
            .unwrap();
        file.write_all(&pretty).unwrap();
        file.sync_all().unwrap();
        assert!(store.reopen(&reference).is_err());
    }

    #[test]
    fn root_and_final_name_replacement_are_detected() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let source = source("replacement");
        let reference = publish(&store, source.clone(), b"stdout", b"stderr");
        let validated = store.reopen(&reference).expect("retain validated view");
        let artifact = artifact_path(&fixture.state, &source);
        let displaced = fixture.state.join("displaced-artifact");
        fs::rename(&artifact, &displaced).unwrap();
        fs::create_dir(&artifact).unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o700)).unwrap();
        for name in [MANIFEST_FILE, STDOUT_FILE, STDERR_FILE] {
            fs::copy(displaced.join(name), artifact.join(name)).unwrap();
            fs::set_permissions(artifact.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(validated.copy_stdout_to(&mut Vec::new()).is_err());
        drop(validated);

        let old_state = fixture.parent.join("old-state");
        fs::rename(&fixture.state, &old_state).unwrap();
        fs::create_dir(&fixture.state).unwrap();
        fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            store.reopen(&reference),
            Err(CommandOutputStoreError::Root(_))
        ));
    }

    struct MutatingDestination {
        target: PathBuf,
        replacement: Vec<u8>,
        mutated: bool,
        received: Vec<u8>,
    }

    impl io::Write for MutatingDestination {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.received.extend_from_slice(bytes);
            if !self.mutated {
                self.mutated = true;
                let mut target = StdOpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&self.target)?;
                target.write_all(&self.replacement)?;
                target.sync_all()?;
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn mutation_during_read_fails_instead_of_returning_validated_custody() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let source = source("read-mutation");
        let bytes = vec![b'a'; 256 * 1024];
        let reference = publish(&store, source.clone(), &bytes, b"");
        let validated = store.reopen(&reference).expect("retain validated artifact");
        let mut destination = MutatingDestination {
            target: artifact_path(&fixture.state, &source).join(STDOUT_FILE),
            replacement: vec![b'b'; bytes.len()],
            mutated: false,
            received: Vec::new(),
        };
        assert!(matches!(
            validated.copy_stdout_to(&mut destination),
            Err(CommandOutputStoreError::Artifact(_))
        ));
    }

    #[test]
    fn crash_cuts_do_not_expose_partial_final_and_post_rename_is_reconcilable() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");

        let before_finish_source = source("crash-before-finish");
        let capture = store
            .reserve_capture(before_finish_source.clone(), 6)
            .expect("reserve capture");
        let (mut stdout, stderr, _publisher) = capture.split();
        stdout.append(b"bytes").unwrap();
        drop(stdout);
        drop(stderr);
        assert!(!artifact_path(&fixture.state, &before_finish_source).exists());

        let before_rename_source = source("crash-before-rename");
        let capture = store
            .reserve_capture(before_rename_source.clone(), 6)
            .expect("reserve capture");
        let (mut stdout, mut stderr, publisher) = capture.split();
        stdout.append(b"abc").unwrap();
        stderr.append(b"def").unwrap();
        drop(stdout.finish().unwrap());
        drop(stderr.finish().unwrap());
        drop(publisher);
        assert!(!artifact_path(&fixture.state, &before_rename_source).exists());

        let after_rename_source = source("crash-after-rename");
        let capture = store
            .reserve_capture(after_rename_source.clone(), 6)
            .expect("reserve capture");
        let (mut stdout, mut stderr, publisher) = capture.split();
        stdout.append(b"abc").unwrap();
        stderr.append(b"def").unwrap();
        let stdout = stdout.finish().unwrap();
        let stderr = stderr.finish().unwrap();
        let expected = CommandOutputArtifactSetReferenceV1::try_new(
            after_rename_source,
            stdout.artifact(),
            stderr.artifact(),
        )
        .unwrap();
        let Err(error) = publisher.publish_with_post_rename_probe(stdout, stderr, || {
            Err("injected crash after rename".into())
        }) else {
            panic!("publication proof must be uncertain")
        };
        assert!(matches!(
            error,
            CommandOutputStoreError::ReconciliationRequired {
                expected_reference: Some(reference),
                ..
            } if reference.as_ref() == &expected
        ));
        assert_eq!(store.reconcile(&expected).unwrap().reference(), &expected);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the lifecycle test intentionally verifies every persisted success head and exact restart reconstruction in one sequential scenario"
    )]
    fn capture_id_journal_handoff_restart_and_terminal_reconstruction_are_exact() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "journal-lifecycle", 64);
        let dispatch_claim_id =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let reservation = store
            .reserve_anchored_capture(&intent, &dispatch_claim_id, 2)
            .expect("reserve anchored capture");
        assert_eq!(reservation.acquired_anchor().capture_id, intent.capture_id);
        let acquired = reservation
            .into_acquired_anchor_for_handoff()
            .expect("synchronize and close reservation custody");
        let acquired_recovery = store
            .reopen_capture(&intent.capture_id)
            .expect("reopen exact acquired capture");
        assert_eq!(
            acquired_recovery.state(),
            super::CommandOutputCaptureJournalStateV1::Acquired
        );
        assert_eq!(acquired_recovery.acquired(), Some(&acquired));

        let capture = store
            .reopen_anchored_capture(&acquired)
            .expect("take exact writer custody");
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        assert_eq!(publisher.capture_id(), Some(intent.capture_id.as_str()));
        let writer_head = publisher.journal_head().expect("WriterAttached head");
        assert_eq!(writer_head.generation, 3);
        let launch_head = publisher
            .record_launch_intended("runner-native-launch/v1", br#"{"launch":"exact"}"#.to_vec())
            .expect("persist LaunchIntended");
        assert_eq!(launch_head.generation, 4);
        stdout
            .append(b"hello \xf0\x9f\x8c\x8d")
            .expect("append stdout");
        stderr
            .append(&[0, 255, b'\n'])
            .expect("append binary stderr");
        let validated_artifact = publisher
            .publish(stdout.finish().unwrap(), stderr.finish().unwrap())
            .expect("publish journaled capture");
        assert_eq!(
            validated_artifact.capture_id(),
            Some(intent.capture_id.as_str())
        );
        assert_eq!(
            validated_artifact
                .capture_finished_store_head()
                .expect("Finished head")
                .generation,
            5
        );
        let published_head = validated_artifact
            .capture_published_store_head()
            .expect("Published head")
            .clone();
        assert_eq!(published_head.generation, 6);
        let expected_reference = validated_artifact.reference().clone();
        drop(validated_artifact);

        let terminal_bytes = br#"{"response":"completed","utf8":"\u03bb"}"#.to_vec();
        let terminal = store
            .prepare_capture_terminal(
                &intent.capture_id,
                &published_head,
                "runner-wire-command-terminal/v11",
                terminal_bytes.clone(),
            )
            .expect("persist TerminalPrepared");
        assert_eq!(
            terminal.state(),
            super::CommandOutputCaptureJournalStateV1::TerminalPrepared
        );
        assert_eq!(terminal.finished_store_head().unwrap().generation, 5);
        assert_eq!(terminal.published_store_head().unwrap().generation, 6);
        assert_eq!(
            terminal.terminal_prepared_store_head().unwrap().generation,
            7
        );
        assert_eq!(
            terminal.terminal_record_digest(),
            Some(
                &terminal
                    .terminal_prepared_store_head()
                    .unwrap()
                    .record_digest
            )
        );
        assert_eq!(terminal.expected_reference(), Some(&expected_reference));
        assert_eq!(terminal.terminal().unwrap().canonical_bytes, terminal_bytes);
        assert_eq!(
            terminal.terminal_payload_digest(),
            Some(&Digest::sha256(
                &terminal.terminal().unwrap().canonical_bytes
            ))
        );
        assert!(
            !fixture
                .state
                .join(format!(
                    "{}{}",
                    super::command_output_journal::WORKING_PREFIX,
                    intent.capture_id
                ))
                .exists()
        );
    }

    #[test]
    fn fenced_restart_absent_capture_writes_tombstone_and_blocks_stale_reservation() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "restart-absent", 64);
        let claim = recovery_claim(&intent.capture_id, 1, None);

        let cleaned = store
            .reconcile_capture_restart(&intent, &claim, None)
            .expect("fenced recovery creates an intent-only tombstone");
        assert_eq!(
            cleaned.state(),
            super::CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert_eq!(cleaned.store_head().generation, 3);
        assert_eq!(cleaned.cleanup_intended_store_head().unwrap().generation, 2);
        assert_eq!(cleaned.cleaned_store_head().unwrap().generation, 3);
        assert!(cleaned.acquired().is_none());
        assert!(cleaned.launch_intended().is_none());
        assert!(cleaned.launch_intended_store_head().is_none());
        let first_evidence = cleaned
            .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
            .expect("initial tombstone evidence");
        assert_eq!(
            first_evidence.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned
        );
        first_evidence
            .validate_against(&intent, &claim, None)
            .expect("initial tombstone validates against unacquired core authority");

        let readback = store
            .reconcile_capture_restart(&intent, &claim, None)
            .expect("same input and claim read the cleaned tombstone idempotently");
        assert_same_durable_capture(&readback, &cleaned);
        let readback_evidence = readback
            .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 2)
            .expect("same-claim readback evidence");
        assert_eq!(
            readback_evidence.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
        );
        assert_eq!(
            readback_evidence.initial_state,
            Some(grok_build_core::CommandOutputCaptureRestartStateV1::Cleaned)
        );
        readback_evidence
            .validate_against(&intent, &claim, None)
            .expect("same-claim readback validates without fabricated initial state");

        let higher_claim = recovery_claim(&intent.capture_id, 2, Some(claim.claim_id.clone()));
        let higher_readback = store
            .reconcile_capture_restart(&intent, &higher_claim, None)
            .expect("higher exact claim reads the same durable tombstone");
        assert_same_durable_capture(&higher_readback, &cleaned);
        let higher_evidence = higher_readback
            .physical_reconciliation_evidence(
                &intent,
                &higher_claim,
                higher_claim.acquired_at_unix_ms + 1,
            )
            .expect("higher-claim readback evidence");
        assert_eq!(higher_evidence.physical_fence_chain_length, 2);
        assert_eq!(
            higher_evidence.predecessor_fence_digest,
            Some(first_evidence.physical_fence_digest)
        );
        assert_eq!(
            higher_evidence.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
        );
        higher_evidence
            .validate_against(&intent, &higher_claim, None)
            .expect("higher-claim readback validates against exact new fence");

        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        assert!(
            store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .is_err(),
            "a stale dispatch must lose at the capture-ID journal mkdir"
        );
        assert!(
            !fixture
                .state
                .join(format!(
                    "{}{}",
                    super::command_output_journal::WORKING_PREFIX,
                    intent.capture_id
                ))
                .exists(),
            "the losing stale dispatch must not create working files"
        );
    }

    #[test]
    fn fenced_restart_resumes_intent_tombstone_after_cleanup_intended_cut() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "restart-intent-cleanup-cut", 8);
        let claim = recovery_claim(&intent.capture_id, 1, None);
        assert!(
            super::command_output_journal::inject_restart_cleanup_cut(
                &store,
                &intent,
                &claim,
                None,
                super::command_output_journal::CleanupCheckpoint::CleanupIntended,
            )
            .is_err()
        );
        assert_eq!(
            store.reopen_capture(&intent.capture_id).unwrap().state(),
            super::CommandOutputCaptureJournalStateV1::CleanupIntended
        );
        let cleaned = store
            .reconcile_capture_restart(&intent, &claim, None)
            .expect("same claim resumes intent-only cleanup");
        assert_eq!(
            cleaned.state(),
            super::CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert_eq!(cleaned.store_head().generation, 3);
    }

    #[test]
    fn fenced_restart_recovers_every_pre_intent_journal_admission_cut() {
        for (index, cut) in [
            super::command_output_journal::InjectedJournalAdmissionCut::DirectoryCreated,
            super::command_output_journal::InjectedJournalAdmissionCut::LockCreated,
            super::command_output_journal::InjectedJournalAdmissionCut::IntentTempTorn,
            super::command_output_journal::InjectedJournalAdmissionCut::IntentTempSynced,
            super::command_output_journal::InjectedJournalAdmissionCut::IntentFinal,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("journal-admission-{index}"), 8);
            super::command_output_journal::inject_initial_journal_admission_cut(
                &store, &intent, cut,
            )
            .expect("inject exact pre-Intent journal cut");
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let cleaned = store
                .reconcile_capture_restart(&intent, &claim, None)
                .expect("fenced restart owns and closes pre-Intent admission cut");
            assert_eq!(
                cleaned.state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned,
                "cut {cut:?}"
            );
            assert_eq!(cleaned.store_head().generation, 3);
            let evidence = cleaned
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .expect("admission recovery evidence is canonical");
            assert_eq!(evidence.final_store_head, *cleaned.store_head());
        }
    }

    #[test]
    fn fenced_restart_cleans_every_pre_acquisition_cut_without_core_backfill() {
        for (index, cut) in [
            super::command_output_journal::InjectedPreAcquisitionCut::WorkingDirectoryCreated,
            super::command_output_journal::InjectedPreAcquisitionCut::StdoutCreated,
            super::command_output_journal::InjectedPreAcquisitionCut::StderrCreated,
            super::command_output_journal::InjectedPreAcquisitionCut::AcquiredTempTorn,
            super::command_output_journal::InjectedPreAcquisitionCut::AcquiredTempSynced,
            super::command_output_journal::InjectedPreAcquisitionCut::AcquiredFinal,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("pre-acquisition-{index}"), 8);
            super::command_output_journal::inject_preacquisition_cut(&store, &intent, cut)
                .expect("inject exact pre-acquisition cut");
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let cleaned = store
                .reconcile_capture_restart(&intent, &claim, None)
                .expect("Intent-only core authority cleans exact physical pre-acquisition state");
            assert_eq!(
                cleaned.state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned,
                "cut {cut:?}"
            );
            let has_physical_acquired = matches!(
                cut,
                super::command_output_journal::InjectedPreAcquisitionCut::AcquiredTempSynced
                    | super::command_output_journal::InjectedPreAcquisitionCut::AcquiredFinal
            );
            assert_eq!(cleaned.acquired().is_some(), has_physical_acquired);
            cleaned
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .expect("pre-acquisition physical evidence is canonical");
        }
    }

    #[test]
    fn intent_only_core_authority_rejects_writer_attached_and_later_physical_state() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "intent-rejects-writer", 8);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = store
            .reserve_anchored_capture(&intent, &dispatch, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();
        let capture = store.reopen_anchored_capture(&acquired).unwrap();
        drop(capture);
        let claim = recovery_claim(&intent.capture_id, 1, None);
        assert!(
            store
                .reconcile_capture_restart(&intent, &claim, None)
                .is_err(),
            "physical WriterAttached cannot be reconciled as an unacquired Intent"
        );
        assert_eq!(
            store.reopen_capture(&intent.capture_id).unwrap().state(),
            super::CommandOutputCaptureJournalStateV1::WriterAttached
        );
    }

    #[test]
    fn fenced_restart_resumes_every_planned_namespace_unlink_cut() {
        for (index, cut) in [
            super::command_output_journal::CleanupCheckpoint::CleanupIntended,
            super::command_output_journal::CleanupCheckpoint::ManifestUnlinked,
            super::command_output_journal::CleanupCheckpoint::StdoutUnlinked,
            super::command_output_journal::CleanupCheckpoint::StderrUnlinked,
            super::command_output_journal::CleanupCheckpoint::DirectoryUnlinked,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("cleanup-cut-{index}"), 32);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            let working = fixture.state.join(format!(
                "{}{}",
                super::command_output_journal::WORKING_PREFIX,
                intent.capture_id
            ));
            let manifest = working.join(MANIFEST_FILE);
            fs::write(&manifest, b"pre-unlink-manifest").expect("create cleanup manifest");
            fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))
                .expect("make cleanup manifest private");
            let claim = recovery_claim(&intent.capture_id, 1, None);
            assert!(
                super::command_output_journal::inject_restart_cleanup_cut(
                    &store,
                    &intent,
                    &claim,
                    Some(&acquired.store_head),
                    cut,
                )
                .is_err(),
                "cut {cut:?} must interrupt before Cleaned"
            );
            let interrupted = store.reopen_capture(&intent.capture_id).unwrap();
            assert_eq!(
                interrupted.state(),
                super::CommandOutputCaptureJournalStateV1::CleanupIntended
            );

            let cleaned = store
                .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
                .expect("same claim resumes exact durable cleanup plan");
            assert_eq!(
                cleaned.state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned
            );
            assert!(!working.exists());
            cleaned
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .expect("physical reconciliation evidence is canonical");
        }
    }

    #[test]
    fn fenced_restart_cleans_acquired_winner_and_retains_historical_launch_binding() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");

        let acquired_intent = capture_intent(&fixture, "restart-acquired-winner", 32);
        let acquired_dispatch = super::command_output_journal::expected_dispatch_claim_id(
            &acquired_intent.source.effect_id,
        );
        let acquired = store
            .reserve_anchored_capture(&acquired_intent, &acquired_dispatch, 2)
            .expect("stale reservation wins mkdir")
            .into_acquired_anchor_for_handoff()
            .expect("close stale reservation custody");
        let acquired_claim = recovery_claim(&acquired_intent.capture_id, 1, None);
        let acquired_cleaned = store
            .reconcile_capture_restart(
                &acquired_intent,
                &acquired_claim,
                Some(&acquired.store_head),
            )
            .expect("fenced recovery cleans the exact acquired winner");
        assert_eq!(
            acquired_cleaned.state(),
            super::CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert_eq!(acquired_cleaned.cleaned_store_head().unwrap().generation, 4);

        let launched_intent = capture_intent(&fixture, "restart-launch-history", 32);
        let launched_dispatch = super::command_output_journal::expected_dispatch_claim_id(
            &launched_intent.source.effect_id,
        );
        let launched = store
            .reserve_anchored_capture(&launched_intent, &launched_dispatch, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();
        let capture = store.reopen_anchored_capture(&launched).unwrap();
        let (stdout, stderr, mut publisher) = capture.split();
        let launch_bytes = br#"{"native_launch":"exact"}"#.to_vec();
        let launch_head = publisher
            .record_launch_intended("runner-native-launch/v1", launch_bytes.clone())
            .expect("persist exact launch binding");
        drop(stdout);
        drop(stderr);
        drop(publisher);

        let launched_claim = recovery_claim(&launched_intent.capture_id, 1, None);
        let launched_cleaned = store
            .reconcile_capture_restart(&launched_intent, &launched_claim, Some(&launch_head))
            .expect("clean launch-intended physical capture");
        assert_eq!(
            launched_cleaned.state(),
            super::CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert_eq!(
            launched_cleaned.launch_intended_store_head(),
            Some(&launch_head)
        );
        assert_eq!(
            launched_cleaned
                .launch_intended()
                .expect("historical launch binding")
                .canonical_bytes,
            launch_bytes
        );
        assert_eq!(
            launched_cleaned.launch_intended_payload_digest(),
            Some(&Digest::sha256(&launch_bytes))
        );
        assert_eq!(
            store
                .reopen_capture(&launched_intent.capture_id)
                .unwrap()
                .launch_intended_store_head(),
            Some(&launch_head)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one negative matrix proves every caller-supplied restart authority binding against the same immutable capture"
    )]
    fn fenced_restart_rejects_crossed_claim_intent_source_head_and_fence() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "restart-negative", 32);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = store
            .reserve_anchored_capture(&intent, &dispatch, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();

        let crossed_claim =
            recovery_claim(&Digest::sha256(b"another-capture").to_string(), 1, None);
        assert!(
            store
                .reconcile_capture_restart(&intent, &crossed_claim, Some(&acquired.store_head))
                .is_err()
        );

        let crossed_intent = CommandOutputCaptureIntentV1::try_new(
            intent.capture_id.clone(),
            source("restart-negative-crossed-source"),
            intent.private_state_digest.clone(),
            intent.max_aggregate_output_bytes,
            intent.created_at_unix_ms,
        )
        .expect("construct independently valid crossed Intent");
        let claim_one = recovery_claim(&intent.capture_id, 1, None);
        assert!(
            store
                .reconcile_capture_restart(&crossed_intent, &claim_one, Some(&acquired.store_head))
                .is_err()
        );

        let wrong_head = grok_build_core::CommandOutputCaptureStoreHeadV1 {
            generation: acquired.store_head.generation,
            record_digest: Digest::sha256(b"wrong-restart-head"),
        };
        assert!(
            store
                .reconcile_capture_restart(&intent, &claim_one, Some(&wrong_head))
                .is_err()
        );
        assert_eq!(
            store
                .reopen_capture(&intent.capture_id)
                .unwrap()
                .store_head(),
            &acquired.store_head,
            "a rejected head cannot mutate lifecycle records"
        );

        let claim_two = recovery_claim(&intent.capture_id, 2, Some(claim_one.claim_id.clone()));
        assert!(
            store
                .reconcile_capture_restart(&intent, &claim_two, Some(&wrong_head))
                .is_err()
        );
        let stale = store
            .reconcile_capture_restart(&intent, &claim_one, Some(&acquired.store_head))
            .expect_err("older claim epoch remains physically fenced");
        assert!(stale.to_string().contains("fenced"));

        let mut invalid_fence =
            recovery_claim(&intent.capture_id, 3, Some(claim_two.claim_id.clone()));
        invalid_fence.fencing_token = Digest::sha256(b"crossed-fencing-token");
        assert!(
            store
                .reconcile_capture_restart(&intent, &invalid_fence, Some(&acquired.store_head))
                .is_err()
        );
    }

    #[test]
    fn durable_restart_fence_permanently_blocks_stale_acquired_reopen() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "fence-blocks-stale-acquired-reopen", 8);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = store
            .reserve_anchored_capture(&intent, &dispatch, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();
        let before = store.reopen_capture(&intent.capture_id).unwrap();
        let claim = recovery_claim(&intent.capture_id, 1, None);
        super::command_output_journal::inject_recovery_fence_cut(
            &store,
            &intent.capture_id,
            &claim,
            super::command_output_journal::InjectedFenceCut::PostRename,
        )
        .expect("persist exact recovery fence before injected restart crash");

        let Err(stale_error) = store.reopen_anchored_capture(&acquired) else {
            panic!("stale ordinary owner must not append WriterAttached after a fence");
        };
        assert!(stale_error.to_string().contains("permanently fenced"));
        assert_same_durable_capture(&store.reopen_capture(&intent.capture_id).unwrap(), &before);

        let cleaned = store
            .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
            .expect("the exact fenced recovery owner remains authorized");
        assert_eq!(
            cleaned.state(),
            super::CommandOutputCaptureJournalStateV1::Cleaned
        );
    }

    #[test]
    fn fenced_restart_same_claim_resumes_every_fence_publication_cut() {
        for (index, cut) in [
            super::command_output_journal::InjectedFenceCut::TempTorn,
            super::command_output_journal::InjectedFenceCut::TempSynced,
            super::command_output_journal::InjectedFenceCut::PostRename,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("fence-cut-{index}"), 8);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            let claim = recovery_claim(&intent.capture_id, 1, None);
            super::command_output_journal::inject_recovery_fence_cut(
                &store,
                &intent.capture_id,
                &claim,
                cut,
            )
            .expect("inject exact recovery-fence cut");

            let cleaned = store
                .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
                .expect("same exact claim resumes its physical fence");
            assert_eq!(
                cleaned.state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned
            );
            let evidence = cleaned
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .expect("physical fence evidence is canonical");
            assert_eq!(evidence.physical_fence_chain_length, 1);
            let replay = store
                .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
                .expect("same final claim replay is idempotent");
            assert_eq!(replay.store_head(), cleaned.store_head());
        }
    }

    #[test]
    fn fenced_restart_rejects_same_epoch_other_claim_and_higher_epoch_supersedes() {
        for (index, cut) in [
            super::command_output_journal::InjectedFenceCut::TempTorn,
            super::command_output_journal::InjectedFenceCut::TempSynced,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("fence-conflict-{index}"), 8);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            let claim_one = recovery_claim(&intent.capture_id, 1, None);
            super::command_output_journal::inject_recovery_fence_cut(
                &store,
                &intent.capture_id,
                &claim_one,
                cut,
            )
            .unwrap();
            let crossed =
                recovery_claim_for_owner(&intent.capture_id, 1, None, "different-recovery-owner");
            assert!(
                store
                    .reconcile_capture_restart(&intent, &crossed, Some(&acquired.store_head))
                    .is_err(),
                "same epoch from another valid claim must not own the pending fence"
            );

            let claim_two = recovery_claim(&intent.capture_id, 2, Some(claim_one.claim_id.clone()));
            let cleaned = store
                .reconcile_capture_restart(&intent, &claim_two, Some(&acquired.store_head))
                .expect("higher physical epoch supersedes interrupted lower fence");
            let evidence = cleaned
                .physical_reconciliation_evidence(
                    &intent,
                    &claim_two,
                    claim_two.acquired_at_unix_ms + 1,
                )
                .unwrap();
            let expected_chain_length = if matches!(
                cut,
                super::command_output_journal::InjectedFenceCut::TempSynced
            ) {
                2
            } else {
                1
            };
            assert_eq!(evidence.physical_fence_chain_length, expected_chain_length);
        }
    }

    #[test]
    fn fenced_restart_resolves_valid_and_torn_pending_record_boundaries() {
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
            let label = format!("restart-pending-cut-{index}");
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
            .expect("inject interrupted successor");
            assert_eq!(
                store
                    .reopen_capture(&intent.capture_id)
                    .unwrap()
                    .pending_record()
                    .unwrap()
                    .class(),
                expected_class
            );

            let claim = recovery_claim(&intent.capture_id, 1, None);
            let cleaned = store
                .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
                .expect("fenced restart resolves exact pending boundary");
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
    fn fenced_restart_finished_cuts_publish_only_complete_canonical_successor() {
        for (index, cut) in [
            super::command_output_journal::InjectedRecordPublicationCut::TempTorn,
            super::command_output_journal::InjectedRecordPublicationCut::TempSynced,
            super::command_output_journal::InjectedRecordPublicationCut::Final,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("finished-cut-{index}"), 6);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            let capture = store.reopen_anchored_capture(&acquired).unwrap();
            let (mut stdout, mut stderr, mut publisher) = capture.split();
            publisher
                .record_launch_intended("runner-native-launch/v1", b"launch".to_vec())
                .unwrap();
            stdout.append(b"abc").unwrap();
            stderr.append(b"def").unwrap();
            let stdout = stdout.finish().unwrap();
            let stderr = stderr.finish().unwrap();
            let stdout_artifact = stdout.artifact();
            let stderr_artifact = stderr.artifact();
            drop(stdout);
            drop(stderr);
            drop(publisher);
            super::command_output_journal::inject_finished_record_cut(
                &store,
                &intent.capture_id,
                stdout_artifact,
                stderr_artifact,
                cut,
            )
            .expect("inject Finished record cut");

            let claim = recovery_claim(&intent.capture_id, 1, None);
            let recovery = store
                .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
                .expect("fenced restart classifies Finished candidate exactly");
            if matches!(
                cut,
                super::command_output_journal::InjectedRecordPublicationCut::TempTorn
            ) {
                assert_eq!(
                    recovery.state(),
                    super::CommandOutputCaptureJournalStateV1::Cleaned,
                    "torn Finished bytes cannot become publication"
                );
                assert!(recovery.expected_reference().is_none());
            } else {
                assert_eq!(
                    recovery.state(),
                    super::CommandOutputCaptureJournalStateV1::Published
                );
                assert!(recovery.expected_reference().is_some());
            }
            recovery
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .expect("Finished-cut physical evidence is canonical");
        }
    }

    #[test]
    fn fenced_restart_terminal_cuts_never_promote_torn_payload_bytes() {
        for (index, cut) in [
            super::command_output_journal::InjectedRecordPublicationCut::TempTorn,
            super::command_output_journal::InjectedRecordPublicationCut::TempSynced,
            super::command_output_journal::InjectedRecordPublicationCut::Final,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("terminal-cut-{index}"), 6);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            let capture = store.reopen_anchored_capture(&acquired).unwrap();
            let (mut stdout, mut stderr, mut publisher) = capture.split();
            publisher
                .record_launch_intended("runner-native-launch/v1", b"launch".to_vec())
                .unwrap();
            stdout.append(b"abc").unwrap();
            stderr.append(b"def").unwrap();
            let published_artifact = publisher
                .publish(stdout.finish().unwrap(), stderr.finish().unwrap())
                .unwrap();
            drop(published_artifact);
            let terminal_bytes = format!("terminal-cut-{index}").into_bytes();
            super::command_output_journal::inject_terminal_prepared_record_cut(
                &store,
                &intent.capture_id,
                "runner-wire-command-terminal/v11",
                terminal_bytes.clone(),
                cut,
            )
            .expect("inject TerminalPrepared record cut");

            let claim = recovery_claim(&intent.capture_id, 1, None);
            let recovery = store
                .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
                .expect("fenced restart classifies terminal candidate exactly");
            if matches!(
                cut,
                super::command_output_journal::InjectedRecordPublicationCut::TempTorn
            ) {
                assert_eq!(
                    recovery.state(),
                    super::CommandOutputCaptureJournalStateV1::Published
                );
                assert!(recovery.terminal().is_none());
            } else {
                assert_eq!(
                    recovery.state(),
                    super::CommandOutputCaptureJournalStateV1::TerminalPrepared
                );
                assert_eq!(recovery.terminal().unwrap().canonical_bytes, terminal_bytes);
            }
            recovery
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .expect("terminal-cut physical evidence is canonical");
        }
    }

    #[test]
    fn fenced_restart_cleaned_record_cuts_converge_under_same_claim() {
        for (index, cut) in [
            super::command_output_journal::InjectedRecordPublicationCut::TempTorn,
            super::command_output_journal::InjectedRecordPublicationCut::TempSynced,
            super::command_output_journal::InjectedRecordPublicationCut::Final,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("cleaned-cut-{index}"), 8);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            let claim = recovery_claim(&intent.capture_id, 1, None);
            assert!(
                super::command_output_journal::inject_restart_cleanup_cut(
                    &store,
                    &intent,
                    &claim,
                    Some(&acquired.store_head),
                    super::command_output_journal::CleanupCheckpoint::DirectoryUnlinked,
                )
                .is_err()
            );
            super::command_output_journal::inject_cleaned_record_cut(
                &store,
                &intent.capture_id,
                &claim,
                cut,
            )
            .expect("inject Cleaned publication cut");
            let cleaned = store
                .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
                .expect("same claim converges Cleaned record publication");
            assert_eq!(
                cleaned.state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned
            );
            cleaned
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .expect("Cleaned-cut physical evidence is canonical");
        }
    }

    #[test]
    fn unknown_resolution_launch_intended_record_publication_cuts_are_receipted() {
        for (index, cut) in [
            super::command_output_journal::InjectedRecordPublicationCut::TempTorn,
            super::command_output_journal::InjectedRecordPublicationCut::TempValid,
            super::command_output_journal::InjectedRecordPublicationCut::TempSynced,
            super::command_output_journal::InjectedRecordPublicationCut::Final,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("unknown-launch-cut-{index}"), 8);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            let capture = store.reopen_anchored_capture(&acquired).unwrap();
            let (stdout, stderr, publisher) = capture.split();
            let writer_head = publisher
                .journal_head()
                .expect("WriterAttached head")
                .clone();
            drop(stdout);
            drop(stderr);
            drop(publisher);
            super::command_output_journal::inject_launch_intended_record_cut(
                &store,
                &intent.capture_id,
                "runner-contained-capture-launch/v1",
                format!("launch-cut-{index}").into_bytes(),
                cut,
            )
            .expect("inject LaunchIntended publication cut");
            let observed = store.reopen_capture(&intent.capture_id).unwrap();
            let observed_head = observed.store_head().clone();
            let terminal = unknown_terminal(
                &intent,
                &acquired,
                writer_head.clone(),
                &format!("launch-{index}"),
            );
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let at = claim.acquired_at_unix_ms + 1;
            let result = store
                .resolve_unknown_capture(
                    &intent,
                    &acquired,
                    &writer_head,
                    &claim,
                    &observed_head,
                    || Ok(at),
                )
                .expect("resolve LaunchIntended cut under exact Unknown fence");
            assert_eq!(
                result.recovery().state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned
            );
            if matches!(
                cut,
                super::command_output_journal::InjectedRecordPublicationCut::TempTorn
            ) {
                assert!(result.recovery().launch_intended().is_none());
                assert!(matches!(
                    result.physical_reconciliation().pending_resolution,
                    grok_build_core::CommandOutputCapturePendingResolutionV1::RemovedTorn { .. }
                ));
            } else {
                assert!(result.recovery().launch_intended().is_some());
            }
            assert_fenced_unknown_resolution_valid(
                &intent, &acquired, &terminal, &claim, &result, at,
            );
        }
    }

    #[test]
    fn unknown_resolution_cleanup_intended_record_publication_cuts_are_receipted() {
        for (index, cut) in [
            super::command_output_journal::InjectedRecordPublicationCut::TempTorn,
            super::command_output_journal::InjectedRecordPublicationCut::TempValid,
            super::command_output_journal::InjectedRecordPublicationCut::TempSynced,
            super::command_output_journal::InjectedRecordPublicationCut::Final,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("unknown-cleanup-cut-{index}"), 8);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            super::command_output_journal::inject_cleanup_intended_record_cut(
                &store,
                &intent.capture_id,
                cut,
            )
            .expect("inject CleanupIntended publication cut");
            let observed = store.reopen_capture(&intent.capture_id).unwrap();
            let observed_head = observed.store_head().clone();
            let terminal = unknown_terminal(
                &intent,
                &acquired,
                acquired.store_head.clone(),
                &format!("cleanup-{index}"),
            );
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let at = claim.acquired_at_unix_ms + 1;
            let result = store
                .resolve_unknown_capture(
                    &intent,
                    &acquired,
                    &acquired.store_head,
                    &claim,
                    &observed_head,
                    || Ok(at),
                )
                .expect("resolve CleanupIntended cut under exact Unknown fence");
            assert_eq!(
                result.recovery().state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned
            );
            assert!(result.recovery().cleaned_store_head().is_some());
            assert_fenced_unknown_resolution_valid(
                &intent, &acquired, &terminal, &claim, &result, at,
            );
        }
    }

    #[test]
    fn unknown_resolution_published_record_publication_cuts_are_receipted() {
        for (index, cut) in [
            super::command_output_journal::InjectedRecordPublicationCut::TempTorn,
            super::command_output_journal::InjectedRecordPublicationCut::TempValid,
            super::command_output_journal::InjectedRecordPublicationCut::TempSynced,
            super::command_output_journal::InjectedRecordPublicationCut::Final,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(&fixture, &format!("unknown-published-cut-{index}"), 16);
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();
            let capture = store.reopen_anchored_capture(&acquired).unwrap();
            let (mut stdout, mut stderr, mut publisher) = capture.split();
            publisher
                .record_launch_intended(
                    "runner-contained-capture-launch/v1",
                    format!("launch-published-{index}").into_bytes(),
                )
                .unwrap();
            stdout.append(b"stdout").unwrap();
            stderr.append(b"stderr").unwrap();
            let stdout = stdout.finish().unwrap();
            let stderr = stderr.finish().unwrap();
            let Err(_) = publisher.publish_with_post_rename_probe(stdout, stderr, || {
                Err("injected post-rename cut before Published".into())
            }) else {
                panic!("post-rename cut must retain Finished")
            };
            let finished = store.reopen_capture(&intent.capture_id).unwrap();
            let finished_head = finished
                .finished_store_head()
                .expect("Finished head")
                .clone();
            super::command_output_journal::inject_published_record_cut(
                &store,
                &intent.capture_id,
                cut,
            )
            .expect("inject Published publication cut");
            let observed = store.reopen_capture(&intent.capture_id).unwrap();
            let observed_head = observed.store_head().clone();
            let terminal = unknown_terminal(
                &intent,
                &acquired,
                finished_head.clone(),
                &format!("published-{index}"),
            );
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let at = claim.acquired_at_unix_ms + 1;
            let result = store
                .resolve_unknown_capture(
                    &intent,
                    &acquired,
                    &finished_head,
                    &claim,
                    &observed_head,
                    || Ok(at),
                )
                .expect("resolve Published cut under exact Unknown fence");
            assert_eq!(
                result.recovery().state(),
                super::CommandOutputCaptureJournalStateV1::Published
            );
            assert!(result.recovery().expected_reference().is_some());
            assert_fenced_unknown_resolution_valid(
                &intent, &acquired, &terminal, &claim, &result, at,
            );
        }
    }

    #[test]
    fn unknown_resolution_retry_reissues_exact_higher_claim_terminal_readback_receipt() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "unknown-resolution-retry", 8);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = store
            .reserve_anchored_capture(&intent, &dispatch, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();
        let terminal = unknown_terminal(&intent, &acquired, acquired.store_head.clone(), "retry");
        let claim_one = recovery_claim(&intent.capture_id, 1, None);
        let first_at = claim_one.acquired_at_unix_ms + 1;
        let first = store
            .resolve_unknown_capture(
                &intent,
                &acquired,
                &acquired.store_head,
                &claim_one,
                &acquired.store_head,
                || Ok(first_at),
            )
            .expect("first physical resolution succeeds before simulated core cut");
        assert_fenced_unknown_resolution_valid(
            &intent, &acquired, &terminal, &claim_one, &first, first_at,
        );
        let cleaned_head = first.recovery().store_head().clone();

        let claim_two = recovery_claim(&intent.capture_id, 2, Some(claim_one.claim_id.clone()));
        let second_at = claim_two.acquired_at_unix_ms + 1;
        let second = store
            .resolve_unknown_capture(
                &intent,
                &acquired,
                &acquired.store_head,
                &claim_two,
                &cleaned_head,
                || Ok(second_at),
            )
            .expect("higher claim regenerates exact receipt after runner/core cut");
        assert_same_durable_capture(first.recovery(), second.recovery());
        assert_eq!(
            second.physical_reconciliation().resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
        );
        assert_eq!(
            second
                .physical_reconciliation()
                .requested_store_head
                .as_ref(),
            Some(&acquired.store_head)
        );
        assert_eq!(
            second.physical_reconciliation().initial_store_head.as_ref(),
            Some(&cleaned_head)
        );
        assert_eq!(
            second.physical_reconciliation().physical_fence_chain_length,
            2
        );
        assert_fenced_unknown_resolution_valid(
            &intent, &acquired, &terminal, &claim_two, &second, second_at,
        );

        let crossed_observed = grok_build_core::CommandOutputCaptureStoreHeadV1 {
            generation: cleaned_head.generation,
            record_digest: Digest::sha256(b"crossed observed Unknown-resolution head"),
        };
        assert!(
            store
                .resolve_unknown_capture(
                    &intent,
                    &acquired,
                    &acquired.store_head,
                    &claim_two,
                    &crossed_observed,
                    || Ok(second_at + 1),
                )
                .is_err()
        );
        let crossed_terminal = grok_build_core::CommandOutputCaptureStoreHeadV1 {
            generation: acquired.store_head.generation,
            record_digest: Digest::sha256(b"crossed Unknown terminal head"),
        };
        assert!(
            store
                .resolve_unknown_capture(
                    &intent,
                    &acquired,
                    &crossed_terminal,
                    &claim_two,
                    &cleaned_head,
                    || Ok(second_at + 1),
                )
                .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One table-driven test covers both post-readback clock-failure cuts.
    fn unknown_resolution_seals_time_after_readback_and_recovers_clock_failures_with_higher_claim()
    {
        #[derive(Clone, Copy, Debug)]
        enum LateClockFailure {
            ReadFailed,
            ExactExpiry,
        }

        for (index, failure) in [LateClockFailure::ReadFailed, LateClockFailure::ExactExpiry]
            .into_iter()
            .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(
                &fixture,
                &format!("unknown-resolution-post-readback-clock-{index}"),
                8,
            );
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .expect("reserve post-readback-clock capture")
                .into_acquired_anchor_for_handoff()
                .expect("synchronize post-readback-clock acquisition");
            let terminal = unknown_terminal(
                &intent,
                &acquired,
                acquired.store_head.clone(),
                &format!("post-readback-clock-{index}"),
            );
            let claim_one = recovery_claim(&intent.capture_id, 1, None);
            let clock_called = Cell::new(false);
            let error = store
                .resolve_unknown_capture(
                    &intent,
                    &acquired,
                    &acquired.store_head,
                    &claim_one,
                    &acquired.store_head,
                    || {
                        clock_called.set(true);
                        match failure {
                            LateClockFailure::ReadFailed => {
                                Err(CommandOutputStoreError::Reference(
                                    "injected post-readback clock failure".into(),
                                ))
                            }
                            LateClockFailure::ExactExpiry => Ok(claim_one.expires_at_unix_ms),
                        }
                    },
                )
                .expect_err("clock failure or exact expiry must withhold a fenced receipt");
            assert!(clock_called.get(), "post-readback clock must be invoked");
            match failure {
                LateClockFailure::ReadFailed => {
                    assert!(error.to_string().contains("post-readback clock failure"));
                }
                LateClockFailure::ExactExpiry => {
                    assert!(error.to_string().contains("reconciled_at_unix_ms"));
                }
            }

            let physical_after_failure = store
                .reopen_capture(&intent.capture_id)
                .expect("late clock failure leaves an exact recoverable physical cut");
            assert_eq!(
                physical_after_failure.state(),
                super::CommandOutputCaptureJournalStateV1::Cleaned
            );
            let cleaned_head = physical_after_failure.store_head().clone();
            let claim_two = recovery_claim(&intent.capture_id, 2, Some(claim_one.claim_id.clone()));
            let retry_at = claim_two.acquired_at_unix_ms + 1;
            let retried = store
                .resolve_unknown_capture(
                    &intent,
                    &acquired,
                    &acquired.store_head,
                    &claim_two,
                    &cleaned_head,
                    || Ok(retry_at),
                )
                .expect("higher claim recovers the post-readback receipt cut");
            assert_eq!(
                retried.physical_reconciliation().resolution_action,
                CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
            );
            assert_eq!(
                retried
                    .physical_reconciliation()
                    .requested_store_head
                    .as_ref(),
                Some(&acquired.store_head)
            );
            assert_eq!(
                retried
                    .physical_reconciliation()
                    .initial_store_head
                    .as_ref(),
                Some(&cleaned_head)
            );
            assert_eq!(
                retried
                    .physical_reconciliation()
                    .physical_fence_chain_length,
                2
            );
            assert_fenced_unknown_resolution_valid(
                &intent, &acquired, &terminal, &claim_two, &retried, retry_at,
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the requested-head matrix proves every Acquired successor against the exact same core validation boundary"
    )]
    fn fenced_restart_accepts_exact_core_acquired_head_across_every_physical_successor() {
        #[derive(Clone, Copy, Debug)]
        enum PhysicalSuccessor {
            Acquired,
            WriterAttached,
            LaunchIntended,
            Finished,
            Published,
            TerminalPrepared,
        }

        for (index, successor) in [
            PhysicalSuccessor::Acquired,
            PhysicalSuccessor::WriterAttached,
            PhysicalSuccessor::LaunchIntended,
            PhysicalSuccessor::Finished,
            PhysicalSuccessor::Published,
            PhysicalSuccessor::TerminalPrepared,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new();
            let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
            let intent = capture_intent(
                &fixture,
                &format!("requested-acquired-successor-{index}"),
                16,
            );
            let dispatch =
                super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
            let acquired = store
                .reserve_anchored_capture(&intent, &dispatch, 2)
                .unwrap()
                .into_acquired_anchor_for_handoff()
                .unwrap();

            match successor {
                PhysicalSuccessor::Acquired => {}
                PhysicalSuccessor::WriterAttached => {
                    drop(store.reopen_anchored_capture(&acquired).unwrap());
                }
                PhysicalSuccessor::LaunchIntended => {
                    let capture = store.reopen_anchored_capture(&acquired).unwrap();
                    let (stdout, stderr, mut publisher) = capture.split();
                    publisher
                        .record_launch_intended(
                            "runner-native-launch/v1",
                            format!("launch-{index}").into_bytes(),
                        )
                        .unwrap();
                    drop(stdout);
                    drop(stderr);
                    drop(publisher);
                }
                PhysicalSuccessor::Finished => {
                    let capture = store.reopen_anchored_capture(&acquired).unwrap();
                    let (mut stdout, mut stderr, mut publisher) = capture.split();
                    publisher
                        .record_launch_intended(
                            "runner-native-launch/v1",
                            format!("launch-{index}").into_bytes(),
                        )
                        .unwrap();
                    stdout.append(b"stdout").unwrap();
                    stderr.append(b"stderr").unwrap();
                    let stdout = stdout.finish().unwrap();
                    let stderr = stderr.finish().unwrap();
                    let stdout_artifact = stdout.artifact();
                    let stderr_artifact = stderr.artifact();
                    drop(stdout);
                    drop(stderr);
                    drop(publisher);
                    super::command_output_journal::inject_finished_record_cut(
                        &store,
                        &intent.capture_id,
                        stdout_artifact,
                        stderr_artifact,
                        super::command_output_journal::InjectedRecordPublicationCut::Final,
                    )
                    .unwrap();
                }
                PhysicalSuccessor::Published | PhysicalSuccessor::TerminalPrepared => {
                    let capture = store.reopen_anchored_capture(&acquired).unwrap();
                    let (mut stdout, mut stderr, mut publisher) = capture.split();
                    publisher
                        .record_launch_intended(
                            "runner-native-launch/v1",
                            format!("launch-{index}").into_bytes(),
                        )
                        .unwrap();
                    stdout.append(b"stdout").unwrap();
                    stderr.append(b"stderr").unwrap();
                    let published_artifact = publisher
                        .publish(stdout.finish().unwrap(), stderr.finish().unwrap())
                        .unwrap();
                    let published_head = published_artifact
                        .capture_published_store_head()
                        .expect("Published head")
                        .clone();
                    drop(published_artifact);
                    if matches!(successor, PhysicalSuccessor::TerminalPrepared) {
                        store
                            .prepare_capture_terminal(
                                &intent.capture_id,
                                &published_head,
                                "runner-wire-command-terminal/v11",
                                format!("terminal-{index}").into_bytes(),
                            )
                            .unwrap();
                    }
                }
            }

            let before = store.reopen_capture(&intent.capture_id).unwrap();
            let expected_initial = match successor {
                PhysicalSuccessor::Acquired => super::CommandOutputCaptureJournalStateV1::Acquired,
                PhysicalSuccessor::WriterAttached => {
                    super::CommandOutputCaptureJournalStateV1::WriterAttached
                }
                PhysicalSuccessor::LaunchIntended => {
                    super::CommandOutputCaptureJournalStateV1::LaunchIntended
                }
                PhysicalSuccessor::Finished => super::CommandOutputCaptureJournalStateV1::Finished,
                PhysicalSuccessor::Published => {
                    super::CommandOutputCaptureJournalStateV1::Published
                }
                PhysicalSuccessor::TerminalPrepared => {
                    super::CommandOutputCaptureJournalStateV1::TerminalPrepared
                }
            };
            assert_eq!(before.state(), expected_initial, "{successor:?}");

            let claim = recovery_claim(&intent.capture_id, 1, None);
            let recovery = store
                .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
                .expect("exact core Acquired head remains valid across its physical successors");
            let expected_final = match successor {
                PhysicalSuccessor::Acquired
                | PhysicalSuccessor::WriterAttached
                | PhysicalSuccessor::LaunchIntended => {
                    super::CommandOutputCaptureJournalStateV1::Cleaned
                }
                PhysicalSuccessor::Finished | PhysicalSuccessor::Published => {
                    super::CommandOutputCaptureJournalStateV1::Published
                }
                PhysicalSuccessor::TerminalPrepared => {
                    super::CommandOutputCaptureJournalStateV1::TerminalPrepared
                }
            };
            assert_eq!(recovery.state(), expected_final, "{successor:?}");
            let evidence = recovery
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .expect("runner constructs exact successor evidence");
            assert_eq!(
                evidence.requested_store_head.as_ref(),
                Some(&acquired.store_head),
                "{successor:?}"
            );
            assert_eq!(
                evidence.physical_acquired.as_ref(),
                Some(&acquired),
                "{successor:?}"
            );
            evidence
                .validate_against(&intent, &claim, Some(&acquired))
                .unwrap_or_else(|error| {
                    panic!("{successor:?} evidence must validate against core Acquired: {error}")
                });
        }
    }

    #[test]
    fn fenced_restart_rejects_crossed_and_nonexistent_requested_heads_before_mutation() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "requested-head-rejection", 8);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = store
            .reserve_anchored_capture(&intent, &dispatch, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();
        drop(store.reopen_anchored_capture(&acquired).unwrap());
        let before = store.reopen_capture(&intent.capture_id).unwrap();
        let claim = recovery_claim(&intent.capture_id, 1, None);

        let crossed = grok_build_core::CommandOutputCaptureStoreHeadV1 {
            generation: acquired.store_head.generation,
            record_digest: Digest::sha256(b"crossed requested head"),
        };
        assert!(
            store
                .reconcile_capture_restart(&intent, &claim, Some(&crossed))
                .is_err()
        );
        assert_same_durable_capture(&store.reopen_capture(&intent.capture_id).unwrap(), &before);

        let nonexistent = grok_build_core::CommandOutputCaptureStoreHeadV1 {
            generation: before.store_head().generation + 100,
            record_digest: Digest::sha256(b"nonexistent requested head"),
        };
        assert!(
            store
                .reconcile_capture_restart(&intent, &claim, Some(&nonexistent))
                .is_err()
        );
        assert_same_durable_capture(&store.reopen_capture(&intent.capture_id).unwrap(), &before);

        let cleaned = store
            .reconcile_capture_restart(&intent, &claim, Some(&acquired.store_head))
            .expect("rejected requested heads do not poison the exact winning claim");
        assert_eq!(
            cleaned.state(),
            super::CommandOutputCaptureJournalStateV1::Cleaned
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exact no-mutation readback assertions cover both durable terminal states.
    fn fenced_restart_reads_published_and_terminal_prepared_without_lifecycle_mutation() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "restart-terminal-readback", 6);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = store
            .reserve_anchored_capture(&intent, &dispatch, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();
        let capture = store.reopen_anchored_capture(&acquired).unwrap();
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        publisher
            .record_launch_intended("runner-native-launch/v1", b"launch".to_vec())
            .unwrap();
        stdout.append(b"abc").unwrap();
        stderr.append(b"def").unwrap();
        let artifact = publisher
            .publish(stdout.finish().unwrap(), stderr.finish().unwrap())
            .unwrap();
        let published_head = artifact
            .capture_published_store_head()
            .expect("Published head")
            .clone();
        drop(artifact);

        let claim = recovery_claim(&intent.capture_id, 1, None);
        let published_readback = store
            .reconcile_capture_restart(&intent, &claim, Some(&published_head))
            .expect("Published is an idempotent fenced readback");
        assert_eq!(
            published_readback.state(),
            super::CommandOutputCaptureJournalStateV1::Published
        );
        assert_eq!(published_readback.store_head(), &published_head);
        let stale_terminal = store
            .prepare_capture_terminal(
                &intent.capture_id,
                &published_head,
                "runner-wire-command-terminal/v11",
                b"stale-terminal".to_vec(),
            )
            .expect_err("ordinary terminal preparation is permanently restart-fenced");
        assert!(stale_terminal.to_string().contains("permanently fenced"));
        assert_same_durable_capture(
            &store.reopen_capture(&intent.capture_id).unwrap(),
            &published_readback,
        );

        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "restart-prepared-terminal-readback", 6);
        let dispatch =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = store
            .reserve_anchored_capture(&intent, &dispatch, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();
        let capture = store.reopen_anchored_capture(&acquired).unwrap();
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        publisher
            .record_launch_intended("runner-native-launch/v1", b"launch".to_vec())
            .unwrap();
        stdout.append(b"abc").unwrap();
        stderr.append(b"def").unwrap();
        let artifact = publisher
            .publish(stdout.finish().unwrap(), stderr.finish().unwrap())
            .unwrap();
        let published_head = artifact
            .capture_published_store_head()
            .expect("Published head")
            .clone();
        drop(artifact);
        let terminal = store
            .prepare_capture_terminal(
                &intent.capture_id,
                &published_head,
                "runner-wire-command-terminal/v11",
                b"terminal".to_vec(),
            )
            .unwrap();
        let terminal_head = terminal.store_head().clone();
        let claim = recovery_claim(&intent.capture_id, 1, None);
        let first = store
            .reconcile_capture_restart(&intent, &claim, Some(&terminal_head))
            .expect("TerminalPrepared is an idempotent fenced readback");
        let second = store
            .reconcile_capture_restart(&intent, &claim, Some(&terminal_head))
            .expect("repeat terminal readback does not append lifecycle records");
        assert_same_durable_capture(&first, &terminal);
        assert_same_durable_capture(&second, &terminal);
        assert_same_durable_capture(&first, &second);
        let first_evidence = first
            .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
            .expect("first terminal readback evidence");
        let second_evidence = second
            .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 2)
            .expect("repeat terminal readback evidence");
        for evidence in [&first_evidence, &second_evidence] {
            assert_eq!(
                evidence.resolution_action,
                CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
            );
            assert_eq!(
                evidence.initial_state,
                Some(grok_build_core::CommandOutputCaptureRestartStateV1::TerminalPrepared)
            );
        }
        assert_eq!(
            first_evidence.lifecycle_history,
            second_evidence.lifecycle_history
        );
        assert_eq!(second.store_head(), &terminal_head);
    }

    #[test]
    fn fenced_recovery_rolls_forward_an_exact_post_rename_finished_capture() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "journal-post-rename", 6);
        let dispatch_claim_id =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = store
            .reserve_anchored_capture(&intent, &dispatch_claim_id, 2)
            .unwrap()
            .into_acquired_anchor_for_handoff()
            .unwrap();
        let capture = store.reopen_anchored_capture(&acquired).unwrap();
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        publisher
            .record_launch_intended("runner-native-launch/v1", b"launch".to_vec())
            .unwrap();
        stdout.append(b"abc").unwrap();
        stderr.append(b"def").unwrap();
        let Err(error) = publisher.publish_with_post_rename_probe(
            stdout.finish().unwrap(),
            stderr.finish().unwrap(),
            || Err("injected crash after exact rename".into()),
        ) else {
            panic!("post-rename cut must not claim Published")
        };
        assert!(matches!(
            error,
            CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(id),
                ..
            } if id == intent.capture_id
        ));

        let uncertain = store
            .reopen_capture(&intent.capture_id)
            .expect("Finished journal must classify the exact renamed directory");
        assert_eq!(
            uncertain.state(),
            super::CommandOutputCaptureJournalStateV1::Finished
        );
        let finished_head = uncertain.finished_store_head().unwrap().clone();
        let reference = uncertain.expected_reference().unwrap().clone();
        assert_eq!(finished_head.generation, 5);
        assert_eq!(uncertain.store_head(), &finished_head);

        let claim = recovery_claim(&intent.capture_id, 1, None);
        let reconciled = store
            .cleanup_capture(&claim, &finished_head)
            .expect("fenced owner must roll exact publication forward, never unlink it");
        assert_eq!(
            reconciled.state(),
            super::CommandOutputCaptureJournalStateV1::Published
        );
        assert_eq!(reconciled.expected_reference(), Some(&reference));
        assert_eq!(reconciled.published_store_head().unwrap().generation, 6);
        assert!(reconciled.cleaned_store_head().is_none());

        let error = store
            .prepare_capture_terminal(
                &intent.capture_id,
                reconciled.published_store_head().unwrap(),
                "runner-wire-command-terminal/v11",
                b"terminal".to_vec(),
            )
            .expect_err("ordinary mutation cannot cross a durable restart fence");
        assert!(
            error
                .to_string()
                .contains("permanently fenced by restart reconciliation")
        );
        let terminal = store
            .reopen_capture(&intent.capture_id)
            .expect("fenced publication remains exactly readable");
        assert_eq!(
            terminal.state(),
            super::CommandOutputCaptureJournalStateV1::Published
        );
    }

    #[test]
    fn terminal_payload_json_expansion_is_bounded_and_binary_exact_at_limit() {
        let maximum = super::command_output_journal::MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES;
        let payload = vec![0xff; maximum];
        let bounded = super::CommandOutputCaptureCanonicalPayloadV1::try_new(
            "runner-wire-command-terminal/v11",
            payload.clone(),
            maximum,
        )
        .expect("maximum payload is admitted");
        let encoded = serde_json::to_vec(&bounded).expect("encode bounded payload");
        assert!(
            u64::try_from(encoded.len()).unwrap() < super::command_output_journal::MAX_RECORD_BYTES,
            "worst-case decimal byte-array expansion must fit the journal record bound"
        );
        assert_eq!(bounded.canonical_bytes_digest, Digest::sha256(&payload));
        assert!(
            super::CommandOutputCaptureCanonicalPayloadV1::try_new(
                "runner-wire-command-terminal/v11",
                vec![0; maximum + 1],
                maximum,
            )
            .is_err()
        );
        assert!(
            super::CommandOutputCaptureCanonicalPayloadV1::try_new(
                "terminal/\u{03bb}",
                vec![1],
                maximum,
            )
            .is_err(),
            "schema identity stays canonical ASCII while payload bytes remain arbitrary"
        );
    }

    #[test]
    fn fenced_restart_cleanup_proves_exact_objects_unlinked_and_stale_epochs_lose() {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = capture_intent(&fixture, "journal-cleanup", 32);
        let dispatch_claim_id =
            super::command_output_journal::expected_dispatch_claim_id(&intent.source.effect_id);
        let acquired = store
            .reserve_anchored_capture(&intent, &dispatch_claim_id, 2)
            .expect("reserve anchored capture")
            .into_acquired_anchor_for_handoff()
            .expect("close handoff custody");
        let wrong_head = grok_build_core::CommandOutputCaptureStoreHeadV1 {
            generation: acquired.store_head.generation,
            record_digest: Digest::sha256(b"wrong-head"),
        };
        let claim_one = recovery_claim(&intent.capture_id, 1, None);
        assert!(store.cleanup_capture(&claim_one, &wrong_head).is_err());
        let claim_two = recovery_claim(&intent.capture_id, 2, Some(claim_one.claim_id.clone()));
        assert!(store.cleanup_capture(&claim_two, &wrong_head).is_err());
        let stale = store
            .cleanup_capture(&claim_one, &acquired.store_head)
            .expect_err("lower epoch must remain durably fenced");
        assert!(stale.to_string().contains("fenced"));

        let claim_three = recovery_claim(&intent.capture_id, 3, Some(claim_two.claim_id.clone()));
        let cleaned = store
            .cleanup_capture(&claim_three, &acquired.store_head)
            .expect("exact fenced cleanup");
        assert_eq!(
            cleaned.state(),
            super::CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert_eq!(cleaned.cleanup_intended_store_head().unwrap().generation, 3);
        assert_eq!(cleaned.cleaned_store_head().unwrap().generation, 4);
        assert_eq!(
            cleaned.cleaned_record_digest(),
            Some(&cleaned.cleaned_store_head().unwrap().record_digest)
        );
        assert_eq!(
            cleaned.terminal_record_digest(),
            cleaned.cleaned_record_digest()
        );
        assert_eq!(
            cleaned.head_digest(),
            cleaned.cleaned_record_digest().unwrap()
        );
        assert!(
            !fixture
                .state
                .join(format!(
                    "{}{}",
                    super::command_output_journal::WORKING_PREFIX,
                    intent.capture_id
                ))
                .exists()
        );
        assert!(
            fixture
                .state
                .join(format!(
                    "{}{}",
                    super::command_output_journal::JOURNAL_PREFIX,
                    intent.capture_id
                ))
                .is_dir(),
            "cleanup proof journal must outlive removable working files"
        );
        assert_eq!(
            store.reopen_capture(&intent.capture_id).unwrap().state(),
            super::CommandOutputCaptureJournalStateV1::Cleaned
        );
    }
