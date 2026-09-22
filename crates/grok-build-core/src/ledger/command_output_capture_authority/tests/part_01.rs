    use super::*;
    use crate::{CommandOutputStreamArtifactV1, CommandOutputStreamV1, EffectKind};

    fn source() -> CommandOutputArtifactSourceV1 {
        CommandOutputArtifactSourceV1 {
            sprint_id: "sprint-v27".into(),
            runner_launch_id: "launch-v27".into(),
            runner_session_id: "session-v27".into(),
            effect_id: "effect-v27".into(),
            request_digest: Digest::sha256(b"command"),
        }
    }

    fn intent() -> CommandOutputCaptureIntentV1 {
        CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(b"capture-v27").as_str(),
            source(),
            Digest::sha256(b"private-state"),
            MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES,
            10,
        )
        .expect("canonical capture intent")
    }

    #[test]
    fn current_capture_maximum_v1_has_one_exact_overflow_checked_formula() {
        assert_eq!(
            COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES_V1,
            (64 * 1024 * 2) * (400 + 1)
        );
        let largest_policy = MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES
            - COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES_V1;
        assert_eq!(
            current_command_output_capture_maximum_v1(largest_policy)
                .expect("exact immutable-store ceiling"),
            MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES
        );
        assert_eq!(
            current_command_output_capture_maximum_v1(0)
                .expect_err("zero policy ceiling is closed")
                .message(),
            "command-output policy ceiling must be greater than zero"
        );
        assert_eq!(
            current_command_output_capture_maximum_v1(largest_policy + 1)
                .expect_err("one byte beyond the store ceiling is closed")
                .message(),
            format!(
                "command-output capture ceiling {} exceeds immutable-store ceiling {}",
                MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES + 1,
                MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES
            )
        );
        assert_eq!(
            current_command_output_capture_maximum_v1(u64::MAX)
                .expect_err("addition overflow is closed")
                .message(),
            "command-output capture ceiling overflowed u64"
        );
    }

    fn acquired(intent: &CommandOutputCaptureIntentV1) -> CommandOutputCaptureAcquiredV1 {
        CommandOutputCaptureAcquiredV1::try_new(
            intent,
            expected_dispatch_claim_id(&intent.source.effect_id),
            CommandOutputCaptureStoreHeadV1 {
                generation: 1,
                record_digest: Digest::sha256(b"acquired-record"),
            },
            CommandOutputCaptureDirectoryIdentityV1 {
                device_id: 7,
                inode: 11,
                owner_uid: 501,
                mode: 0o700,
                link_count: 2,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 7,
                inode: 12,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 7,
                inode: 13,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            20,
        )
        .expect("canonical acquired anchor")
    }

    fn observation(
        intent: &CommandOutputCaptureIntentV1,
        outcome: EffectOutcome,
    ) -> EffectObservation {
        EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: "observation-v27".into(),
            effect_id: intent.source.effect_id.clone(),
            idempotency_key: "idempotency-v27".into(),
            sprint_id: intent.source.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            worker_lease: None,
            correlation_id: "correlation-v27".into(),
            kind: EffectKind::RunCommand,
            request_digest: intent.source.request_digest.clone(),
            policy_hash: Digest::sha256(b"policy"),
            input_snapshot: Digest::sha256(b"snapshot"),
            outcome,
            observed_at_unix_ms: 30,
        }
    }

    #[test]
    fn capture_ids_are_exact_lowercase_sha256_and_limits_are_hard_bounded() {
        let canonical = intent();
        assert_eq!(canonical.capture_id.len(), 64);
        let uppercase = canonical.capture_id.to_uppercase();
        assert!(
            CommandOutputCaptureIntentV1::try_new(
                uppercase,
                source(),
                Digest::sha256(b"private-state"),
                MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES,
                10,
            )
            .is_err()
        );
        assert!(
            CommandOutputCaptureIntentV1::try_new(
                Digest::sha256(b"other").as_str(),
                source(),
                Digest::sha256(b"private-state"),
                MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES + 1,
                10,
            )
            .is_err()
        );
    }

    #[test]
    fn acquired_anchor_rejects_crossed_files_claims_and_intents() {
        let intent = intent();
        let mut bad_files = acquired(&intent);
        bad_files.stderr.inode = bad_files.stdout.inode;
        assert!(bad_files.validate_against(&intent).is_err());

        let mut crossed = acquired(&intent);
        crossed.dispatch_claim_id = Digest::sha256(b"wrong-claim").as_str().to_owned();
        assert!(crossed.validate_against(&intent).is_err());
    }

    #[test]
    fn terminal_branches_are_closed_and_unknown_keeps_reconciliation_open() {
        let intent = intent();
        let acquired = acquired(&intent);
        let success = observation(
            &intent,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(b"success"),
            },
        );
        let artifacts = CommandOutputArtifactSetReferenceV1::try_new(
            intent.source.clone(),
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stdout,
                byte_length: 1,
                content_digest: Digest::sha256(b"x"),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stderr,
                byte_length: 0,
                content_digest: Digest::sha256(&[]),
            },
        )
        .expect("canonical artifacts");
        let published = CommandOutputCaptureTerminalAnchorV1::try_new(
            &intent,
            Some(&acquired),
            &success,
            CommandOutputCaptureTerminalDispositionV1::Published,
            CommandOutputCaptureStoreHeadV1 {
                generation: 2,
                record_digest: Digest::sha256(b"published-record"),
            },
            Digest::sha256(b"terminal"),
            Some(artifacts),
            40,
        )
        .expect("published terminal");
        published.validate().expect("published validates");

        let unknown = observation(
            &intent,
            EffectOutcome::Unknown {
                evidence_digest: Digest::sha256(b"unknown"),
            },
        );
        assert!(
            CommandOutputCaptureTerminalAnchorV1::try_new(
                &intent,
                Some(&acquired),
                &unknown,
                CommandOutputCaptureTerminalDispositionV1::Published,
                CommandOutputCaptureStoreHeadV1 {
                    generation: 2,
                    record_digest: Digest::sha256(b"unknown-record"),
                },
                Digest::sha256(b"unknown-terminal"),
                None,
                40,
            )
            .is_err()
        );
        CommandOutputCaptureTerminalAnchorV1::try_new(
            &intent,
            Some(&acquired),
            &unknown,
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
            CommandOutputCaptureStoreHeadV1 {
                generation: 2,
                record_digest: Digest::sha256(b"unknown-record"),
            },
            Digest::sha256(b"unknown-terminal"),
            None,
            40,
        )
        .expect("unknown reconciliation terminal");
    }

    #[test]
    fn reconciliation_expiry_is_exclusive_at_the_exact_boundary() {
        let claim = CommandOutputCaptureReconciliationClaimV1::try_new(
            Digest::sha256(b"claim").as_str(),
            Digest::sha256(b"capture-v27").as_str(),
            "owner-v27",
            1,
            None,
            100,
            200,
        )
        .expect("canonical claim");
        assert!(reconciliation_claim_is_live_at(&claim, 100));
        assert!(reconciliation_claim_is_live_at(&claim, 199));
        assert!(!reconciliation_claim_is_live_at(&claim, 200));
    }
