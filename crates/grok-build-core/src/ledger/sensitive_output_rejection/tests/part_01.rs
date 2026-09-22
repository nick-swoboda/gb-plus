    use super::*;

    fn fixed_acquisition_prefix_vector() -> (
        String,
        CommandOutputCaptureAcquiredV1,
        SensitiveOutputDetectionPolicyReferenceV1,
    ) {
        const DISPATCH_CLAIM_ID: &str =
            "40c29436c71bffe6a01f2d81545cded98f50d149db8554c8ca187b3fca2c5cc7";
        let capture_id = Digest::sha256(b"v36-golden-capture").to_string();
        let intent = CommandOutputCaptureIntentV1::try_new(
            capture_id.clone(),
            crate::CommandOutputArtifactSourceV1 {
                sprint_id: "sprint-v36-golden".into(),
                runner_launch_id: "launch-v36-golden".into(),
                runner_session_id: "session-v36-golden".into(),
                effect_id: "effect-v36-golden".into(),
                request_digest: Digest::sha256(b"request-v36-golden"),
            },
            Digest::sha256(b"private-state-v36-golden"),
            4_096,
            100,
        )
        .expect("construct fixed golden capture intent");
        assert_eq!(
            super::super::command_output_capture_authority::expected_dispatch_claim_id(
                &intent.source.effect_id,
            ),
            DISPATCH_CLAIM_ID,
            "hard-coded dispatch identity is independently frozen",
        );
        let acquired = CommandOutputCaptureAcquiredV1::try_new(
            &intent,
            DISPATCH_CLAIM_ID,
            CommandOutputCaptureStoreHeadV1 {
                generation: 2,
                record_digest: Digest::sha256(b"store-head-v36-golden"),
            },
            crate::CommandOutputCaptureDirectoryIdentityV1 {
                device_id: 42,
                inode: 100,
                owner_uid: 501,
                mode: 0o700,
                link_count: 2,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 42,
                inode: 101,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 42,
                inode: 102,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            200,
        )
        .expect("construct fixed golden capture acquisition");
        (
            format!("sensitive-output-journal-v2-{capture_id}"),
            acquired,
            SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
        )
    }

    #[test]
    fn detector_policy_digest_authenticates_exact_ordered_public_grammar() {
        let expected = [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "XAI_API_KEY=",
            "OPENAI_API_KEY=",
            "ANTHROPIC_API_KEY=",
            "AWS_SECRET_ACCESS_KEY=",
            "gb-secret-canary-",
        ];
        assert_eq!(
            SensitiveOutputDetectionPolicyReferenceV1::public_literal_markers_v1(),
            expected
        );
        assert!(!expected.contains(&"sk-"));

        let canonical = SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        assert_eq!(
            canonical.policy_digest,
            compute_policy_digest(POLICY_ID, 1, &expected)
        );
        let mut reordered = expected;
        reordered.swap(0, 1);
        assert_ne!(
            canonical.policy_digest,
            compute_policy_digest(POLICY_ID, 1, &reordered)
        );
        let mut changed = expected;
        changed[8] = "gb-secret-canary-v2-";
        assert_ne!(
            canonical.policy_digest,
            compute_policy_digest(POLICY_ID, 1, &changed)
        );
        assert_ne!(
            canonical.policy_digest,
            compute_policy_digest(POLICY_ID, 1, &expected[..8])
        );
        assert_ne!(
            canonical.policy_digest,
            compute_policy_digest("gb.sensitive-output-detector.v2", 1, &expected)
        );
        assert_ne!(
            canonical.policy_digest,
            compute_policy_digest(POLICY_ID, 2, &expected)
        );
    }

    #[test]
    fn acquisition_prefix_golden_vector_matches_frozen_runner_digest_bytes() {
        let (journal_id, acquired, detector_policy) = fixed_acquisition_prefix_vector();
        let heads = derive_sensitive_output_acquisition_journal_heads_v2(
            &journal_id,
            &acquired.capture_id,
            &acquired.source.runner_session_id,
            &acquired.source.effect_id,
            &acquired.source.request_digest,
            &acquired.intent_digest,
            &detector_policy,
            &acquired,
        )
        .expect("derive fixed core-owned acquisition prefix");
        assert_eq!(heads[0].generation, 1);
        assert_eq!(heads[1].generation, 2);
        assert_eq!(
            heads[0].record_digest.as_str(),
            "fd3c3f145698503cf029b3f28b032ffb49b920a9451189384ecaaaa58be7d8fe",
        );
        assert_eq!(
            heads[1].record_digest.as_str(),
            "eb57c8422e32309ddaeafca8de7bdb89cede5266ea7b65d4482c04a852c9312a",
        );
    }
