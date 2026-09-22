    use std::path::PathBuf;

    use grok_build_core::Digest;
    use grok_build_providers::{ProviderToolCall, ProviderToolIntent, ProviderToolOutput};
    use grok_build_runner::RunnerResponse;

    use super::{WalkingSkeletonTaskEffectOutcome, adapt_provider_response};

    #[test]
    fn native_adapter_preserves_the_complete_file_mutation_receipt() {
        let input_snapshot = Digest::sha256(b"adapter-input-snapshot");
        let result_snapshot = Digest::sha256(b"adapter-result-snapshot");
        let contents = b"adapter result bytes".to_vec();
        let result_digest = Digest::sha256(&contents);
        let call = ProviderToolCall {
            sprint_id: "adapter-sprint".into(),
            task_id: "adapter-task".into(),
            sequence: 1,
            call_id: "adapter-call".into(),
            idempotency_key: "adapter-key".into(),
            intent: ProviderToolIntent::CreateRegularFile {
                path: PathBuf::from("docs/adapter.txt"),
                contents,
            },
        };
        let adapted = adapt_provider_response(
            &call,
            &RunnerResponse::FileMutated {
                path: "docs/adapter.txt".into(),
                input_snapshot: input_snapshot.clone(),
                result_snapshot: result_snapshot.clone(),
                previous_digest: None,
                result_digest: Some(result_digest.clone()),
            },
        )
        .expect("adapt exact native mutation response");
        let receipt = adapted
            .mutation_receipt
            .expect("retain the complete mutation receipt");
        assert_eq!(receipt.path, PathBuf::from("docs/adapter.txt"));
        assert_eq!(receipt.input_snapshot, input_snapshot);
        assert_eq!(receipt.result_snapshot, result_snapshot);
        assert_eq!(receipt.previous_digest, None);
        assert_eq!(receipt.result_digest, Some(result_digest.clone()));
        assert!(matches!(
            adapted.outcome,
            WalkingSkeletonTaskEffectOutcome::Succeeded(result)
                if matches!(
                    &result.output,
                    ProviderToolOutput::RegularFileCreated { result_hash, .. }
                        if result_hash == &result_digest
                )
        ));
    }
