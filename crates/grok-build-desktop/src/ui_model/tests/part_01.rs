    use super::*;
    use std::path::PathBuf;

    use grok_build_core::{
        AgentEvent, ApplicationReceipt, ApplicationValidationEvidence, CONTRACT_VERSION,
        CommandOutputArtifactSetReferenceV1, CommandOutputArtifactSourceV1,
        CommandOutputStreamArtifactV1, CommandOutputStreamV1, CommandSpec, CommandTerminationV1,
        CompletionLiveStateCaptureAuthority, CompletionReceipt, DescriptorRelativeManifestEntry,
        DescriptorRelativeWorkspaceManifest, FinalReport, LiveStateCaptureBranch,
        LiveStateCaptureEvidence, LiveStateCaptureReceipt, LiveStateDriftBlockedProof,
        NonSuccessTerminalState, PathScope, PersistedTerminalOutcome, PersistedTerminalProof,
        PreV24CompletionLiveStateCaptureExemption, RollbackReference, RollbackReferenceEvidence,
        RunnerLaunchIntent, RunnerSessionPolicyRecord, SprintTerminalEvidence,
        TaskIntegrationReceipt, VerificationEffectEvidence, VerificationReceipt,
        VerifiedNoOpReceipt, WorkerCleanupBackend, WorkerCleanupEvidence, WorkerCleanupReceipt,
        WorkerLease,
    };

    fn digest(byte: u8) -> Digest {
        Digest::sha256(&[byte])
    }

    fn launch(
        launch_id: &str,
        session_id: &str,
        purpose: RunnerSessionPurpose,
        policy_hash: Digest,
    ) -> RunnerLaunchIntent {
        RunnerLaunchIntent {
            contract_version: CONTRACT_VERSION,
            launch_id: launch_id.into(),
            sprint_id: "sprint-1".into(),
            session_id: session_id.into(),
            purpose,
            worker_id: None,
            worker_lease: None,
            policy_hash,
            runner_binary_digest: digest(20),
            protocol_digest: digest(21),
            private_state_digest: digest(22),
            grant_hash: digest(1),
            policy_version: 1,
            created_at_unix_ms: 10,
        }
    }

    fn session(launch: &RunnerLaunchIntent) -> RunnerSessionPolicyRecord {
        RunnerSessionPolicyRecord {
            contract_version: CONTRACT_VERSION,
            sprint_id: launch.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: launch.session_id.clone(),
            purpose: launch.purpose,
            worker_id: launch.worker_id.clone(),
            worker_lease: launch.worker_lease.clone(),
            policy_hash: launch.policy_hash.clone(),
            session_nonce: digest(23),
            runner_binary_digest: launch.runner_binary_digest.clone(),
            protocol_digest: launch.protocol_digest.clone(),
            private_state_digest: launch.private_state_digest.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            registered_at_unix_ms: 11,
        }
    }

    fn cleanup(
        receipt_id: &str,
        launch: &RunnerLaunchIntent,
        backend: WorkerCleanupBackend,
        cleaned_at_unix_ms: u64,
    ) -> WorkerCleanupEvidence {
        let bytes = format!("zero descendants for {}", launch.launch_id).into_bytes();
        WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: receipt_id.into(),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                effect_id: format!("effect-{receipt_id}"),
                observation_id: format!("observation-{receipt_id}"),
                session_id: launch.session_id.clone(),
                worker_lease: launch.worker_lease.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: backend,
                os_evidence_digest: Digest::sha256(&bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms,
            },
            os_evidence_bytes: bytes,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture retains the complete terminal/capture/cleanup proof so UI action derivation cannot be tested from a partial mock"
    )]
    fn live_state_drift_terminal() -> PersistedTerminalOutcome {
        let sprint_id = "sprint-1";
        let record_id = "terminal-live-state-drift";
        let grant_hash = digest(1);
        let policy_hash = digest(2);
        let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            grant_hash.clone(),
            30,
            40,
            Vec::new(),
        )
        .expect("construct drift manifest");
        let observed_snapshot = manifest.manifest_digest.clone();
        let expected_snapshot = digest(99);
        assert_ne!(expected_snapshot, observed_snapshot);
        let branch = LiveStateCaptureBranch::VerifiedNoOp {
            final_verification_receipt_id: "verification-final".into(),
            task_integration_receipt_id: "integration-empty".into(),
        };
        let capture_evidence = LiveStateCaptureEvidence {
            contract_version: CONTRACT_VERSION,
            receipt: LiveStateCaptureReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: "capture-drift".into(),
                admission_id: "capture-admission".into(),
                effect_id: "capture-effect".into(),
                observation_id: "capture-observation".into(),
                dispatch_claim_id: "capture-claim".into(),
                sprint_id: sprint_id.into(),
                plan_id: "capture-plan".into(),
                plan_digest: digest(3),
                request_digest: digest(4),
                branch: branch.clone(),
                expected_snapshot: expected_snapshot.clone(),
                observed_snapshot: observed_snapshot.clone(),
                runner_launch_id: "launch-live-state".into(),
                runner_session_id: "session-live-state".into(),
                policy_hash: policy_hash.clone(),
                grant_hash: grant_hash.clone(),
                policy_version: 1,
                manifest_digest: observed_snapshot.clone(),
                capture_started_at_unix_ms: 30,
                captured_at_unix_ms: 40,
            },
            manifest,
        };
        capture_evidence.validate().expect("valid drift capture");
        let verifier_launch = launch(
            "launch-live-state",
            "session-live-state",
            RunnerSessionPurpose::LiveStateVerifier,
            policy_hash.clone(),
        );
        let verifier_cleanup_evidence = cleanup(
            "cleanup-live-state",
            &verifier_launch,
            WorkerCleanupBackend::LinuxCgroupV2,
            50,
        );
        let evidence = SprintTerminalEvidence {
            contract_version: CONTRACT_VERSION,
            record_id: record_id.into(),
            sprint_id: sprint_id.into(),
            state: NonSuccessTerminalState::Blocked,
            reason: "The selected live-state capture differs from the completion snapshot.".into(),
            terminal_at_unix_ms: 60,
        };
        let evidence_bytes = serde_json::to_vec(&evidence).expect("encode terminal evidence");
        let evidence_digest = Digest::sha256(&evidence_bytes);
        let capture_evidence_bytes =
            serde_json::to_vec(&capture_evidence).expect("encode capture evidence");
        let proof = LiveStateDriftBlockedProof {
            contract_version: CONTRACT_VERSION,
            sprint_id: sprint_id.into(),
            terminal_record_id: record_id.into(),
            terminal_evidence_digest: evidence_digest.clone(),
            branch,
            capture_receipt_id: capture_evidence.receipt.receipt_id.clone(),
            capture_admission_id: capture_evidence.receipt.admission_id.clone(),
            capture_plan_id: capture_evidence.receipt.plan_id.clone(),
            capture_plan_digest: capture_evidence.receipt.plan_digest.clone(),
            capture_effect_id: capture_evidence.receipt.effect_id.clone(),
            capture_observation_id: capture_evidence.receipt.observation_id.clone(),
            capture_dispatch_claim_id: capture_evidence.receipt.dispatch_claim_id.clone(),
            runner_launch_id: capture_evidence.receipt.runner_launch_id.clone(),
            runner_session_id: capture_evidence.receipt.runner_session_id.clone(),
            capture_evidence_digest: Digest::sha256(&capture_evidence_bytes),
            expected_snapshot: expected_snapshot.clone(),
            observed_snapshot: observed_snapshot.clone(),
            manifest_digest: observed_snapshot,
            grant_hash,
            policy_hash,
            policy_version: 1,
            verifier_cleanup_receipt_id: verifier_cleanup_evidence.receipt.receipt_id.clone(),
            required_cleanup_set_digest: digest(5),
            capture_started_at_unix_ms: 30,
            captured_at_unix_ms: 40,
            verifier_cleaned_at_unix_ms: 50,
            blocked_at_unix_ms: 60,
        };
        proof.validate().expect("valid drift blocked proof");
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: 1,
            event_id: record_id.into(),
            sprint_id: sprint_id.into(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: record_id.into(),
            policy_hash: None,
            occurred_at_unix_ms: 60,
            payload: AgentEventKind::SprintTerminalRecorded {
                record_id: record_id.into(),
                state: NonSuccessTerminalState::Blocked,
                evidence_digest: evidence_digest.clone(),
            },
        };
        event.validate().expect("valid terminal event");
        PersistedTerminalOutcome {
            evidence,
            evidence_bytes,
            evidence_digest,
            event,
            terminal_state: SprintState::Blocked,
            proof: PersistedTerminalProof::LiveStateDriftBlocked {
                proof: Box::new(proof),
                capture_evidence: Box::new(capture_evidence),
                verifier_cleanup_evidence: Box::new(verifier_cleanup_evidence),
            },
        }
    }

    fn verification(
        snapshot_id: Digest,
        launch: &RunnerLaunchIntent,
    ) -> VerificationEffectEvidence {
        let stdout = b"verification passed\n".to_vec();
        let command = CommandSpec {
            program: "verify".into(),
            arguments: Vec::new(),
            working_directory: PathBuf::new(),
        };
        let request_digest = Digest::sha256(
            &serde_json::to_vec(&command).expect("encode verification fixture command"),
        );
        let output_artifacts = CommandOutputArtifactSetReferenceV1::try_new(
            CommandOutputArtifactSourceV1 {
                sprint_id: launch.sprint_id.clone(),
                runner_launch_id: launch.launch_id.clone(),
                runner_session_id: launch.session_id.clone(),
                effect_id: "effect-verify-final".into(),
                request_digest,
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stdout,
                byte_length: u64::try_from(stdout.len()).expect("fixture output length fits u64"),
                content_digest: Digest::sha256(&stdout),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stderr,
                byte_length: 0,
                content_digest: Digest::sha256(&[]),
            },
        )
        .expect("construct verification fixture output artifacts");
        let output_evidence_bytes = output_artifacts
            .output_evidence_bytes()
            .expect("reconstruct verification fixture output evidence");
        VerificationEffectEvidence {
            contract_version: CONTRACT_VERSION,
            verification: VerificationReceipt {
                receipt_id: "verification-final".into(),
                sprint_id: "sprint-1".into(),
                task_id: None,
                snapshot_id,
                command,
                policy_hash: launch.policy_hash.clone(),
                exit_status: Some(0),
                termination: Some(CommandTerminationV1::Exited { code: 0 }),
                output_digest: Digest::sha256(&output_evidence_bytes),
                duration_ms: 5,
                finished_at_unix_ms: 30,
            },
            effect_id: "effect-verify-final".into(),
            observation_id: "observation-verify-final".into(),
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: launch.session_id.clone(),
            output_artifacts: Some(output_artifacts),
            output_evidence_bytes,
        }
    }

    fn completion() -> PersistedCompletion {
        let final_launch = launch(
            "launch-final",
            "session-final",
            RunnerSessionPurpose::FinalVerifier,
            digest(3),
        );
        let final_session = session(&final_launch);
        let final_verification_evidence = verification(digest(2), &final_launch);
        let final_verification = final_verification_evidence.verification.clone();
        let cleanup = cleanup(
            "cleanup-final",
            &final_launch,
            WorkerCleanupBackend::MacOsDedicatedIdentity,
            40,
        );
        let no_op = VerifiedNoOpReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "noop-1".into(),
            sprint_id: "sprint-1".into(),
            final_verification_receipt_id: final_verification.receipt_id.clone(),
            base_snapshot: digest(2),
            live_manifest_digest: digest(2),
            grant_hash: digest(1),
            policy_version: 1,
            observed_at_unix_ms: 50,
        };
        let body = "All acceptance conditions passed.";
        let receipt = CompletionReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "receipt-1".into(),
            sprint_id: "sprint-1".into(),
            grant_hash: digest(1),
            policy_version: 1,
            final_snapshot: digest(2),
            final_verification_receipt_id: final_verification.receipt_id.clone(),
            application: CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id: no_op.receipt_id.clone(),
            },
            worker_cleanup_receipt_ids: vec![cleanup.receipt.receipt_id.clone()],
            satisfied_criterion_ids: vec!["accept-1".into()],
            criterion_evidence_receipt_ids: vec!["acceptance-receipt-1".into()],
            task_integration_receipt_ids: Vec::new(),
            verification_receipts: vec![final_verification.receipt_id.clone()],
            provider_backend: "fake".into(),
            provider_model: "deterministic-v1".into(),
            final_report_id: "report-1".into(),
            completed_at_unix_ms: 70,
        };
        let completion_receipt_wire_digest = legacy_completion_receipt_wire_digest(&receipt);
        let live_state_authority = PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(
            PreV24CompletionLiveStateCaptureExemption {
                sprint_id: receipt.sprint_id.clone(),
                completion_receipt_id: receipt.receipt_id.clone(),
                completion_event_id: "completion-event-1".into(),
                completion_receipt_digest: completion_receipt_wire_digest.clone(),
                terminal_at_unix_ms: receipt.completed_at_unix_ms,
                contract_version: receipt.contract_version,
                marked_at_schema_version: 24,
            },
        );
        PersistedCompletion {
            final_report: FinalReport {
                report_id: "report-1".into(),
                sprint_id: "sprint-1".into(),
                final_snapshot: digest(2),
                content_digest: FinalReport::digest_body(body),
                body: body.into(),
                created_at_unix_ms: 60,
            },
            receipt,
            completion_receipt_wire_digest,
            final_verification,
            verification_evidence: vec![final_verification_evidence],
            task_integrations: Vec::new(),
            application: PersistedCompletionApplication::VerifiedNoOp(no_op),
            live_state_authority,
            worker_cleanup_evidence: vec![cleanup],
            runner_sessions: vec![final_session],
            runner_launches: vec![final_launch],
            event: AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: 8,
                event_id: "completion-event-1".into(),
                sprint_id: "sprint-1".into(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: "sprint-1".into(),
                policy_hash: None,
                occurred_at_unix_ms: 70,
                payload: AgentEventKind::CompletionRecorded("receipt-1".into()),
            },
            terminal_state: SprintState::Completed,
        }
    }

    #[derive(serde::Serialize)]
    struct LegacyCompletionReceiptWire<'a> {
        contract_version: u32,
        receipt_id: &'a str,
        sprint_id: &'a str,
        grant_hash: &'a Digest,
        policy_version: u32,
        final_snapshot: &'a Digest,
        final_verification_receipt_id: &'a str,
        application: &'a CompletionApplication,
        worker_cleanup_receipt_ids: &'a [String],
        passed_acceptance_criteria: &'a [String],
        acceptance_receipts: &'a [String],
        task_integration_receipt_ids: &'a [String],
        verification_receipts: &'a [String],
        provider_backend: &'a str,
        provider_model: &'a str,
        final_report_id: &'a str,
        completed_at_unix_ms: u64,
    }

    fn legacy_completion_receipt_wire_digest(receipt: &CompletionReceipt) -> Digest {
        let wire = LegacyCompletionReceiptWire {
            contract_version: receipt.contract_version,
            receipt_id: &receipt.receipt_id,
            sprint_id: &receipt.sprint_id,
            grant_hash: &receipt.grant_hash,
            policy_version: receipt.policy_version,
            final_snapshot: &receipt.final_snapshot,
            final_verification_receipt_id: &receipt.final_verification_receipt_id,
            application: &receipt.application,
            worker_cleanup_receipt_ids: &receipt.worker_cleanup_receipt_ids,
            passed_acceptance_criteria: &receipt.satisfied_criterion_ids,
            acceptance_receipts: &receipt.criterion_evidence_receipt_ids,
            task_integration_receipt_ids: &receipt.task_integration_receipt_ids,
            verification_receipts: &receipt.verification_receipts,
            provider_backend: &receipt.provider_backend,
            provider_model: &receipt.provider_model,
            final_report_id: &receipt.final_report_id,
            completed_at_unix_ms: receipt.completed_at_unix_ms,
        };
        let bytes = serde_json::to_vec(&wire).expect("serialize legacy completion receipt wire");
        Digest::sha256(&bytes)
    }

    fn refresh_migration_exemption(completion: &mut PersistedCompletion) {
        completion.completion_receipt_wire_digest =
            legacy_completion_receipt_wire_digest(&completion.receipt);
        let PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(exemption) =
            &mut completion.live_state_authority
        else {
            panic!("fixture must carry a pre-v24 exemption")
        };
        exemption.sprint_id = completion.receipt.sprint_id.clone();
        exemption.completion_receipt_id = completion.receipt.receipt_id.clone();
        exemption.completion_event_id = completion.event.event_id.clone();
        exemption.completion_receipt_digest = completion.completion_receipt_wire_digest.clone();
        exemption.terminal_at_unix_ms = completion.receipt.completed_at_unix_ms;
        exemption.contract_version = completion.receipt.contract_version;
    }

    fn install_linked_authority(
        completion: &mut PersistedCompletion,
        manifest: DescriptorRelativeWorkspaceManifest,
        branch: LiveStateCaptureBranch,
        application: CompletionLiveStateApplicationLink,
        verifier_cleanup: &WorkerCleanupEvidence,
    ) {
        completion.completion_receipt_wire_digest = completion
            .receipt
            .receipt_digest()
            .expect("current completion receipt wire digest");
        let verifier_launch = completion
            .runner_launches
            .iter()
            .find(|launch| launch.launch_id == verifier_cleanup.receipt.launch_id)
            .expect("live-state verifier launch");
        let capture_receipt = LiveStateCaptureReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "capture-receipt-current".into(),
            admission_id: "capture-admission-current".into(),
            effect_id: "capture-effect-current".into(),
            observation_id: "capture-observation-current".into(),
            dispatch_claim_id: "capture-claim-current".into(),
            sprint_id: completion.receipt.sprint_id.clone(),
            plan_id: "capture-plan-current".into(),
            plan_digest: digest(31),
            request_digest: digest(32),
            branch,
            expected_snapshot: completion.receipt.final_snapshot.clone(),
            observed_snapshot: manifest.manifest_digest.clone(),
            runner_launch_id: verifier_launch.launch_id.clone(),
            runner_session_id: verifier_launch.session_id.clone(),
            policy_hash: verifier_launch.policy_hash.clone(),
            grant_hash: completion.receipt.grant_hash.clone(),
            policy_version: completion.receipt.policy_version,
            manifest_digest: manifest.manifest_digest.clone(),
            capture_started_at_unix_ms: manifest.capture_started_at_unix_ms,
            captured_at_unix_ms: manifest.captured_at_unix_ms,
        };
        let capture_evidence = LiveStateCaptureEvidence {
            contract_version: CONTRACT_VERSION,
            receipt: capture_receipt.clone(),
            manifest,
        };
        capture_evidence.validate().expect("valid capture evidence");
        let link = CompletionLiveStateCaptureLink {
            contract_version: CONTRACT_VERSION,
            sprint_id: completion.receipt.sprint_id.clone(),
            completion_receipt_id: completion.receipt.receipt_id.clone(),
            completion_receipt_digest: completion.completion_receipt_wire_digest.clone(),
            final_snapshot: completion.receipt.final_snapshot.clone(),
            grant_hash: completion.receipt.grant_hash.clone(),
            policy_hash: capture_receipt.policy_hash.clone(),
            policy_version: completion.receipt.policy_version,
            final_verification_receipt_id: completion.receipt.final_verification_receipt_id.clone(),
            application,
            capture: CompletionLiveStateCaptureAuthority {
                capture_receipt_id: capture_receipt.receipt_id.clone(),
                admission_id: capture_receipt.admission_id.clone(),
                plan_id: capture_receipt.plan_id.clone(),
                plan_digest: capture_receipt.plan_digest.clone(),
                effect_id: capture_receipt.effect_id.clone(),
                observation_id: capture_receipt.observation_id.clone(),
                dispatch_claim_id: capture_receipt.dispatch_claim_id.clone(),
                runner_launch_id: capture_receipt.runner_launch_id.clone(),
                runner_session_id: capture_receipt.runner_session_id.clone(),
                expected_snapshot: capture_receipt.expected_snapshot.clone(),
                observed_snapshot: capture_receipt.observed_snapshot.clone(),
                manifest_digest: capture_receipt.manifest_digest.clone(),
            },
            verifier_cleanup_receipt_id: verifier_cleanup.receipt.receipt_id.clone(),
            capture_started_at_unix_ms: capture_receipt.capture_started_at_unix_ms,
            captured_at_unix_ms: capture_receipt.captured_at_unix_ms,
            verifier_cleaned_at_unix_ms: verifier_cleanup.receipt.cleaned_at_unix_ms,
            completed_at_unix_ms: completion.receipt.completed_at_unix_ms,
        };
        link.validate().expect("valid completion capture link");
        completion.live_state_authority = PersistedCompletionLiveStateAuthority::Linked {
            link,
            capture_evidence,
            verifier_cleanup_evidence: verifier_cleanup.clone(),
        };
    }

    #[allow(clippy::too_many_lines)] // Builds one complete linked no-op proof fixture explicitly.
    fn linked_no_op_completion() -> PersistedCompletion {
        let mut completion = completion();
        let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            digest(1),
            50,
            51,
            Vec::new(),
        )
        .expect("empty live manifest");
        let final_snapshot = manifest.manifest_digest.clone();

        completion.receipt.final_snapshot = final_snapshot.clone();
        completion.final_report.final_snapshot = final_snapshot.clone();
        completion.final_verification.snapshot_id = final_snapshot.clone();
        completion.verification_evidence[0].verification.snapshot_id = final_snapshot.clone();
        let PersistedCompletionApplication::VerifiedNoOp(no_op) = &mut completion.application
        else {
            panic!("no-op fixture")
        };
        no_op.base_snapshot = final_snapshot.clone();
        no_op.live_manifest_digest = final_snapshot.clone();
        no_op.observed_at_unix_ms = 51;

        let lease = WorkerLease::new(
            "sprint-1".into(),
            1,
            "task-1".into(),
            "worker-1".into(),
            vec![PathScope::Workspace],
            5,
        )
        .expect("task lease");
        let mut task_launch = launch(
            "launch-aaa-task",
            "session-aaa-task",
            RunnerSessionPurpose::TaskWorker,
            digest(7),
        );
        task_launch.worker_id = Some("worker-1".into());
        task_launch.worker_lease = Some(lease.clone());
        let task_session = session(&task_launch);
        let task_cleanup = cleanup(
            "cleanup-aaa-task",
            &task_launch,
            WorkerCleanupBackend::MacOsDedicatedIdentity,
            25,
        );
        let integration = TaskIntegrationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "integration-task-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            worker_id: "worker-1".into(),
            worker_lease: Some(lease),
            worker_launch_id: task_launch.launch_id.clone(),
            worker_session_id: task_session.session_id.clone(),
            worker_policy_hash: task_session.policy_hash.clone(),
            effect_id: "effect-integration-task-1".into(),
            observation_id: "observation-integration-task-1".into(),
            change_set_id: "change-set-empty-task-1".into(),
            input_snapshot: final_snapshot.clone(),
            result_snapshot: final_snapshot.clone(),
            task_verification_receipt_ids: Vec::new(),
            integration_ordinal: 0,
            integrated_at_unix_ms: 20,
        };
        integration.validate().expect("valid task integration");

        let mut live_launch = launch(
            "launch-zzz-live",
            "session-zzz-live",
            RunnerSessionPurpose::LiveStateVerifier,
            digest(13),
        );
        live_launch.created_at_unix_ms = 45;
        let mut live_session = session(&live_launch);
        live_session.registered_at_unix_ms = 46;
        let live_cleanup = cleanup(
            "cleanup-zzz-live",
            &live_launch,
            WorkerCleanupBackend::MacOsDedicatedIdentity,
            55,
        );

        completion.task_integrations = vec![integration];
        completion.receipt.task_integration_receipt_ids = vec!["integration-task-1".into()];
        completion.receipt.worker_cleanup_receipt_ids = vec![
            task_cleanup.receipt.receipt_id.clone(),
            completion.worker_cleanup_evidence[0]
                .receipt
                .receipt_id
                .clone(),
            live_cleanup.receipt.receipt_id.clone(),
        ];
        completion.runner_launches = vec![
            task_launch,
            completion.runner_launches.remove(0),
            live_launch,
        ];
        completion.runner_sessions = vec![
            task_session,
            completion.runner_sessions.remove(0),
            live_session,
        ];
        completion.worker_cleanup_evidence = vec![
            task_cleanup,
            completion.worker_cleanup_evidence.remove(0),
            live_cleanup.clone(),
        ];

        install_linked_authority(
            &mut completion,
            manifest,
            LiveStateCaptureBranch::VerifiedNoOp {
                final_verification_receipt_id: "verification-final".into(),
                task_integration_receipt_id: "integration-task-1".into(),
            },
            CompletionLiveStateApplicationLink::VerifiedNoOp {
                verified_no_op_receipt_id: "noop-1".into(),
                task_integration_receipt_id: "integration-task-1".into(),
            },
            &live_cleanup,
        );
        completion
    }

    fn linked_applied_completion() -> PersistedCompletion {
        let mut completion = applied_completion();
        let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            digest(1),
            61,
            62,
            vec![DescriptorRelativeManifestEntry {
                path: "report.txt".into(),
                content_digest: digest(40),
                byte_length: 1,
                unix_mode: 0o644,
            }],
        )
        .expect("applied live manifest");
        let final_snapshot = manifest.manifest_digest.clone();
        completion.receipt.final_snapshot = final_snapshot.clone();
        completion.final_report.final_snapshot = final_snapshot.clone();
        completion.final_report.created_at_unix_ms = 66;
        completion.final_verification.snapshot_id = final_snapshot.clone();
        completion.verification_evidence[0].verification.snapshot_id = final_snapshot.clone();
        let PersistedCompletionApplication::Applied {
            application_evidence,
            rollback_reference,
        } = &mut completion.application
        else {
            panic!("applied fixture")
        };
        application_evidence.receipt.result_snapshot = final_snapshot;
        rollback_reference.reference.journal_binding_digest = application_evidence
            .receipt
            .journal_binding_digest()
            .expect("updated application journal binding");
        completion.worker_cleanup_evidence[0]
            .receipt
            .cleaned_at_unix_ms = 60;

        let mut live_launch = launch(
            "launch-live",
            "session-live",
            RunnerSessionPurpose::LiveStateVerifier,
            digest(13),
        );
        live_launch.created_at_unix_ms = 60;
        let mut live_session = session(&live_launch);
        live_session.registered_at_unix_ms = 60;
        let live_cleanup = cleanup(
            "cleanup-live",
            &live_launch,
            WorkerCleanupBackend::LinuxCgroupV2,
            65,
        );
        completion
            .receipt
            .worker_cleanup_receipt_ids
            .push(live_cleanup.receipt.receipt_id.clone());
        completion.runner_launches.push(live_launch);
        completion.runner_sessions.push(live_session);
        completion
            .worker_cleanup_evidence
            .push(live_cleanup.clone());

        install_linked_authority(
            &mut completion,
            manifest,
            LiveStateCaptureBranch::Applied {
                final_verification_receipt_id: "verification-final".into(),
                application_receipt_id: "application-1".into(),
                rollback_reference_id: "rollback-reference-1".into(),
            },
            CompletionLiveStateApplicationLink::Applied {
                application_receipt_id: "application-1".into(),
                rollback_reference_id: "rollback-reference-1".into(),
            },
            &live_cleanup,
        );
        completion
    }

    fn applied_completion() -> PersistedCompletion {
        let mut completion = completion();
        let applier_launch = launch(
            "launch-applier",
            "session-applier",
            RunnerSessionPurpose::Applier,
            digest(8),
        );
        let applier_session = session(&applier_launch);
        let applier_cleanup = cleanup(
            "cleanup-applier",
            &applier_launch,
            WorkerCleanupBackend::TrustedApplierDirectChildWait,
            65,
        );

        completion.receipt.final_snapshot = digest(4);
        completion.final_report.final_snapshot = digest(4);
        completion.final_verification.snapshot_id = digest(4);
        completion.verification_evidence[0].verification.snapshot_id = digest(4);
        let application = ApplicationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "application-1".into(),
            sprint_id: "sprint-1".into(),
            effect_id: "effect-application".into(),
            observation_id: "observation-application".into(),
            applier_session_id: applier_session.session_id.clone(),
            transaction_id: "transaction-1".into(),
            change_set_id: "changes-1".into(),
            base_snapshot: digest(2),
            result_snapshot: digest(4),
            policy_hash: applier_session.policy_hash.clone(),
            grant_hash: digest(1),
            policy_version: 1,
            applied_operations_digest: digest(9),
            touched_path_endpoints_digest: digest(10),
            live_manifest_digest: digest(11),
            applied_at_unix_ms: 50,
        };
        let artifacts = b"reopened rollback artifacts".to_vec();
        let reference = RollbackReference {
            contract_version: CONTRACT_VERSION,
            reference_id: "rollback-reference-1".into(),
            sprint_id: "sprint-1".into(),
            application_receipt_id: application.receipt_id.clone(),
            transaction_id: application.transaction_id.clone(),
            journal_binding_digest: application
                .journal_binding_digest()
                .expect("journal binding"),
            base_snapshot: application.base_snapshot.clone(),
            touched_target_set_digest: digest(12),
            reopened_artifacts_digest: Digest::sha256(&artifacts),
            validated_at_unix_ms: 60,
        };
        completion.receipt.application = CompletionApplication::Applied {
            application_receipt_id: application.receipt_id.clone(),
            rollback_reference_id: reference.reference_id.clone(),
        };
        completion.receipt.worker_cleanup_receipt_ids = vec![
            applier_cleanup.receipt.receipt_id.clone(),
            completion.worker_cleanup_evidence[0]
                .receipt
                .receipt_id
                .clone(),
        ];
        completion.application = PersistedCompletionApplication::Applied {
            application_evidence: ApplicationEvidence {
                contract_version: CONTRACT_VERSION,
                receipt: application,
                validation: ApplicationValidationEvidence {
                    mode: ApplicationValidationMode::DirectEffectResponse,
                    runner_launch_id: applier_session.launch_id.clone(),
                    runner_session_id: applier_session.session_id.clone(),
                    policy_hash: applier_session.policy_hash.clone(),
                    grant_hash: applier_session.grant_hash.clone(),
                    policy_version: applier_session.policy_version,
                    private_state_digest: applier_session.private_state_digest.clone(),
                },
            },
            rollback_reference: RollbackReferenceEvidence {
                reference,
                reopened_artifacts_bytes: artifacts,
            },
        };
        completion.runner_launches.insert(0, applier_launch);
        completion.runner_sessions.insert(0, applier_session);
        completion
            .worker_cleanup_evidence
            .insert(0, applier_cleanup);
        refresh_migration_exemption(&mut completion);
        completion
    }

    fn recovered_applied_completion() -> PersistedCompletion {
        let mut completion = applied_completion();
        let executor = completion.runner_sessions[0].clone();
        let mut recovery_launch = completion.runner_launches[0].clone();
        recovery_launch.launch_id = "launch-recovery".into();
        recovery_launch.session_id = "session-recovery".into();
        recovery_launch.created_at_unix_ms = 45;
        let mut recovery_session = session(&recovery_launch);
        recovery_session.session_nonce = digest(24);
        recovery_session.registered_at_unix_ms = 46;
        let recovery_cleanup = cleanup(
            "cleanup-recovery",
            &recovery_launch,
            WorkerCleanupBackend::TrustedApplierDirectChildWait,
            66,
        );
        let PersistedCompletionApplication::Applied {
            application_evidence,
            ..
        } = &mut completion.application
        else {
            unreachable!("applied completion shape")
        };
        application_evidence.validation = ApplicationValidationEvidence {
            mode: ApplicationValidationMode::RecoveryApplierReconciliation,
            runner_launch_id: recovery_session.launch_id.clone(),
            runner_session_id: recovery_session.session_id.clone(),
            policy_hash: executor.policy_hash,
            grant_hash: executor.grant_hash,
            policy_version: executor.policy_version,
            private_state_digest: executor.private_state_digest,
        };
        completion
            .receipt
            .worker_cleanup_receipt_ids
            .push(recovery_cleanup.receipt.receipt_id.clone());
        completion.runner_launches.push(recovery_launch);
        completion.runner_sessions.push(recovery_session);
        completion.worker_cleanup_evidence.push(recovery_cleanup);
        refresh_migration_exemption(&mut completion);
        completion
    }

    fn acceptance() -> Vec<AcceptanceCard> {
        vec![AcceptanceCard {
            criterion_id: "accept-1".into(),
            description: "the exact fixture passes".into(),
            status: AcceptanceStatus::Verified {
                criterion_evidence_receipt_id: "criterion-evidence-receipt-1".into(),
                verification_receipt_id: "verification-receipt-1".into(),
            },
        }]
    }

    #[test]
    fn completed_banner_requires_correlated_durable_evidence() {
        assert_eq!(
            TerminalBanner::from_state(SprintState::Completed, None, None),
            Err(UiModelError::CompletionEvidenceRequired)
        );
        let completion = completion();
        let banner = TerminalBanner::from_state(SprintState::Completed, Some(&completion), None)
            .expect("build completed banner")
            .expect("terminal banner");
        assert!(banner.is_done());
        assert_eq!(banner.title(), "Completed");
        assert_eq!(banner.completion_receipt_id(), Some("receipt-1"));
        assert_eq!(banner.rollback_target(), None);
        assert_eq!(banner.verified_no_op_live_snapshot(), Some(&digest(2)));
        assert!(matches!(
            banner.completion_live_state(),
            Some(CompletionLiveState::VerifiedNoOp { .. })
        ));
    }

    #[test]
    fn pre_v28_authority_uses_exact_legacy_wire_digest_not_current_reserialization() {
        let completion = completion();
        let current_wire_digest = completion
            .receipt
            .receipt_digest()
            .expect("current receipt wire digest");
        assert_ne!(
            completion.completion_receipt_wire_digest,
            current_wire_digest
        );
        let PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(exemption) =
            &completion.live_state_authority
        else {
            panic!("legacy fixture must retain its migration exemption")
        };
        assert_eq!(
            exemption.completion_receipt_digest,
            completion.completion_receipt_wire_digest
        );
        assert!(
            TerminalBanner::from_state(SprintState::Completed, Some(&completion), None).is_ok()
        );

        let mut crossed = completion;
        crossed.completion_receipt_wire_digest = current_wire_digest;
        assert!(matches!(
            TerminalBanner::from_state(SprintState::Completed, Some(&crossed), None),
            Err(UiModelError::InvalidPersistedCompletion(reason))
                if reason.contains("pre-v24 completion exemption")
        ));
    }

    #[test]
    fn current_linked_no_op_and_applied_authority_render_done() {
        let no_op = linked_no_op_completion();
        assert_eq!(
            no_op.completion_receipt_wire_digest,
            no_op
                .receipt
                .receipt_digest()
                .expect("current no-op receipt wire digest")
        );
        let no_op_banner = TerminalBanner::from_state(SprintState::Completed, Some(&no_op), None)
            .expect("validate current no-op completion")
            .expect("current no-op banner");
        assert!(no_op_banner.is_done());
        assert_eq!(
            no_op_banner.verified_no_op_live_snapshot(),
            Some(&no_op.receipt.final_snapshot)
        );

        let applied = linked_applied_completion();
        assert_eq!(
            applied.completion_receipt_wire_digest,
            applied
                .receipt
                .receipt_digest()
                .expect("current applied receipt wire digest")
        );
        let applied_banner =
            TerminalBanner::from_state(SprintState::Completed, Some(&applied), None)
                .expect("validate current applied completion")
                .expect("current applied banner");
        assert!(applied_banner.is_done());
        assert_eq!(applied_banner.rollback_target(), Some(&digest(2)));
    }

    #[test]
    fn current_linked_authority_rejects_crossed_capture_and_cleanup_cut() {
        let mut crossed_capture = linked_no_op_completion();
        let PersistedCompletionLiveStateAuthority::Linked {
            capture_evidence, ..
        } = &mut crossed_capture.live_state_authority
        else {
            panic!("linked fixture")
        };
        capture_evidence.receipt.dispatch_claim_id = "capture-claim-crossed".into();
        assert!(matches!(
            TerminalBanner::from_state(SprintState::Completed, Some(&crossed_capture), None),
            Err(UiModelError::InvalidPersistedCompletion(reason))
                if reason.contains("live-state authority crosses")
        ));

        let mut late_prior_cleanup = linked_applied_completion();
        late_prior_cleanup.worker_cleanup_evidence[1]
            .receipt
            .cleaned_at_unix_ms = 64;
        assert!(matches!(
            TerminalBanner::from_state(SprintState::Completed, Some(&late_prior_cleanup), None),
            Err(UiModelError::InvalidPersistedCompletion(reason))
                if reason.contains("plan-prior runner cleanup")
        ));
    }

    #[test]
    fn applied_banner_uses_only_the_persisted_rollback_reference() {
        let completion = applied_completion();
        let banner = TerminalBanner::from_state(SprintState::Completed, Some(&completion), None)
            .expect("build applied banner")
            .expect("terminal banner");
        assert_eq!(banner.rollback_target(), Some(&digest(2)));
        assert_eq!(banner.verified_no_op_live_snapshot(), None);
        assert!(matches!(
            banner.completion_live_state(),
            Some(CompletionLiveState::Applied {
                rollback_reference_id,
                ..
            }) if rollback_reference_id == "rollback-reference-1"
        ));
    }

    #[test]
    fn recovered_applied_banner_requires_exact_validator_runtime_and_cleanup_ordering() {
        let completion = recovered_applied_completion();
        assert!(
            TerminalBanner::from_state(SprintState::Completed, Some(&completion), None).is_ok()
        );

        let mut crossed_binary = recovered_applied_completion();
        crossed_binary.runner_launches[2].runner_binary_digest = digest(30);
        crossed_binary.runner_sessions[2].runner_binary_digest = digest(30);
        assert!(matches!(
            TerminalBanner::from_state(SprintState::Completed, Some(&crossed_binary), None),
            Err(UiModelError::InvalidPersistedCompletion(reason))
                if reason.contains("applied completion")
        ));

        let mut early_cleanup = recovered_applied_completion();
        early_cleanup.worker_cleanup_evidence[2]
            .receipt
            .cleaned_at_unix_ms = 59;
        assert!(matches!(
            TerminalBanner::from_state(SprintState::Completed, Some(&early_cleanup), None),
            Err(UiModelError::InvalidPersistedCompletion(reason))
                if reason.contains("cleanup ordering")
        ));
    }

    #[test]
    fn completion_rejects_standalone_verification_and_missing_typed_integrations() {
        let mut standalone = completion();
        standalone.verification_evidence.clear();
        assert!(matches!(
            TerminalBanner::from_state(SprintState::Completed, Some(&standalone), None),
            Err(UiModelError::InvalidPersistedCompletion(reason))
                if reason.contains("effect-bound")
        ));

        let mut missing_integration = completion();
        missing_integration
            .receipt
            .task_integration_receipt_ids
            .push("integration-task-1".into());
        assert!(matches!(
            TerminalBanner::from_state(SprintState::Completed, Some(&missing_integration), None),
            Err(UiModelError::InvalidPersistedCompletion(reason))
                if reason.contains("typed integration")
        ));
    }

    #[test]
    fn completion_rejects_contradictory_live_state_and_terminal_evidence() {
        let mut contradiction = completion();
        contradiction.receipt.application = CompletionApplication::Applied {
            application_receipt_id: "application-1".into(),
            rollback_reference_id: "rollback-reference-1".into(),
        };
        refresh_migration_exemption(&mut contradiction);
        assert!(matches!(
            TerminalBanner::from_state(SprintState::Completed, Some(&contradiction), None),
            Err(UiModelError::InvalidPersistedCompletion(reason))
                if reason.contains("branches contradict")
        ));

        let completion = completion();
        assert_eq!(
            TerminalBanner::from_state(
                SprintState::Completed,
                Some(&completion),
                Some("not actually complete")
            ),
            Err(UiModelError::ContradictoryTerminalEvidence)
        );
    }

    #[test]
    fn every_other_terminal_state_is_unmistakably_not_done() {
        for state in [
            SprintState::Blocked,
            SprintState::Failed,
            SprintState::Canceled,
            SprintState::Unknown,
        ] {
            let banner = TerminalBanner::from_state(state, None, Some("exact reason"))
                .expect("build non-success banner")
                .expect("terminal banner");
            assert!(!banner.is_done());
            assert!(banner.title().contains("not completed"));
            assert_eq!(banner.detail(), "exact reason");
            assert_eq!(banner.completion_receipt_id(), None);
            assert_eq!(banner.completion_live_state(), None);
            assert_eq!(banner.terminal_cause(), None);
            assert_eq!(banner.safe_next_action(), None);
        }
    }

    #[test]
    fn drift_blocked_banner_derives_only_the_safe_new_sprint_action() {
        let terminal = live_state_drift_terminal();
        let banner = TerminalBanner::from_persisted_terminal(&terminal)
            .expect("derive typed drift terminal banner");

        assert_eq!(banner.state(), SprintState::Blocked);
        assert_eq!(banner.title(), "Blocked — not completed");
        assert!(!banner.is_done());
        assert_eq!(banner.completion_receipt_id(), None);
        assert_eq!(banner.completion_live_state(), None);
        assert_eq!(banner.rollback_target(), None);
        assert_eq!(
            banner.safe_next_action(),
            Some(UiSafeNextAction::StartNewSprintFromObservedWorkspace)
        );
        assert!(matches!(
            banner.terminal_cause(),
            Some(UiTerminalCause::LiveStateDrift {
                capture_receipt_id,
                expected_snapshot,
                observed_snapshot,
            }) if capture_receipt_id == "capture-drift"
                && expected_snapshot != observed_snapshot
        ));
    }

    #[test]
    fn drift_blocked_banner_rejects_crossed_capture_proof() {
        let mut terminal = live_state_drift_terminal();
        let PersistedTerminalProof::LiveStateDriftBlocked { proof, .. } = &mut terminal.proof
        else {
            panic!("drift fixture must retain typed proof")
        };
        proof.capture_receipt_id = "crossed-capture".into();

        assert!(matches!(
            TerminalBanner::from_persisted_terminal(&terminal),
            Err(UiModelError::InvalidPersistedTerminal(reason))
                if reason.contains("crosses terminal")
        ));
    }

    #[test]
    fn active_states_reject_terminal_evidence() {
        for state in [
            SprintState::Draft,
            SprintState::Planning,
            SprintState::Running,
            SprintState::AwaitingAcceptance,
            SprintState::FinalVerification,
            SprintState::Applying,
        ] {
            assert_eq!(
                TerminalBanner::from_state(state, None, Some("too early")),
                Err(UiModelError::TerminalEvidenceForActiveSprint)
            );
            assert_eq!(
                TerminalBanner::from_state(state, None, None).expect("active state"),
                None
            );
        }
    }

    #[test]
    fn frame_enforces_worker_ceiling_and_contiguous_activity() {
        let workers = (1..=4)
            .map(|index| WorkerCard {
                worker_id: format!("worker-{index}"),
                state: WorkerState::Idle,
                task_id: None,
            })
            .collect();
        assert_eq!(
            SprintFrame::new(
                "sprint-1".into(),
                "objective".into(),
                SprintState::Running,
                Vec::new(),
                workers,
                acceptance(),
                Vec::new(),
                None,
            ),
            Err(UiModelError::WorkerLimitExceeded { actual: 4 })
        );

        assert_eq!(
            SprintFrame::new(
                "sprint-1".into(),
                "objective".into(),
                SprintState::Running,
                Vec::new(),
                Vec::new(),
                acceptance(),
                vec![ActivityRow {
                    sequence: 2,
                    summary: "gap".into(),
                }],
                None,
            ),
            Err(UiModelError::ActivitySequence {
                expected: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn acceptance_words_and_accessibility_keep_machine_and_human_claims_distinct() {
        let cases = [
            (AcceptanceStatus::Pending, "Pending", false),
            (
                AcceptanceStatus::AwaitingYourDecision {
                    prompt_id: "prompt-1".into(),
                },
                "Awaiting your decision",
                false,
            ),
            (
                AcceptanceStatus::Verified {
                    criterion_evidence_receipt_id: "criterion-evidence-1".into(),
                    verification_receipt_id: "verification-1".into(),
                },
                "Verified",
                true,
            ),
            (
                AcceptanceStatus::AcceptedByYou {
                    criterion_evidence_receipt_id: "criterion-evidence-2".into(),
                    prompt_id: "prompt-2".into(),
                    decision_id: "decision-2".into(),
                },
                "Accepted by you",
                true,
            ),
            (
                AcceptanceStatus::VerificationFailed {
                    verification_receipt_id: "verification-3".into(),
                    reason: "exit 1".into(),
                },
                "Verification failed",
                false,
            ),
            (
                AcceptanceStatus::RejectedByYou {
                    prompt_id: "prompt-4".into(),
                    decision_id: "decision-4".into(),
                },
                "Rejected by you",
                false,
            ),
        ];
        for (status, label, satisfied) in cases {
            assert_eq!(status.visible_label(), label);
            assert_eq!(status.accessibility_label(), label);
            assert_eq!(status.is_satisfied(), satisfied);
            let card = AcceptanceCard {
                criterion_id: "criterion-1".into(),
                description: "exact criterion".into(),
                status,
            };
            assert_eq!(
                card.accessibility_label(),
                format!("Criterion: exact criterion. Status: {label}.")
            );
        }

        let machine = serde_json::to_string(&AcceptanceStatus::Verified {
            criterion_evidence_receipt_id: "criterion-evidence-machine".into(),
            verification_receipt_id: "verification-machine".into(),
        })
        .expect("serialize machine status");
        assert!(machine.contains("verified"));
        assert!(!machine.contains("accepted"));
        let human = serde_json::to_string(&AcceptanceStatus::AcceptedByYou {
            criterion_evidence_receipt_id: "criterion-evidence-human".into(),
            prompt_id: "prompt-human".into(),
            decision_id: "decision-human".into(),
        })
        .expect("serialize human status");
        assert!(human.contains("accepted-by-you"));
        assert!(!human.contains("verified"));
    }

    #[test]
    fn aggregate_satisfied_requires_completed_and_every_typed_success() {
        let active = SprintFrame::new(
            "sprint-1".into(),
            "objective".into(),
            SprintState::Running,
            Vec::new(),
            Vec::new(),
            acceptance(),
            Vec::new(),
            None,
        )
        .expect("active frame with machine evidence");
        assert_eq!(active.criteria_status(), CriteriaAggregateStatus::Pending);

        let awaiting = SprintFrame::new(
            "sprint-1".into(),
            "objective".into(),
            SprintState::AwaitingAcceptance,
            Vec::new(),
            Vec::new(),
            vec![AcceptanceCard {
                criterion_id: "accept-1".into(),
                description: "exact human criterion".into(),
                status: AcceptanceStatus::AwaitingYourDecision {
                    prompt_id: "prompt-1".into(),
                },
            }],
            Vec::new(),
            None,
        )
        .expect("awaiting human frame");
        assert_eq!(
            awaiting.criteria_status(),
            CriteriaAggregateStatus::AwaitingYourDecision
        );

        let failed = SprintFrame::new(
            "sprint-1".into(),
            "objective".into(),
            SprintState::Running,
            Vec::new(),
            Vec::new(),
            vec![AcceptanceCard {
                criterion_id: "accept-1".into(),
                description: "exact machine criterion".into(),
                status: AcceptanceStatus::VerificationFailed {
                    verification_receipt_id: "verification-1".into(),
                    reason: "exit 1".into(),
                },
            }],
            Vec::new(),
            None,
        )
        .expect("failed criterion frame");
        assert_eq!(
            failed.criteria_status(),
            CriteriaAggregateStatus::Unsatisfied
        );

        let completion = completion();
        let banner = TerminalBanner::from_state(SprintState::Completed, Some(&completion), None)
            .expect("completed banner")
            .expect("terminal banner");
        let completed = SprintFrame::new(
            "sprint-1".into(),
            "objective".into(),
            SprintState::Completed,
            Vec::new(),
            Vec::new(),
            acceptance(),
            Vec::new(),
            Some(banner.clone()),
        )
        .expect("completed frame with exact typed criterion evidence");
        assert_eq!(
            completed.criteria_status(),
            CriteriaAggregateStatus::Satisfied
        );

        assert_eq!(
            SprintFrame::new(
                "sprint-1".into(),
                "objective".into(),
                SprintState::Completed,
                Vec::new(),
                Vec::new(),
                vec![AcceptanceCard {
                    criterion_id: "accept-1".into(),
                    description: "exact human criterion".into(),
                    status: AcceptanceStatus::RejectedByYou {
                        prompt_id: "prompt-1".into(),
                        decision_id: "decision-1".into(),
                    },
                }],
                Vec::new(),
                Some(banner),
            ),
            Err(UiModelError::CompletedCriteriaNotSatisfied)
        );
    }

    #[test]
    fn completed_frame_cannot_omit_or_mismatch_terminal_banner() {
        assert_eq!(
            SprintFrame::new(
                "sprint-1".into(),
                "objective".into(),
                SprintState::Completed,
                Vec::new(),
                Vec::new(),
                acceptance(),
                Vec::new(),
                None,
            ),
            Err(UiModelError::TerminalBannerMismatch)
        );

        let completion = completion();
        let banner = TerminalBanner::from_state(SprintState::Completed, Some(&completion), None)
            .expect("completed banner")
            .expect("terminal");
        let frame = SprintFrame::new(
            "sprint-1".into(),
            "objective".into(),
            SprintState::Completed,
            Vec::new(),
            Vec::new(),
            acceptance(),
            Vec::new(),
            Some(banner),
        )
        .expect("completed frame");
        assert!(frame.is_done());
    }
