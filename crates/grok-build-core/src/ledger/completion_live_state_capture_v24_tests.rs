fn persist_v24_matching_live_state_capture(
    ledger: &mut EventLedger,
    attempt: &mut V23AdversarialCaptureAttempt,
    entries: Vec<crate::DescriptorRelativeManifestEntry>,
    receipt_id: &str,
    suffix: &str,
) -> LiveStateCaptureEvidence {
    let (claimed, authority) = v23_adversarial_claim(ledger, attempt);
    let (mut observation, _, mut evidence, _) =
        v23_adversarial_success_terminal(ledger, attempt, &claimed, suffix);
    let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
        attempt.plan.grant_hash.clone(),
        evidence.receipt.capture_started_at_unix_ms,
        evidence.receipt.captured_at_unix_ms,
        entries,
    )
    .expect("construct matching v24 descriptor manifest");
    assert_eq!(manifest.manifest_digest, attempt.plan.expected_snapshot);
    evidence.receipt.receipt_id = receipt_id.into();
    evidence.receipt.observed_snapshot = manifest.manifest_digest.clone();
    evidence.receipt.manifest_digest = manifest.manifest_digest.clone();
    evidence.manifest = manifest;
    evidence.validate().expect("validate matching v24 capture");

    let evidence_bytes =
        encode("v24 matching capture evidence", &evidence).expect("encode v24 capture");
    observation.outcome = EffectOutcome::Succeeded {
        evidence_digest: Digest::sha256(&evidence_bytes),
    };
    let terminal = effect_terminal_event(
        &attempt.intent,
        &attempt.proposed_event.event_id,
        &observation,
        ledger
            .next_sequence(&attempt.intent.sprint_id)
            .expect("v24 capture terminal sequence"),
        &format!("event-{suffix}-capture-finished"),
    );
    ledger
        .record_claimed_live_state_capture_observation(
            authority,
            &observation,
            &evidence,
            &terminal,
        )
        .expect("persist matching v24 capture");
    evidence
}

fn persist_v24_matching_empty_live_state_capture(
    ledger: &mut EventLedger,
    attempt: &mut V23AdversarialCaptureAttempt,
) -> LiveStateCaptureEvidence {
    persist_v24_matching_live_state_capture(
        ledger,
        attempt,
        Vec::new(),
        "receipt-v24-noop-capture",
        "v24-noop-runtime",
    )
}

fn v24_admit_capture_for_plan(
    ledger: &mut EventLedger,
    spec: &SprintSpec,
    policy: CompiledExecutionPolicy,
    plan: SprintLiveStateCapturePlan,
    suffix: &str,
) -> V23AdversarialCaptureAttempt {
    let launch = runner_launch(
        &format!("launch-{suffix}"),
        &format!("session-{suffix}"),
        RunnerSessionPurpose::LiveStateVerifier,
        None,
        &policy,
        plan.planned_at_unix_ms.saturating_add(10),
    );
    let (cleanup_intent, _, cleanup_request_bytes, cleanup_event) =
        test_runner_launch_cleanup_contracts(ledger, &launch, WorkerCleanupBackend::LinuxCgroupV2)
            .expect("build v24 LSV cleanup admission");
    ledger
        .admit_live_state_verifier_launch_with_cleanup(
            &plan,
            &launch,
            &policy,
            &cleanup_intent,
            &cleanup_request_bytes,
            &cleanup_event,
        )
        .expect("persist v24 plan and LSV launch");
    let session = runner_session(&launch, launch.created_at_unix_ms.saturating_add(10));
    ledger
        .register_live_state_verifier_session(&plan, &session, &policy)
        .expect("register v24 LSV session");
    let request = SprintLiveStateCaptureRequest::from_plan(plan.clone())
        .expect("construct v24 capture request");
    let request_bytes = encode("v24 capture request", &request).expect("encode v24 request");
    let admitted_at_unix_ms = session.registered_at_unix_ms.saturating_add(10);
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: format!("effect-{suffix}"),
        idempotency_key: format!("key-{suffix}"),
        sprint_id: spec.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        worker_lease: None,
        causation_event_id: Some(cleanup_event.event_id.clone()),
        correlation_id: format!("correlation-{suffix}"),
        kind: EffectKind::CaptureWorkspaceState,
        request_digest: Digest::sha256(&request_bytes),
        policy_hash: plan.policy_hash.clone(),
        input_snapshot: plan.expected_snapshot.clone(),
        created_at_unix_ms: admitted_at_unix_ms,
    };
    let proposed_event = effect_proposal_event(
        &intent,
        ledger
            .next_sequence(&spec.sprint_id)
            .expect("v24 capture proposal sequence"),
        &format!("event-{suffix}-proposed"),
    );
    let admission = SprintLiveStateCaptureAdmission {
        contract_version: CONTRACT_VERSION,
        admission_id: format!("admission-{suffix}"),
        plan: plan.clone(),
        request,
        effect_id: intent.effect_id.clone(),
        runner_launch_id: launch.launch_id.clone(),
        runner_session_id: session.session_id.clone(),
        admitted_at_unix_ms,
    };
    let SprintLiveStateCaptureDispatchAdmission::Fresh {
        admission: stored_admission,
        effect,
        permit,
    } = ledger
        .admit_sprint_live_state_capture_for_dispatch(&admission, &intent, &proposed_event)
        .expect("admit fresh v24 capture")
    else {
        panic!("first v24 capture admission must be Fresh")
    };
    assert_eq!(stored_admission, admission);
    assert_eq!(effect.intent, intent);
    V23AdversarialCaptureAttempt {
        policy,
        plan,
        launch,
        session,
        admission,
        intent,
        proposed_event,
        request_bytes,
        permit: Some(permit),
    }
}

#[test]
#[allow(clippy::too_many_lines)] // One positive runtime test retains the full v24 authority chain.
fn v24_verified_no_op_completion_round_trips_core_derived_authority() {
    let empty_manifest =
        DescriptorRelativeWorkspaceManifest::from_captured_entries(digest('a'), 1, 1, Vec::new())
            .expect("derive empty workspace snapshot identity");
    let expected_snapshot = empty_manifest.manifest_digest;
    let prepared = prepare_v22_explicit_empty_preparation_fixture_with_base_snapshot(
        expected_snapshot.clone(),
    );
    let final_verification_receipt_id = prepared.final_evidence.verification.receipt_id;
    let V15CandidateFixture {
        database,
        mut ledger,
        spec,
        ..
    } = prepared.candidate;
    assert_eq!(spec.base_snapshot, expected_snapshot);

    let task_done = ledger
        .assess_task_done(&spec.sprint_id, "task-1")
        .expect("assess v24 no-op TaskDone")
        .proof
        .expect("v24 no-op task is done");
    let task_integration_receipt_id = task_done.integration_receipt.receipt_id.clone();
    let mut attempt = v23_adversarial_admit_attempt(
        &mut ledger,
        &spec,
        &final_verification_receipt_id,
        &task_integration_receipt_id,
        "v24-noop-runtime",
    );
    assert_eq!(attempt.plan.expected_snapshot, expected_snapshot);
    let capture = persist_v24_matching_empty_live_state_capture(&mut ledger, &mut attempt);

    let cleanup_effect = ledger
        .with_runner_launch_cleanup_exclusion(&spec.sprint_id, &attempt.launch.launch_id, |claim| {
            Ok(cleanup_terminal_from_live_claim(
                claim,
                "v24-noop-runtime",
                capture.receipt.captured_at_unix_ms.saturating_add(10),
            ))
        })
        .expect("close selected v24 live-state verifier");
    let verifier_cleanup = match cleanup_effect.finish_receipt {
        PersistedFinishReceipt::WorkerCleanup(evidence) => evidence,
        other => panic!("expected v24 verifier cleanup, got {other:?}"),
    };
    assert!(matches!(
        ledger
            .load_command_domain_cleanup_completeness(
                &spec.sprint_id,
                &attempt.launch.launch_id,
                &attempt.session.session_id,
                CommandDomainBackend::LinuxCgroupV2,
            )
            .expect("load v24 verifier command-domain cleanup"),
        CommandDomainCleanupCompleteness::Complete(_)
    ));

    let recorded_at_unix_ms = verifier_cleanup
        .receipt
        .cleaned_at_unix_ms
        .saturating_add(10);
    let criterion_evidence = CriterionEvidenceReceiptV2::Verified {
        receipt_id: "criterion-evidence-v24-noop".into(),
        sprint_id: spec.sprint_id.clone(),
        criterion_id: "tests".into(),
        snapshot_digest: expected_snapshot.clone(),
        verification_receipt_id: final_verification_receipt_id.clone(),
        recorded_at: recorded_at_unix_ms,
    };
    ledger
        .persist_verified_criterion_evidence_receipt_v2(&criterion_evidence)
        .expect("persist v24 no-op machine-verified criterion evidence");
    let body = "The exact descriptor-relative live state proves a verified no-op.".to_owned();
    let report = FinalReport {
        report_id: "report-v24-noop".into(),
        sprint_id: spec.sprint_id.clone(),
        final_snapshot: expected_snapshot.clone(),
        content_digest: FinalReport::digest_body(&body),
        body,
        created_at_unix_ms: recorded_at_unix_ms.saturating_add(10),
    };
    let mut worker_cleanup_receipt_ids = attempt.plan.required_cleanup_receipt_ids.clone();
    worker_cleanup_receipt_ids.push(verifier_cleanup.receipt.receipt_id.clone());
    worker_cleanup_receipt_ids.sort();
    let mut verification_receipts = task_done
        .integration_receipt
        .task_verification_receipt_ids
        .clone();
    verification_receipts.push(final_verification_receipt_id.clone());
    verification_receipts.sort();
    let receipt = CompletionReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: "completion-v24-noop".into(),
        sprint_id: spec.sprint_id.clone(),
        grant_hash: spec.workspace_grant.grant_hash.clone(),
        policy_version: spec.workspace_grant.policy_version,
        final_snapshot: expected_snapshot.clone(),
        final_verification_receipt_id: final_verification_receipt_id.clone(),
        application: CompletionApplication::VerifiedNoOp {
            verified_no_op_receipt_id: "verified-no-op-v24-runtime".into(),
        },
        worker_cleanup_receipt_ids,
        satisfied_criterion_ids: vec![criterion_evidence.criterion_id().to_owned()],
        criterion_evidence_receipt_ids: vec![criterion_evidence.receipt_id().to_owned()],
        task_integration_receipt_ids: vec![task_integration_receipt_id],
        verification_receipts,
        provider_backend: spec.provider.backend_id.clone(),
        provider_model: spec.provider.model_id.clone(),
        final_report_id: report.report_id.clone(),
        completed_at_unix_ms: report.created_at_unix_ms.saturating_add(10),
    };
    let completion_event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(&spec.sprint_id)
            .expect("v24 no-op completion sequence"),
        event_id: "event-v24-noop-completed".into(),
        sprint_id: spec.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        causation_id: None,
        correlation_id: "v24-noop-completion".into(),
        policy_hash: None,
        occurred_at_unix_ms: receipt.completed_at_unix_ms,
        payload: AgentEventKind::CompletionRecorded(receipt.receipt_id.clone()),
    };
    let expected_link = ledger
        .derive_completion_live_state_capture_link(&receipt, &capture.receipt.receipt_id)
        .expect("derive v24 completion capture link");
    assert!(
        ledger
            .assess_completion_eligibility_from_live_state_capture(
                &report,
                &receipt,
                &capture.receipt.receipt_id,
                &completion_event,
            )
            .expect("assess v24 completion")
            .is_eligible()
    );
    let persisted = ledger
        .record_successful_completion_from_live_state_capture(
            &report,
            &receipt,
            &capture.receipt.receipt_id,
            &completion_event,
        )
        .expect("record v24 no-op completion");
    assert_eq!(
        row_count(&ledger, "v28_completion_criterion_evidence_receipts"),
        1
    );
    assert_eq!(row_count(&ledger, "v9_completion_acceptance_receipts"), 0);
    let PersistedCompletionApplication::VerifiedNoOp(no_op) = &persisted.application else {
        panic!("v24 no-op completion loaded the wrong branch");
    };
    assert_eq!(no_op.receipt_id, "verified-no-op-v24-runtime");
    assert_eq!(no_op.live_manifest_digest, expected_snapshot);
    assert_eq!(
        no_op.observed_at_unix_ms,
        capture.receipt.captured_at_unix_ms
    );
    match &persisted.live_state_authority {
        PersistedCompletionLiveStateAuthority::Linked {
            link,
            capture_evidence,
            verifier_cleanup_evidence,
        } => {
            assert_eq!(link, &expected_link);
            assert_eq!(capture_evidence, &capture);
            assert_eq!(verifier_cleanup_evidence, &verifier_cleanup);
        }
        PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(_) => {
            panic!("current v24 completion cannot use a migration exemption");
        }
    }

    let database_path = database.path.clone();
    drop(ledger);
    let reopened = EventLedger::open(&database_path).expect("reopen v24 completion ledger");
    assert_eq!(
        reopened
            .load_completion(&spec.sprint_id)
            .expect("reload v24 no-op completion")
            .expect("v24 completion remains present"),
        persisted
    );
    drop(reopened);
    drop(database);
}

#[test]
#[allow(clippy::too_many_lines)] // Applied authority retains the full application/capture/cleanup/restart chain.
fn v24_applied_completion_round_trips_exact_live_state_authority() {
    let base_manifest =
        DescriptorRelativeWorkspaceManifest::from_captured_entries(digest('a'), 1, 1, Vec::new())
            .expect("derive v24 Applied base snapshot");
    let result_entries = vec![crate::DescriptorRelativeManifestEntry {
        path: "report.txt".into(),
        content_digest: digest('d'),
        byte_length: 1,
        unix_mode: 0o644,
    }];
    let result_manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
        digest('a'),
        1,
        1,
        result_entries.clone(),
    )
    .expect("derive v24 Applied result snapshot");
    let mut fixture = prepare_v22_application_admission_fixture_with_snapshots(
        base_manifest.manifest_digest,
        result_manifest.manifest_digest.clone(),
    );
    assert_eq!(
        fixture.request.change_set.result_snapshot,
        result_manifest.manifest_digest
    );
    let terminal = persist_v22_claimed_application_fixture(&mut fixture);
    persist_cleanup_evidence(
        &mut fixture.candidate.ledger,
        &fixture.applier_launch,
        &fixture.request.change_set.result_snapshot,
        "cleanup-v24-applied-applier",
        WorkerCleanupBackend::TrustedApplierDirectChildWait,
        2_520,
        2_540,
    );

    let policy = compiled_test_policy("policy-v24-applied-live-state");
    let cut = v23_adversarial_latest_cut(
        &fixture.candidate.ledger,
        &fixture.candidate.spec.sprint_id,
        "v24-applied-runtime",
    );
    let plan = fixture
        .candidate
        .ledger
        .derive_applied_live_state_capture_plan(
            cut,
            &policy,
            &fixture.candidate.spec.sprint_id,
            &fixture.admission.final_verification_receipt_id,
            &terminal.receipt.receipt_id,
            &terminal.rollback.reference.reference_id,
        )
        .expect("derive v24 Applied capture plan");
    assert_eq!(plan.expected_snapshot, result_manifest.manifest_digest);
    let mut attempt = v24_admit_capture_for_plan(
        &mut fixture.candidate.ledger,
        &fixture.candidate.spec,
        policy,
        plan,
        "v24-applied-runtime",
    );
    let capture = persist_v24_matching_live_state_capture(
        &mut fixture.candidate.ledger,
        &mut attempt,
        result_entries,
        "receipt-v24-applied-capture",
        "v24-applied-runtime",
    );
    let cleanup_effect = fixture
        .candidate
        .ledger
        .with_runner_launch_cleanup_exclusion(
            &fixture.candidate.spec.sprint_id,
            &attempt.launch.launch_id,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "v24-applied-runtime",
                    capture.receipt.captured_at_unix_ms.saturating_add(10),
                ))
            },
        )
        .expect("close selected v24 Applied live-state verifier");
    let verifier_cleanup = match cleanup_effect.finish_receipt {
        PersistedFinishReceipt::WorkerCleanup(evidence) => evidence,
        other => panic!("expected v24 Applied verifier cleanup, got {other:?}"),
    };
    assert!(matches!(
        fixture
            .candidate
            .ledger
            .load_command_domain_cleanup_completeness(
                &fixture.candidate.spec.sprint_id,
                &attempt.launch.launch_id,
                &attempt.session.session_id,
                CommandDomainBackend::LinuxCgroupV2,
            )
            .expect("load v24 Applied verifier command-domain cleanup"),
        CommandDomainCleanupCompleteness::Complete(_)
    ));

    let recorded_at_unix_ms = verifier_cleanup
        .receipt
        .cleaned_at_unix_ms
        .saturating_add(10);
    let criterion_evidence = CriterionEvidenceReceiptV2::Verified {
        receipt_id: "criterion-evidence-v24-applied".into(),
        sprint_id: fixture.candidate.spec.sprint_id.clone(),
        criterion_id: "tests".into(),
        snapshot_digest: result_manifest.manifest_digest.clone(),
        verification_receipt_id: fixture.admission.final_verification_receipt_id.clone(),
        recorded_at: recorded_at_unix_ms,
    };
    fixture
        .candidate
        .ledger
        .persist_verified_criterion_evidence_receipt_v2(&criterion_evidence)
        .expect("persist v24 Applied machine-verified criterion evidence");
    let integration = fixture
        .candidate
        .ledger
        .load_task_integration_receipt(&fixture.assembly.sources[0].task_integration_receipt_id)
        .expect("load v24 Applied TaskDone integration");
    let body = "The applied result matches the exact descriptor-relative live state.".to_owned();
    let report = FinalReport {
        report_id: "report-v24-applied".into(),
        sprint_id: fixture.candidate.spec.sprint_id.clone(),
        final_snapshot: result_manifest.manifest_digest.clone(),
        content_digest: FinalReport::digest_body(&body),
        body,
        created_at_unix_ms: recorded_at_unix_ms.saturating_add(10),
    };
    let mut worker_cleanup_receipt_ids = attempt.plan.required_cleanup_receipt_ids.clone();
    worker_cleanup_receipt_ids.push(verifier_cleanup.receipt.receipt_id.clone());
    worker_cleanup_receipt_ids.sort();
    let mut verification_receipts = integration.task_verification_receipt_ids.clone();
    verification_receipts.push(fixture.admission.final_verification_receipt_id.clone());
    verification_receipts.sort();
    let receipt = CompletionReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: "completion-v24-applied".into(),
        sprint_id: fixture.candidate.spec.sprint_id.clone(),
        grant_hash: fixture.candidate.spec.workspace_grant.grant_hash.clone(),
        policy_version: fixture.candidate.spec.workspace_grant.policy_version,
        final_snapshot: result_manifest.manifest_digest.clone(),
        final_verification_receipt_id: fixture.admission.final_verification_receipt_id.clone(),
        application: CompletionApplication::Applied {
            application_receipt_id: terminal.receipt.receipt_id.clone(),
            rollback_reference_id: terminal.rollback.reference.reference_id.clone(),
        },
        worker_cleanup_receipt_ids,
        satisfied_criterion_ids: vec![criterion_evidence.criterion_id().to_owned()],
        criterion_evidence_receipt_ids: vec![criterion_evidence.receipt_id().to_owned()],
        task_integration_receipt_ids: vec![integration.receipt_id.clone()],
        verification_receipts,
        provider_backend: fixture.candidate.spec.provider.backend_id.clone(),
        provider_model: fixture.candidate.spec.provider.model_id.clone(),
        final_report_id: report.report_id.clone(),
        completed_at_unix_ms: report.created_at_unix_ms.saturating_add(10),
    };
    let completion_event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: fixture
            .candidate
            .ledger
            .next_sequence(&receipt.sprint_id)
            .expect("v24 Applied completion sequence"),
        event_id: "event-v24-applied-completed".into(),
        sprint_id: receipt.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        causation_id: Some(terminal.event.event_id.clone()),
        correlation_id: "v24-applied-completion".into(),
        policy_hash: None,
        occurred_at_unix_ms: receipt.completed_at_unix_ms,
        payload: AgentEventKind::CompletionRecorded(receipt.receipt_id.clone()),
    };
    let expected_link = fixture
        .candidate
        .ledger
        .derive_completion_live_state_capture_link(&receipt, &capture.receipt.receipt_id)
        .expect("derive v24 Applied completion link");
    let assessment = fixture
        .candidate
        .ledger
        .assess_completion_eligibility_from_live_state_capture(
            &report,
            &receipt,
            &capture.receipt.receipt_id,
            &completion_event,
        )
        .expect("assess v24 Applied completion");
    assert!(assessment.is_eligible(), "unexpected unmet: {assessment:?}");
    let persisted = fixture
        .candidate
        .ledger
        .record_successful_completion_from_live_state_capture(
            &report,
            &receipt,
            &capture.receipt.receipt_id,
            &completion_event,
        )
        .expect("record v24 Applied completion");
    assert_eq!(
        row_count(
            &fixture.candidate.ledger,
            "v28_completion_criterion_evidence_receipts",
        ),
        1
    );
    assert_eq!(
        row_count(
            &fixture.candidate.ledger,
            "v9_completion_acceptance_receipts",
        ),
        0
    );
    match &persisted.application {
        PersistedCompletionApplication::Applied {
            application_evidence,
            rollback_reference,
        } => {
            assert_eq!(application_evidence, &terminal.evidence);
            assert_eq!(rollback_reference, &terminal.rollback);
        }
        PersistedCompletionApplication::VerifiedNoOp(_) => {
            panic!("v24 Applied completion loaded the no-op branch")
        }
    }
    match &persisted.live_state_authority {
        PersistedCompletionLiveStateAuthority::Linked {
            link,
            capture_evidence,
            verifier_cleanup_evidence,
        } => {
            assert_eq!(link, &expected_link);
            assert_eq!(capture_evidence, &capture);
            assert_eq!(verifier_cleanup_evidence, &verifier_cleanup);
        }
        PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(_) => {
            panic!("current v24 Applied completion cannot use a migration exemption")
        }
    }

    let database_path = fixture.candidate.database.path.clone();
    drop(fixture.candidate.ledger);
    let reopened = EventLedger::open(&database_path).expect("reopen v24 Applied completion ledger");
    assert_eq!(
        reopened
            .load_completion(&receipt.sprint_id)
            .expect("reload v24 Applied completion")
            .expect("v24 Applied completion remains present"),
        persisted
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the namespace regression proves both collision directions, zero partial writes, retained retry custody, and successful retry"
)]
fn v24_capture_and_command_receipt_namespaces_reject_collisions_with_retry_custody() {
    let V23AdversarialFixture {
        database: _database,
        mut ledger,
        mut attempt,
        ..
    } = prepare_v23_adversarial_fixture();
    let colliding_proof_id = ledger
        .connection
        .query_row(
            "SELECT proof_id
             FROM command_domain_cleanup_proofs ORDER BY proof_id LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("load existing command-domain proof identity");
    let (claimed, authority) = v23_adversarial_claim(&mut ledger, &mut attempt);
    let (mut observation, _, mut evidence, _) =
        v23_adversarial_success_terminal(&ledger, &attempt, &claimed, "v24-id-collision");
    evidence.receipt.receipt_id = colliding_proof_id.clone();
    let evidence_bytes =
        encode("v24 colliding capture evidence", &evidence).expect("encode collision evidence");
    observation.outcome = EffectOutcome::Succeeded {
        evidence_digest: Digest::sha256(&evidence_bytes),
    };
    let terminal = effect_terminal_event(
        &attempt.intent,
        &attempt.proposed_event.event_id,
        &observation,
        ledger
            .next_sequence(&attempt.intent.sprint_id)
            .expect("collision terminal sequence"),
        "event-v24-id-collision-finished",
    );
    let before = [
        row_count(&ledger, "live_state_capture_manifest_entries"),
        row_count(&ledger, "live_state_capture_receipts"),
        row_count(&ledger, "live_state_capture_receipt_ids"),
        row_count(&ledger, "effect_observations"),
        row_count(&ledger, "effect_evidence_payloads"),
        row_count(&ledger, "agent_events"),
    ];
    let failure = ledger
        .record_claimed_live_state_capture_observation(
            authority,
            &observation,
            &evidence,
            &terminal,
        )
        .expect_err("capture ID colliding with command proof must fail");
    assert!(failure.has_retry_authority());
    assert!(matches!(
        failure.error(),
        LedgerError::ArtifactAlreadyExists {
            entity: "global live-state capture receipt identity",
            id,
        } if id == &colliding_proof_id
    ));
    assert_eq!(
        before,
        [
            row_count(&ledger, "live_state_capture_manifest_entries"),
            row_count(&ledger, "live_state_capture_receipts"),
            row_count(&ledger, "live_state_capture_receipt_ids"),
            row_count(&ledger, "effect_observations"),
            row_count(&ledger, "effect_evidence_payloads"),
            row_count(&ledger, "agent_events"),
        ]
    );

    let (_, retry_authority) = failure.into_parts();
    evidence.receipt.receipt_id = "receipt-v24-id-collision-retry".into();
    let retry_evidence_bytes =
        encode("v24 retried capture evidence", &evidence).expect("encode retry evidence");
    observation.outcome = EffectOutcome::Succeeded {
        evidence_digest: Digest::sha256(&retry_evidence_bytes),
    };
    let retry_terminal = effect_terminal_event(
        &attempt.intent,
        &attempt.proposed_event.event_id,
        &observation,
        terminal.sequence,
        &terminal.event_id,
    );
    ledger
        .record_claimed_live_state_capture_observation(
            retry_authority.expect("definite precommit failure retains authority"),
            &observation,
            &evidence,
            &retry_terminal,
        )
        .expect("retry capture with globally unique identity");
    assert_eq!(
        ledger
            .load_live_state_capture_evidence(&evidence.receipt.receipt_id)
            .expect("reload retried capture"),
        evidence
    );

    let binding = ledger
        .load_command_domain_effect_bindings(
            &attempt.intent.sprint_id,
            &attempt.launch.launch_id,
            &attempt.session.session_id,
        )
        .expect("load verifier command-domain set");
    assert!(binding.is_empty());
    ledger
        .connection
        .execute_batch("DROP TRIGGER command_domain_cleanup_proofs_no_delete;")
        .expect("open reverse-namespace test gap");
    let delete_error = ledger
        .connection
        .execute(
            "DELETE FROM command_domain_cleanup_proofs WHERE proof_id = ?1",
            [&colliding_proof_id],
        )
        .expect_err("v27 capture validation must retain its command-domain proof");
    assert!(
        delete_error
            .to_string()
            .contains("FOREIGN KEY constraint failed"),
        "unexpected command-domain proof deletion error: {delete_error:?}"
    );
    assert_eq!(
        ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM command_domain_cleanup_proofs WHERE proof_id = ?1",
                [&colliding_proof_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("confirm capture-referenced command-domain proof remains"),
        1,
        "the v27 capture-validation FK must close the reverse-namespace deletion gap"
    );
}

#[test]
fn v24_post_capture_failed_before_effect_mutation_blocks_completion_cut() {
    let empty_manifest =
        DescriptorRelativeWorkspaceManifest::from_captured_entries(digest('a'), 1, 1, Vec::new())
            .expect("derive mutation-fence base snapshot");
    let prepared = prepare_v22_explicit_empty_preparation_fixture_with_base_snapshot(
        empty_manifest.manifest_digest,
    );
    let final_verification_receipt_id = prepared.final_evidence.verification.receipt_id;
    let V15CandidateFixture {
        database: _database,
        mut ledger,
        spec,
        ..
    } = prepared.candidate;
    let task_integration_receipt_id = ledger
        .assess_task_done(&spec.sprint_id, "task-1")
        .expect("assess mutation-fence TaskDone")
        .proof
        .expect("mutation-fence task is done")
        .integration_receipt
        .receipt_id;
    let mut attempt = v23_adversarial_admit_attempt(
        &mut ledger,
        &spec,
        &final_verification_receipt_id,
        &task_integration_receipt_id,
        "v24-post-capture-failed-before",
    );
    let capture = persist_v24_matching_empty_live_state_capture(&mut ledger, &mut attempt);

    let request_bytes = b"mutation request that must never execute".to_vec();
    let mutation = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: "effect-v24-post-capture-failed-before".into(),
        idempotency_key: "key-v24-post-capture-failed-before".into(),
        sprint_id: spec.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        worker_lease: None,
        causation_event_id: Some("event-v24-noop-runtime-capture-finished".into()),
        correlation_id: "correlation-v24-post-capture-failed-before".into(),
        kind: EffectKind::CreateRegularFile,
        request_digest: Digest::sha256(&request_bytes),
        policy_hash: digest('e'),
        input_snapshot: capture.receipt.observed_snapshot.clone(),
        created_at_unix_ms: capture.receipt.captured_at_unix_ms.saturating_add(10),
    };
    let proposal = effect_proposal_event(
        &mutation,
        ledger
            .next_sequence(&spec.sprint_id)
            .expect("post-capture mutation proposal sequence"),
        "event-v24-post-capture-failed-before-proposed",
    );
    ledger
        .record_effect_intent(&mutation, &request_bytes, &proposal)
        .expect("persist taskless post-capture mutation intent");
    let failure_bytes = b"native mutation was refused before effect".to_vec();
    let observation = effect_observation(
        &mutation,
        "observation-v24-post-capture-failed-before",
        EffectOutcome::FailedBeforeEffect {
            evidence_digest: Digest::sha256(&failure_bytes),
        },
        mutation.created_at_unix_ms.saturating_add(10),
    );
    let terminal = effect_terminal_event(
        &mutation,
        &proposal.event_id,
        &observation,
        ledger
            .next_sequence(&spec.sprint_id)
            .expect("post-capture mutation terminal sequence"),
        "event-v24-post-capture-failed-before-finished",
    );
    ledger
        .record_effect_observation(&observation, &failure_bytes, &terminal)
        .expect("terminalize post-capture mutation before native effect");

    assert!(matches!(
        validate_no_authorized_mutation_after_capture(&ledger.connection, &capture.receipt),
        Err(LedgerError::ReferenceMismatch {
            entity: "completion live-state capture link",
            ..
        })
    ));
}

#[test]
#[allow(clippy::too_many_lines)] // One fixture compares the populated preimage, exact migration, and fresh v25 schema.
fn v24_database_migrates_exactly_to_v25_without_backfilling_drift_proofs() {
    let database = TestDatabase::new();
    let (spec, graph) = sprint_fixture();
    let v24_schema = {
        schema_template::install_exact_database_at(24, &database.path);
        let connection = Connection::open(&database.path).expect("create exact v24 database");
        register_schema_functions(&connection).expect("register v24 schema functions");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = FULL;
                 PRAGMA journal_mode = WAL;",
            )
            .expect("configure exact v24 database");
        let mut v24 = EventLedger {
            connection,
            database_path: database.path.clone(),
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        };
        v24.create_sprint(&spec, &graph, 1_000)
            .expect("persist one v24 planned sprint");
        assert_eq!(
            v24.connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table'
                       AND name = 'sprint_live_state_drift_blocked_proofs'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("confirm v25 drift authority is absent"),
            0
        );
        load_schema_objects(&v24.connection).expect("capture exact populated v24 schema")
    };

    let connection = Connection::open(&database.path).expect("reopen exact v24 database");
    register_schema_functions(&connection).expect("register v25 schema functions");
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA journal_mode = WAL;",
        )
        .expect("configure exact v25 database");
    connection
        .execute_batch(MIGRATIONS[24])
        .expect("install only the exact v25 migration");
    connection
        .pragma_update(None, "user_version", 25_i64)
        .expect("mark exact v25 schema");
    let ledger = EventLedger {
        connection,
        database_path: database.path.clone(),
        read_only: false,
        instance_id: next_event_ledger_instance_id(),
    };
    let version: i64 = ledger
        .connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read upgraded schema version");
    assert_eq!(version, 25);
    let v25_schema = load_schema_objects(&ledger.connection).expect("load exact v25 schema");
    for historical_object in &v24_schema {
        if historical_object.name == "non_success_terminal_requires_cleanup_proof" {
            continue;
        }
        assert!(
            v25_schema.contains(historical_object),
            "v25 migration must preserve v24 schema object {} byte-for-byte",
            historical_object.name
        );
    }
    let v24_terminal_gate = v24_schema
        .iter()
        .find(|object| object.name == "non_success_terminal_requires_cleanup_proof")
        .expect("v24 terminal proof gate exists");
    let v25_terminal_gate = v25_schema
        .iter()
        .find(|object| object.name == "non_success_terminal_requires_cleanup_proof")
        .expect("v25 terminal proof gate exists");
    assert_ne!(v25_terminal_gate.sql, v24_terminal_gate.sql);
    assert!(
        v25_terminal_gate
            .sql
            .contains("sprint_live_state_drift_blocked_proofs"),
        "the sole replaced v24 gate must be the prospective two-proof-family XOR"
    );
    assert_eq!(
        row_count(&ledger, "sprint_live_state_drift_blocked_proofs"),
        0,
        "v25 authority is prospective and must not synthesize historical drift proofs"
    );
    let restored = ledger
        .load_sprint(&spec.sprint_id)
        .expect("load the preserved v24 sprint through v25");
    assert_eq!(restored.spec, spec);
    assert_eq!(restored.graph, Some(graph));
    assert_eq!(restored.completion, None);
    assert_eq!(restored.terminal_outcome, None);
    let expected_connection = Connection::open_in_memory().expect("open expected v25 schema");
    register_schema_functions(&expected_connection).expect("register expected v25 functions");
    for migration in MIGRATIONS.iter().take(25) {
        expected_connection
            .execute_batch(migration)
            .expect("install expected migration through exact v25");
    }
    assert_eq!(
        load_schema_objects(&ledger.connection).expect("load migrated exact v25 schema"),
        load_schema_objects(&expected_connection).expect("load expected exact v25 schema"),
        "migrated schema must equal a fresh exact-v25 schema byte-for-byte"
    );
}

fn open_exact_v24_terminal_migration_ledger(database: &TestDatabase) -> EventLedger {
    schema_template::install_exact_database_at(24, &database.path);
    let connection = Connection::open(&database.path).expect("create exact v24 terminal database");
    register_schema_functions(&connection).expect("register exact v24 schema functions");
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA journal_mode = WAL;",
        )
        .expect("configure exact v24 terminal database");
    EventLedger {
        connection,
        database_path: database.path.clone(),
        read_only: false,
        instance_id: next_event_ledger_instance_id(),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum V24SqlCell {
    Null,
    Integer(i64),
    Real(u64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

fn load_single_v24_row(connection: &Connection, query: &str, sprint_id: &str) -> Vec<V24SqlCell> {
    use rusqlite::types::ValueRef;

    let mut statement = connection.prepare(query).expect("prepare v24 row image");
    let column_count = statement.column_count();
    statement
        .query_row([sprint_id], |row| {
            let mut cells = Vec::with_capacity(column_count);
            for index in 0..column_count {
                cells.push(match row.get_ref(index)? {
                    ValueRef::Null => V24SqlCell::Null,
                    ValueRef::Integer(value) => V24SqlCell::Integer(value),
                    ValueRef::Real(value) => V24SqlCell::Real(value.to_bits()),
                    ValueRef::Text(value) => V24SqlCell::Text(value.to_vec()),
                    ValueRef::Blob(value) => V24SqlCell::Blob(value.to_vec()),
                });
            }
            Ok(cells)
        })
        .expect("load exact v24 row image")
}

#[derive(Debug, Eq, PartialEq)]
struct V24TerminalRowImage {
    outcome: Vec<V24SqlCell>,
    proof: Vec<V24SqlCell>,
    unchanged_receipt: Vec<V24SqlCell>,
    finish_receipt_id: Vec<V24SqlCell>,
    terminal_event: Vec<V24SqlCell>,
}

fn load_v24_terminal_row_image(connection: &Connection, sprint_id: &str) -> V24TerminalRowImage {
    V24TerminalRowImage {
        outcome: load_single_v24_row(
            connection,
            "SELECT * FROM sprint_non_success_terminal_outcomes WHERE sprint_id = ?1",
            sprint_id,
        ),
        proof: load_single_v24_row(
            connection,
            "SELECT * FROM terminal_cleanup_proofs WHERE sprint_id = ?1",
            sprint_id,
        ),
        unchanged_receipt: load_single_v24_row(
            connection,
            "SELECT * FROM live_workspace_unchanged_receipts WHERE sprint_id = ?1",
            sprint_id,
        ),
        finish_receipt_id: load_single_v24_row(
            connection,
            "SELECT finish.*
             FROM finish_receipt_ids finish
             JOIN terminal_cleanup_proofs proof
               ON proof.unchanged_receipt_id = finish.receipt_id
             WHERE proof.sprint_id = ?1",
            sprint_id,
        ),
        terminal_event: load_single_v24_row(
            connection,
            "SELECT event.*
             FROM agent_events event
             JOIN sprint_non_success_terminal_outcomes outcome
               ON outcome.terminal_event_id = event.event_id
             WHERE outcome.sprint_id = ?1",
            sprint_id,
        ),
    }
}

#[test]
fn populated_valid_v24_terminal_proof_migrates_byte_exactly_without_drift_backfill() {
    let database = TestDatabase::new();
    let mut v24 = open_exact_v24_terminal_migration_ledger(&database);
    prepare_terminal_sprint(&mut v24);
    let evidence = terminal_evidence(
        "terminal-v24-valid-migration",
        NonSuccessTerminalState::Failed,
    );
    let persisted = record_test_terminal_outcome(&mut v24, &evidence)
        .expect("record valid populated v24 terminal outcome and cleanup proof");
    let before = load_v24_terminal_row_image(&v24.connection, &evidence.sprint_id);
    assert_eq!(
        v24.connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .expect("read exact v24 version"),
        24
    );
    drop(v24);

    let migrated = EventLedger::open(&database.path)
        .expect("migrate populated valid v24 terminal authority to v25");
    assert_eq!(
        migrated
            .connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .expect("read migrated v25 version"),
        SCHEMA_VERSION
    );
    assert_eq!(
        load_v24_terminal_row_image(&migrated.connection, &evidence.sprint_id),
        before,
        "v25 must preserve every normalized value and every retained v24 JSON byte"
    );
    assert_eq!(
        migrated
            .load_terminal_outcome(&evidence.sprint_id)
            .expect("reload migrated v24 terminal authority")
            .expect("migrated v24 terminal authority remains present"),
        persisted
    );
    assert_eq!(
        row_count(&migrated, "sprint_live_state_drift_blocked_proofs"),
        0,
        "migration must never recast an old cleanup proof as drift authority"
    );
    verify_exact_schema(&migrated.connection)
        .expect("populated terminal migration reaches the exact v25 schema");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the two corrupt historical images share one transactional rejection matrix"
)]
fn v25_rejects_orphan_and_crossed_v24_terminal_proofs_without_partial_migration() {
    for crossed in [false, true] {
        let database = TestDatabase::new();
        let mut v24 = open_exact_v24_terminal_migration_ledger(&database);
        prepare_terminal_sprint(&mut v24);
        if crossed {
            let (mut crossed_spec, mut crossed_graph) = sprint_fixture();
            crossed_spec.sprint_id = "sprint-v24-crossed-proof-owner".into();
            crossed_graph.graph_id = "graph-v24-crossed-proof-owner".into();
            v24.create_sprint(&crossed_spec, &crossed_graph, 1_001)
                .expect("persist alternate v24 sprint for crossed proof");
        }
        let evidence = terminal_evidence(
            if crossed {
                "terminal-v24-crossed-migration"
            } else {
                "terminal-v24-orphan-migration"
            },
            NonSuccessTerminalState::Failed,
        );
        record_test_terminal_outcome(&mut v24, &evidence)
            .expect("record initially valid v24 terminal authority");

        if crossed {
            v24.connection
                .execute_batch("DROP TRIGGER terminal_cleanup_proofs_no_update;")
                .expect("open test-only crossed-proof corruption seam");
            v24.connection
                .execute(
                    "UPDATE terminal_cleanup_proofs
                     SET sprint_id = 'sprint-v24-crossed-proof-owner'
                     WHERE sprint_id = ?1",
                    [&evidence.sprint_id],
                )
                .expect("cross the v24 proof onto a different sprint");
        } else {
            v24.connection
                .execute_batch("DROP TRIGGER terminal_cleanup_proofs_no_delete;")
                .expect("open test-only orphan corruption seam");
            v24.connection
                .execute(
                    "DELETE FROM terminal_cleanup_proofs WHERE sprint_id = ?1",
                    [&evidence.sprint_id],
                )
                .expect("orphan the v24 terminal outcome");
        }
        let before_outcomes = row_count(&v24, "sprint_non_success_terminal_outcomes");
        let before_proofs = row_count(&v24, "terminal_cleanup_proofs");
        assert_eq!(
            v24.connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("read corrupt fixture schema version"),
            24
        );
        drop(v24);

        let Err(migration_error) = EventLedger::open(&database.path) else {
            panic!("v25 must reject an orphaned or crossed v24 proof image");
        };
        assert!(
            matches!(migration_error, LedgerError::Sql(_)),
            "v25 guard must reject through its transactional SQL constraint: {migration_error:?}"
        );

        let preserved = Connection::open(&database.path)
            .expect("inspect transactionally preserved v24 database");
        assert_eq!(
            preserved
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("read version after refused v25 migration"),
            24,
            "a refused migration must not advance user_version"
        );
        assert_eq!(
            preserved
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table'
                       AND name = 'sprint_live_state_drift_blocked_proofs'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("check for partial v25 drift table"),
            0,
            "a refused migration must leave no persistent v25 table"
        );
        assert_eq!(
            preserved
                .query_row(
                    "SELECT COUNT(*) FROM sprint_non_success_terminal_outcomes",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count preserved v24 outcomes"),
            before_outcomes
        );
        assert_eq!(
            preserved
                .query_row("SELECT COUNT(*) FROM terminal_cleanup_proofs", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count preserved v24 proofs"),
            before_proofs
        );
    }
}
