fn v23_additional_admit_plan(
    ledger: &mut EventLedger,
    spec: &SprintSpec,
    plan: SprintLiveStateCapturePlan,
    policy: CompiledExecutionPolicy,
    suffix: &str,
) -> V23AdversarialCaptureAttempt {
    let launch = runner_launch(
        &format!("launch-v23-additional-{suffix}"),
        &format!("session-v23-additional-{suffix}"),
        RunnerSessionPurpose::LiveStateVerifier,
        None,
        &policy,
        plan.planned_at_unix_ms.saturating_add(10),
    );
    let (cleanup_intent, _, cleanup_request_bytes, cleanup_event) =
        test_runner_launch_cleanup_contracts(ledger, &launch, WorkerCleanupBackend::LinuxCgroupV2)
            .expect("build additional v23 verifier cleanup admission");
    ledger
        .admit_live_state_verifier_launch_with_cleanup(
            &plan,
            &launch,
            &policy,
            &cleanup_intent,
            &cleanup_request_bytes,
            &cleanup_event,
        )
        .expect("persist additional v23 plan and verifier launch");
    let session = runner_session(&launch, launch.created_at_unix_ms.saturating_add(10));
    ledger
        .register_live_state_verifier_session(&plan, &session, &policy)
        .expect("register additional v23 verifier session");
    let request = SprintLiveStateCaptureRequest::from_plan(plan.clone())
        .expect("construct additional v23 request");
    let request_bytes =
        encode("additional v23 request", &request).expect("encode additional v23 request");
    let admitted_at_unix_ms = session.registered_at_unix_ms.saturating_add(10);
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: format!("effect-v23-additional-{suffix}"),
        idempotency_key: format!("key-v23-additional-{suffix}"),
        sprint_id: spec.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        worker_lease: None,
        causation_event_id: Some(cleanup_event.event_id.clone()),
        correlation_id: format!("correlation-v23-additional-{suffix}"),
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
            .expect("additional v23 proposal sequence"),
        &format!("event-v23-additional-{suffix}-proposed"),
    );
    let admission = SprintLiveStateCaptureAdmission {
        contract_version: CONTRACT_VERSION,
        admission_id: format!("admission-v23-additional-{suffix}"),
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
        .expect("admit additional v23 capture")
    else {
        panic!("additional v23 admission must be fresh");
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

fn v23_additional_terminal_from_evidence(
    ledger: &EventLedger,
    attempt: &V23AdversarialCaptureAttempt,
    evidence: &LiveStateCaptureEvidence,
    observed_at_unix_ms: u64,
    suffix: &str,
) -> (EffectObservation, AgentEvent) {
    let evidence_bytes =
        encode("additional v23 evidence", evidence).expect("encode additional v23 evidence");
    let observation = effect_observation(
        &attempt.intent,
        &evidence.receipt.observation_id,
        EffectOutcome::Succeeded {
            evidence_digest: Digest::sha256(&evidence_bytes),
        },
        observed_at_unix_ms,
    );
    let event = effect_terminal_event(
        &attempt.intent,
        &attempt.proposed_event.event_id,
        &observation,
        ledger
            .next_sequence(&attempt.intent.sprint_id)
            .expect("additional v23 terminal sequence"),
        &format!("event-v23-additional-{suffix}-finished"),
    );
    (observation, event)
}

#[test]
#[allow(clippy::too_many_lines)] // The full Applied branch and restart chain is intentionally visible end to end.
fn v23_applied_branch_capture_round_trips_exact_receipt_plan_and_restart() {
    let mut fixture = prepare_v22_application_admission_fixture();
    let application = persist_v22_claimed_application_fixture(&mut fixture);
    let cleanup_at = application
        .rollback
        .reference
        .validated_at_unix_ms
        .saturating_add(10);
    fixture
        .candidate
        .ledger
        .with_runner_launch_cleanup_exclusion(
            &fixture.candidate.spec.sprint_id,
            &fixture.applier_launch.launch_id,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "v23-additional-applied-applier",
                    cleanup_at,
                ))
            },
        )
        .expect("close applied branch applier before capture planning");

    let policy = compiled_test_policy("policy-v23-additional-applied");
    let cut = v23_adversarial_latest_cut(
        &fixture.candidate.ledger,
        &fixture.candidate.spec.sprint_id,
        "additional-applied",
    );
    let plan = fixture
        .candidate
        .ledger
        .derive_applied_live_state_capture_plan(
            cut,
            &policy,
            &fixture.candidate.spec.sprint_id,
            &fixture.admission.final_verification_receipt_id,
            &application.receipt.receipt_id,
            &application.rollback.reference.reference_id,
        )
        .expect("derive exact Applied v23 capture plan");
    assert!(matches!(
        &plan.branch,
        LiveStateCaptureBranch::Applied {
            final_verification_receipt_id,
            application_receipt_id,
            rollback_reference_id,
        } if final_verification_receipt_id == &fixture.admission.final_verification_receipt_id
            && application_receipt_id == &application.receipt.receipt_id
            && rollback_reference_id == &application.rollback.reference.reference_id
    ));
    let mut attempt = v23_additional_admit_plan(
        &mut fixture.candidate.ledger,
        &fixture.candidate.spec,
        plan.clone(),
        policy,
        "applied",
    );
    let evidence = v23_adversarial_persist_success(
        &mut fixture.candidate.ledger,
        &mut attempt,
        "additional-applied",
    );
    assert_eq!(evidence.receipt.branch, plan.branch);
    assert_eq!(evidence.receipt.plan_digest, plan.plan_digest().unwrap());
    assert_eq!(
        evidence.receipt.manifest_digest,
        evidence.manifest.manifest_digest
    );
    assert_eq!(
        evidence.receipt.observed_snapshot,
        evidence.manifest.manifest_digest
    );

    let expected_admission = attempt.admission.clone();
    let expected_effect_id = attempt.intent.effect_id.clone();
    let database_path = fixture.candidate.database.path.clone();
    let V22ApplicationAdmissionFixture { candidate, .. } = fixture;
    let V15CandidateFixture {
        database, ledger, ..
    } = candidate;
    drop(ledger);
    let reopened = EventLedger::open(&database_path).expect("restart Applied v23 ledger");
    assert_eq!(
        reopened
            .load_sprint_live_state_capture_plan(&plan.plan_id)
            .expect("reload Applied v23 plan"),
        plan
    );
    assert_eq!(
        reopened
            .load_sprint_live_state_capture_admission(&expected_admission.admission_id)
            .expect("reload Applied v23 admission"),
        expected_admission
    );
    assert_eq!(
        reopened
            .load_live_state_capture_evidence(&evidence.receipt.receipt_id)
            .expect("reload Applied v23 evidence"),
        evidence
    );
    assert!(matches!(
        reopened
            .load_effect(&expected_effect_id)
            .expect("reload Applied v23 effect")
            .finish_receipt,
        PersistedFinishReceipt::LiveStateCapture(_)
    ));
    drop(reopened);
    drop(database);
}

#[test]
fn v23_capture_interval_rejects_pre_admission_reversal_and_observation_mismatch() {
    {
        let mut fixture = prepare_v23_adversarial_fixture();
        let (claimed, authority) = v23_adversarial_claim(&mut fixture.ledger, &mut fixture.attempt);
        let (_, _, mut evidence, _) = v23_adversarial_success_terminal(
            &fixture.ledger,
            &fixture.attempt,
            &claimed,
            "interval-pre-admission",
        );
        let crossed_start = fixture.attempt.admission.admitted_at_unix_ms - 1;
        assert!(crossed_start >= fixture.attempt.plan.planned_at_unix_ms);
        evidence.receipt.capture_started_at_unix_ms = crossed_start;
        evidence.manifest.capture_started_at_unix_ms = crossed_start;
        let observed_at = evidence.receipt.captured_at_unix_ms;
        let (observation, event) = v23_additional_terminal_from_evidence(
            &fixture.ledger,
            &fixture.attempt,
            &evidence,
            observed_at,
            "interval-pre-admission",
        );
        let failure = fixture
            .ledger
            .record_claimed_live_state_capture_observation(
                authority,
                &observation,
                &evidence,
                &event,
            )
            .expect_err("capture cannot begin before its exact admission");
        assert!(failure.has_retry_authority());
        assert_eq!(row_count(&fixture.ledger, "live_state_capture_receipts"), 0);
    }

    {
        let mut fixture = prepare_v23_adversarial_fixture();
        let (claimed, authority) = v23_adversarial_claim(&mut fixture.ledger, &mut fixture.attempt);
        let (_, _, mut evidence, _) = v23_adversarial_success_terminal(
            &fixture.ledger,
            &fixture.attempt,
            &claimed,
            "interval-reversed",
        );
        let reversed_start = evidence.receipt.captured_at_unix_ms.saturating_add(1);
        evidence.receipt.capture_started_at_unix_ms = reversed_start;
        evidence.manifest.capture_started_at_unix_ms = reversed_start;
        let observed_at = evidence.receipt.captured_at_unix_ms;
        let (observation, event) = v23_additional_terminal_from_evidence(
            &fixture.ledger,
            &fixture.attempt,
            &evidence,
            observed_at,
            "interval-reversed",
        );
        let failure = fixture
            .ledger
            .record_claimed_live_state_capture_observation(
                authority,
                &observation,
                &evidence,
                &event,
            )
            .expect_err("capture end cannot precede capture start");
        assert!(failure.has_retry_authority());
        assert_eq!(row_count(&fixture.ledger, "live_state_capture_receipts"), 0);
    }

    {
        let mut fixture = prepare_v23_adversarial_fixture();
        let (claimed, authority) = v23_adversarial_claim(&mut fixture.ledger, &mut fixture.attempt);
        let (_, _, evidence, _) = v23_adversarial_success_terminal(
            &fixture.ledger,
            &fixture.attempt,
            &claimed,
            "interval-observation",
        );
        let crossed_observed_at = evidence.receipt.captured_at_unix_ms.saturating_add(1);
        let (observation, event) = v23_additional_terminal_from_evidence(
            &fixture.ledger,
            &fixture.attempt,
            &evidence,
            crossed_observed_at,
            "interval-observation",
        );
        let failure = fixture
            .ledger
            .record_claimed_live_state_capture_observation(
                authority,
                &observation,
                &evidence,
                &event,
            )
            .expect_err("observation time must equal exact capture finalization time");
        assert!(failure.has_retry_authority());
        assert_eq!(row_count(&fixture.ledger, "live_state_capture_receipts"), 0);
    }
}

#[test]
fn v23_live_state_verifier_launch_and_session_cannot_cross_final_verifier_role() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let plan = fixture.attempt.plan.clone();
    let policy = fixture.attempt.policy.clone();
    let wrong_launch = runner_launch(
        "launch-v23-crossed-final-verifier",
        "session-v23-crossed-final-verifier",
        RunnerSessionPurpose::FinalVerifier,
        None,
        &policy,
        fixture
            .attempt
            .launch
            .created_at_unix_ms
            .saturating_add(100),
    );
    let (cleanup_intent, _, cleanup_request_bytes, cleanup_event) =
        test_runner_launch_cleanup_contracts(
            &fixture.ledger,
            &wrong_launch,
            WorkerCleanupBackend::LinuxCgroupV2,
        )
        .expect("build crossed FinalVerifier cleanup contracts");
    let launch_count = row_count(&fixture.ledger, "runner_launch_intents");
    assert!(
        fixture
            .ledger
            .admit_live_state_verifier_launch_with_cleanup(
                &plan,
                &wrong_launch,
                &policy,
                &cleanup_intent,
                &cleanup_request_bytes,
                &cleanup_event,
            )
            .is_err(),
        "FinalVerifier launch cannot claim LiveStateVerifier plan authority"
    );
    assert_eq!(
        row_count(&fixture.ledger, "runner_launch_intents"),
        launch_count
    );

    let wrong_session = runner_session(
        &wrong_launch,
        wrong_launch.created_at_unix_ms.saturating_add(10),
    );
    assert!(
        fixture
            .ledger
            .register_live_state_verifier_session(&plan, &wrong_session, &policy)
            .is_err(),
        "FinalVerifier session cannot claim LiveStateVerifier plan authority"
    );
    assert!(
        fixture
            .ledger
            .register_runner_session(&fixture.attempt.session, &policy)
            .is_err(),
        "LiveStateVerifier session cannot use the ordinary registration path"
    );
}

#[test]
fn v23_verified_no_op_plan_rejects_an_absent_selected_task_done_source_without_writes() {
    let prepared = prepare_v22_explicit_empty_preparation_fixture();
    let final_verification_receipt_id = prepared.final_evidence.verification.receipt_id;
    let V15CandidateFixture {
        database: _database,
        ledger,
        spec,
        ..
    } = prepared.candidate;
    let policy = compiled_test_policy("policy-v23-additional-no-source");
    let cut = v23_adversarial_latest_cut(&ledger, &spec.sprint_id, "additional-no-source");
    assert!(
        ledger
            .derive_verified_no_op_live_state_capture_plan(
                cut,
                &policy,
                &spec.sprint_id,
                &final_verification_receipt_id,
                "missing-task-done-integration-receipt",
            )
            .is_err(),
        "no absent or caller-selected pseudo-source can derive a no-op plan"
    );
    assert_eq!(row_count(&ledger, "sprint_live_state_capture_plans"), 0);
    assert_eq!(
        row_count(&ledger, "sprint_live_state_capture_admissions"),
        0
    );
}

struct V23UnadmittedLiveStateVerifierAttempt {
    policy: CompiledExecutionPolicy,
    plan: SprintLiveStateCapturePlan,
    launch: RunnerLaunchIntent,
    session: RunnerSessionPolicyRecord,
    admission: SprintLiveStateCaptureAdmission,
    intent: EffectIntent,
    proposed_event: AgentEvent,
}

fn v23_prepare_unadmitted_live_state_verifier_attempt(
    ledger: &mut EventLedger,
    spec: &SprintSpec,
    final_verification_receipt_id: &str,
    task_integration_receipt_id: &str,
    suffix: &str,
    register_session: bool,
) -> V23UnadmittedLiveStateVerifierAttempt {
    let policy = compiled_test_policy(&format!("policy-v23-unadmitted-{suffix}"));
    let cut = v23_adversarial_latest_cut(ledger, &spec.sprint_id, suffix);
    let plan = ledger
        .derive_verified_no_op_live_state_capture_plan(
            cut,
            &policy,
            &spec.sprint_id,
            final_verification_receipt_id,
            task_integration_receipt_id,
        )
        .expect("derive exact unadmitted live-state capture plan");
    let launch = runner_launch(
        &format!("launch-v23-unadmitted-{suffix}"),
        &format!("session-v23-unadmitted-{suffix}"),
        RunnerSessionPurpose::LiveStateVerifier,
        None,
        &policy,
        plan.planned_at_unix_ms.saturating_add(10),
    );
    let (cleanup_intent, _, cleanup_request_bytes, cleanup_event) =
        test_runner_launch_cleanup_contracts(ledger, &launch, WorkerCleanupBackend::LinuxCgroupV2)
            .expect("build unadmitted live-state-verifier cleanup admission");
    ledger
        .admit_live_state_verifier_launch_with_cleanup(
            &plan,
            &launch,
            &policy,
            &cleanup_intent,
            &cleanup_request_bytes,
            &cleanup_event,
        )
        .expect("persist unadmitted live-state-verifier launch and cleanup");
    let session = runner_session(&launch, launch.created_at_unix_ms.saturating_add(10));
    if register_session {
        ledger
            .register_live_state_verifier_session(&plan, &session, &policy)
            .expect("register unadmitted live-state-verifier session");
    }
    let request = SprintLiveStateCaptureRequest::from_plan(plan.clone())
        .expect("construct future live-state capture request");
    let request_bytes =
        encode("future live-state capture request", &request).expect("encode future request");
    let admitted_at_unix_ms = session.registered_at_unix_ms.saturating_add(10);
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: format!("effect-v23-unadmitted-{suffix}"),
        idempotency_key: format!("key-v23-unadmitted-{suffix}"),
        sprint_id: spec.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        worker_lease: None,
        causation_event_id: Some(cleanup_event.event_id.clone()),
        correlation_id: format!("correlation-v23-unadmitted-{suffix}"),
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
            .expect("future capture proposal sequence"),
        &format!("event-v23-unadmitted-{suffix}-proposed"),
    );
    let admission = SprintLiveStateCaptureAdmission {
        contract_version: CONTRACT_VERSION,
        admission_id: format!("admission-v23-unadmitted-{suffix}"),
        plan: plan.clone(),
        request,
        effect_id: intent.effect_id.clone(),
        runner_launch_id: launch.launch_id.clone(),
        runner_session_id: session.session_id.clone(),
        admitted_at_unix_ms,
    };
    V23UnadmittedLiveStateVerifierAttempt {
        policy,
        plan,
        launch,
        session,
        admission,
        intent,
        proposed_event,
    }
}

#[test]
fn unadmitted_live_state_verifier_cleanup_registered_session_closes_and_fences_replay() {
    let prepared = prepare_v22_explicit_empty_preparation_fixture();
    let final_verification_receipt_id = prepared.final_evidence.verification.receipt_id;
    let V15CandidateFixture {
        database: _database,
        mut ledger,
        spec,
        ..
    } = prepared.candidate;
    let task_integration_receipt_id = ledger
        .assess_task_done(&spec.sprint_id, "task-1")
        .expect("assess unadmitted registered-session TaskDone")
        .proof
        .expect("registered-session source is TaskDone")
        .integration_receipt
        .receipt_id;
    let attempt = v23_prepare_unadmitted_live_state_verifier_attempt(
        &mut ledger,
        &spec,
        &final_verification_receipt_id,
        &task_integration_receipt_id,
        "registered",
        true,
    );
    let callback_count = AtomicU64::new(0);
    let cleanup = ledger
        .with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
            &spec.sprint_id,
            &attempt.launch.launch_id,
            &attempt.plan.plan_id,
            |claim| {
                callback_count.fetch_add(1, Ordering::Relaxed);
                assert_eq!(claim.registered_session(), Some(&attempt.session));
                assert_eq!(claim.admission().launch, attempt.launch);
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "v23-unadmitted-registered",
                    attempt.session.registered_at_unix_ms.saturating_add(20),
                ))
            },
        )
        .expect("close exact registered unadmitted live-state verifier");
    assert_eq!(callback_count.load(Ordering::Relaxed), 1);
    assert!(matches!(
        cleanup.finish_receipt,
        PersistedFinishReceipt::WorkerCleanup(_)
    ));

    let replay_count = AtomicU64::new(0);
    assert!(
        ledger
            .with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
                &spec.sprint_id,
                &attempt.launch.launch_id,
                &attempt.plan.plan_id,
                |_| {
                    replay_count.fetch_add(1, Ordering::Relaxed);
                    unreachable!("closed cleanup replay cannot invoke native callback")
                },
            )
            .is_err()
    );
    assert_eq!(replay_count.load(Ordering::Relaxed), 0);
    assert!(
        ledger
            .admit_sprint_live_state_capture_for_dispatch(
                &attempt.admission,
                &attempt.intent,
                &attempt.proposed_event,
            )
            .is_err(),
        "cleanup-first must permanently fence later capture admission"
    );
}

#[test]
fn unadmitted_live_state_verifier_cleanup_sessionless_closes_and_fences_registration() {
    let prepared = prepare_v22_explicit_empty_preparation_fixture();
    let final_verification_receipt_id = prepared.final_evidence.verification.receipt_id;
    let V15CandidateFixture {
        database: _database,
        mut ledger,
        spec,
        ..
    } = prepared.candidate;
    let task_integration_receipt_id = ledger
        .assess_task_done(&spec.sprint_id, "task-1")
        .expect("assess unadmitted sessionless TaskDone")
        .proof
        .expect("sessionless source is TaskDone")
        .integration_receipt
        .receipt_id;
    let attempt = v23_prepare_unadmitted_live_state_verifier_attempt(
        &mut ledger,
        &spec,
        &final_verification_receipt_id,
        &task_integration_receipt_id,
        "sessionless",
        false,
    );
    ledger
        .with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
            &spec.sprint_id,
            &attempt.launch.launch_id,
            &attempt.plan.plan_id,
            |claim| {
                assert_eq!(claim.registered_session(), None);
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "v23-unadmitted-sessionless",
                    attempt.launch.created_at_unix_ms.saturating_add(20),
                ))
            },
        )
        .expect("close exact sessionless unadmitted live-state verifier");
    assert!(
        ledger
            .register_live_state_verifier_session(
                &attempt.plan,
                &attempt.session,
                &attempt.policy,
            )
            .is_err(),
        "cleanup-first must fence later semantic session registration"
    );
}

#[test]
fn unadmitted_live_state_verifier_cleanup_rejects_capture_and_crossed_plan_before_callback() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let capture_before = fixture
        .ledger
        .load_effect(&fixture.attempt.intent.effect_id)
        .expect("snapshot admitted capture before cleanup collision");
    let cleanup_before = fixture
        .ledger
        .load_runner_launch_cleanup_admission(
            &fixture.spec.sprint_id,
            &fixture.attempt.launch.launch_id,
        )
        .expect("snapshot cleanup before capture-admission collision")
        .cleanup_effect;
    let callback_count = AtomicU64::new(0);
    assert!(
        fixture
            .ledger
            .with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
                &fixture.spec.sprint_id,
                &fixture.attempt.launch.launch_id,
                &fixture.attempt.plan.plan_id,
                |_| {
                    callback_count.fetch_add(1, Ordering::Relaxed);
                    unreachable!("capture admission must fence unadmitted cleanup")
                },
            )
            .is_err()
    );
    assert_eq!(callback_count.load(Ordering::Relaxed), 0);
    assert_eq!(
        fixture
            .ledger
            .load_effect(&fixture.attempt.intent.effect_id)
            .expect("capture collision leaves admitted effect unchanged"),
        capture_before
    );
    assert_eq!(
        fixture
            .ledger
            .load_effect(&cleanup_before.intent.effect_id)
            .expect("capture collision leaves cleanup effect unchanged"),
        cleanup_before
    );

    drop(
        fixture
            .attempt
            .permit
            .take()
            .expect("discard capture permit before crossed plan assertion"),
    );
    let crossed_count = AtomicU64::new(0);
    assert!(
        fixture
            .ledger
            .with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
                &fixture.spec.sprint_id,
                &fixture.attempt.launch.launch_id,
                "crossed-live-state-plan",
                |_| {
                    crossed_count.fetch_add(1, Ordering::Relaxed);
                    unreachable!("crossed plan cannot invoke cleanup callback")
                },
            )
            .is_err()
    );
    assert_eq!(crossed_count.load(Ordering::Relaxed), 0);
}
