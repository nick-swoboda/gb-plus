#[derive(Debug)]
struct V23AdversarialCaptureAttempt {
    policy: CompiledExecutionPolicy,
    plan: SprintLiveStateCapturePlan,
    launch: RunnerLaunchIntent,
    session: RunnerSessionPolicyRecord,
    admission: SprintLiveStateCaptureAdmission,
    intent: EffectIntent,
    proposed_event: AgentEvent,
    request_bytes: Vec<u8>,
    permit: Option<FreshLiveStateCaptureDispatchPermit>,
}

struct V23AdversarialFixture {
    database: TestDatabase,
    ledger: EventLedger,
    spec: SprintSpec,
    final_verification_receipt_id: String,
    task_integration_receipt_id: String,
    attempt: V23AdversarialCaptureAttempt,
}

fn v23_adversarial_latest_cut(
    ledger: &EventLedger,
    sprint_id: &str,
    suffix: &str,
) -> SprintLiveStateCapturePlanCut {
    let (source_event_id, source_event_sequence, occurred_at): (String, i64, i64) = ledger
        .connection
        .query_row(
            "SELECT event_id, sequence, occurred_at_unix_ms
             FROM agent_events WHERE sprint_id = ?1
             ORDER BY sequence DESC LIMIT 1",
            [sprint_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("load v23 adversarial high-water event");
    SprintLiveStateCapturePlanCut {
        plan_id: format!("plan-v23-adversarial-{suffix}"),
        source_event_id,
        source_event_sequence: u64::try_from(source_event_sequence)
            .expect("positive v23 source sequence"),
        planned_at_unix_ms: u64::try_from(occurred_at)
            .expect("positive v23 source time")
            .saturating_add(10),
    }
}

fn v23_adversarial_admit_attempt(
    ledger: &mut EventLedger,
    spec: &SprintSpec,
    final_verification_receipt_id: &str,
    task_integration_receipt_id: &str,
    suffix: &str,
) -> V23AdversarialCaptureAttempt {
    let policy = compiled_test_policy(&format!("policy-v23-adversarial-{suffix}"));
    let cut = v23_adversarial_latest_cut(ledger, &spec.sprint_id, suffix);
    let plan = ledger
        .derive_verified_no_op_live_state_capture_plan(
            cut,
            &policy,
            &spec.sprint_id,
            final_verification_receipt_id,
            task_integration_receipt_id,
        )
        .expect("derive exact v23 adversarial no-op capture plan");
    let launch = runner_launch(
        &format!("launch-v23-adversarial-{suffix}"),
        &format!("session-v23-adversarial-{suffix}"),
        RunnerSessionPurpose::LiveStateVerifier,
        None,
        &policy,
        plan.planned_at_unix_ms.saturating_add(10),
    );
    let (cleanup_intent, _, cleanup_request_bytes, cleanup_event) =
        test_runner_launch_cleanup_contracts(ledger, &launch, WorkerCleanupBackend::LinuxCgroupV2)
            .expect("build v23 adversarial LSV cleanup admission");
    ledger
        .admit_live_state_verifier_launch_with_cleanup(
            &plan,
            &launch,
            &policy,
            &cleanup_intent,
            &cleanup_request_bytes,
            &cleanup_event,
        )
        .expect("persist v23 adversarial plan and LSV launch");
    let session = runner_session(&launch, launch.created_at_unix_ms.saturating_add(10));
    ledger
        .register_live_state_verifier_session(&plan, &session, &policy)
        .expect("register v23 adversarial LSV session");
    let request = SprintLiveStateCaptureRequest::from_plan(plan.clone())
        .expect("construct v23 adversarial capture request");
    let request_bytes = encode("v23 adversarial capture request", &request)
        .expect("encode v23 adversarial capture request");
    let admitted_at_unix_ms = session.registered_at_unix_ms.saturating_add(10);
    let intent = EffectIntent {
        contract_version: CONTRACT_VERSION,
        effect_id: format!("effect-v23-adversarial-{suffix}"),
        idempotency_key: format!("key-v23-adversarial-{suffix}"),
        sprint_id: spec.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        worker_lease: None,
        causation_event_id: Some(cleanup_event.event_id.clone()),
        correlation_id: format!("correlation-v23-adversarial-{suffix}"),
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
            .expect("v23 capture proposal sequence"),
        &format!("event-v23-adversarial-{suffix}-proposed"),
    );
    let admission = SprintLiveStateCaptureAdmission {
        contract_version: CONTRACT_VERSION,
        admission_id: format!("admission-v23-adversarial-{suffix}"),
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
        .expect("admit fresh v23 adversarial capture")
    else {
        panic!("first v23 adversarial capture admission must be Fresh");
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

fn prepare_v23_adversarial_fixture() -> V23AdversarialFixture {
    prepare_v23_adversarial_fixture_at_schema(false)
}

fn prepare_historical_v23_adversarial_fixture() -> V23AdversarialFixture {
    prepare_v23_adversarial_fixture_at_schema(true)
}

fn prepare_v23_adversarial_fixture_at_schema(historical_v23: bool) -> V23AdversarialFixture {
    let prepared = if historical_v23 {
        prepare_v22_explicit_empty_preparation_fixture_with_requirement_at_v23(
            CandidateTaskRequirement::Required,
        )
    } else {
        prepare_v22_explicit_empty_preparation_fixture()
    };
    let final_verification_receipt_id = prepared.final_evidence.verification.receipt_id;
    let V15CandidateFixture {
        database,
        mut ledger,
        spec,
        ..
    } = prepared.candidate;
    let task_integration_receipt_id = ledger
        .assess_task_done(&spec.sprint_id, "task-1")
        .expect("assess v23 adversarial TaskDone source")
        .proof
        .expect("v23 adversarial task must be TaskDone")
        .integration_receipt
        .receipt_id;
    let attempt = v23_adversarial_admit_attempt(
        &mut ledger,
        &spec,
        &final_verification_receipt_id,
        &task_integration_receipt_id,
        "first",
    );
    V23AdversarialFixture {
        database,
        ledger,
        spec,
        final_verification_receipt_id,
        task_integration_receipt_id,
        attempt,
    }
}

fn v23_adversarial_exact_claim(
    attempt: &V23AdversarialCaptureAttempt,
) -> PersistedRunnerEffectDispatchClaim {
    PersistedRunnerEffectDispatchClaim {
        dispatch_claim_id: runner_effect_dispatch_claim_id(&attempt.intent.effect_id),
        effect_id: attempt.intent.effect_id.clone(),
        sprint_id: attempt.intent.sprint_id.clone(),
        launch_id: attempt.launch.launch_id.clone(),
        session_id: attempt.session.session_id.clone(),
        running_boundary_id: None,
        authority: RunnerEffectRequestAuthority::SprintLiveStateCapture {
            admission_id: attempt.admission.admission_id.clone(),
        },
        request_digest: attempt.intent.request_digest.clone(),
        opaque_transport_request_digest: Digest::sha256(OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES),
        policy_hash: attempt.intent.policy_hash.clone(),
        input_snapshot: attempt.intent.input_snapshot.clone(),
        contract_version: CONTRACT_VERSION,
    }
}

fn v23_adversarial_claim(
    ledger: &mut EventLedger,
    attempt: &mut V23AdversarialCaptureAttempt,
) -> (PersistedEffect, RunnerEffectObservationAuthority) {
    let (claimed, transport) = ledger
        .claim_sprint_live_state_capture_dispatch(
            attempt
                .permit
                .take()
                .expect("consume sole fresh v23 capture permit"),
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("claim v23 adversarial capture");
    let authority = transport
        .validate_transport_request(
            &attempt.intent,
            &attempt.request_bytes,
            &attempt.launch,
            &attempt.session,
            None,
            OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
        )
        .expect("validate exact v23 adversarial transport request");
    (claimed, authority)
}

fn v23_adversarial_success_terminal(
    ledger: &EventLedger,
    attempt: &V23AdversarialCaptureAttempt,
    claimed: &PersistedEffect,
    suffix: &str,
) -> (
    EffectObservation,
    AgentEvent,
    LiveStateCaptureEvidence,
    Vec<u8>,
) {
    let capture_started_at_unix_ms = attempt.admission.admitted_at_unix_ms.saturating_add(10);
    let captured_at_unix_ms = capture_started_at_unix_ms.saturating_add(10);
    let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
        attempt.plan.grant_hash.clone(),
        capture_started_at_unix_ms,
        captured_at_unix_ms,
        vec![crate::DescriptorRelativeManifestEntry {
            path: format!("capture-{suffix}.txt"),
            content_digest: Digest::sha256(format!("capture contents {suffix}").as_bytes()),
            byte_length: u64::try_from(format!("capture contents {suffix}").len())
                .expect("capture content length"),
            unix_mode: 0o644,
        }],
    )
    .expect("construct v23 adversarial descriptor manifest");
    let claim = claimed
        .dispatch_claim
        .as_ref()
        .expect("claimed v23 effect retains dispatch claim");
    let receipt = LiveStateCaptureReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: format!("receipt-v23-adversarial-{suffix}"),
        admission_id: attempt.admission.admission_id.clone(),
        effect_id: attempt.intent.effect_id.clone(),
        observation_id: format!("observation-v23-adversarial-{suffix}"),
        dispatch_claim_id: claim.dispatch_claim_id.clone(),
        sprint_id: attempt.intent.sprint_id.clone(),
        plan_id: attempt.plan.plan_id.clone(),
        plan_digest: attempt.plan.plan_digest().expect("digest v23 plan"),
        request_digest: attempt
            .admission
            .request
            .request_digest()
            .expect("digest v23 request"),
        branch: attempt.plan.branch.clone(),
        expected_snapshot: attempt.plan.expected_snapshot.clone(),
        observed_snapshot: manifest.manifest_digest.clone(),
        runner_launch_id: attempt.launch.launch_id.clone(),
        runner_session_id: attempt.session.session_id.clone(),
        policy_hash: attempt.plan.policy_hash.clone(),
        grant_hash: attempt.plan.grant_hash.clone(),
        policy_version: attempt.plan.policy_version,
        manifest_digest: manifest.manifest_digest.clone(),
        capture_started_at_unix_ms,
        captured_at_unix_ms,
    };
    let evidence = LiveStateCaptureEvidence {
        contract_version: CONTRACT_VERSION,
        receipt,
        manifest,
    };
    let evidence_bytes = encode("v23 adversarial capture evidence", &evidence)
        .expect("encode v23 adversarial capture evidence");
    let observation = effect_observation(
        &attempt.intent,
        &evidence.receipt.observation_id,
        EffectOutcome::Succeeded {
            evidence_digest: Digest::sha256(&evidence_bytes),
        },
        captured_at_unix_ms,
    );
    let event = effect_terminal_event(
        &attempt.intent,
        &attempt.proposed_event.event_id,
        &observation,
        ledger
            .next_sequence(&attempt.intent.sprint_id)
            .expect("v23 capture terminal sequence"),
        &format!("event-v23-adversarial-{suffix}-finished"),
    );
    (observation, event, evidence, evidence_bytes)
}

fn v23_adversarial_persist_success(
    ledger: &mut EventLedger,
    attempt: &mut V23AdversarialCaptureAttempt,
    suffix: &str,
) -> LiveStateCaptureEvidence {
    let (claimed, authority) = v23_adversarial_claim(ledger, attempt);
    let (observation, event, evidence, _) =
        v23_adversarial_success_terminal(ledger, attempt, &claimed, suffix);
    ledger
        .record_claimed_live_state_capture_observation(authority, &observation, &evidence, &event)
        .expect("persist exact v23 adversarial capture success");
    evidence
}

fn v23_adversarial_unknown_terminal(
    ledger: &EventLedger,
    attempt: &V23AdversarialCaptureAttempt,
    suffix: &str,
) -> (EffectObservation, Vec<u8>, AgentEvent) {
    let evidence_bytes =
        format!("v23 claimed-capture reconciliation evidence:{suffix}").into_bytes();
    let observation = effect_observation(
        &attempt.intent,
        &format!("observation-v23-adversarial-{suffix}"),
        EffectOutcome::Unknown {
            evidence_digest: Digest::sha256(&evidence_bytes),
        },
        attempt.admission.admitted_at_unix_ms.saturating_add(20),
    );
    let event = effect_terminal_event(
        &attempt.intent,
        &attempt.proposed_event.event_id,
        &observation,
        ledger
            .next_sequence(&attempt.intent.sprint_id)
            .expect("v23 reconciliation capture sequence"),
        &format!("event-v23-adversarial-{suffix}"),
    );
    (observation, evidence_bytes, event)
}

fn v23_assert_claimed_reconciliation_rolled_back(
    ledger: &EventLedger,
    attempt: &V23AdversarialCaptureAttempt,
) {
    let capture = ledger
        .load_effect(&attempt.intent.effect_id)
        .expect("reload claimed capture after rolled-back reconciliation");
    assert!(capture.dispatch_claim.is_some());
    assert!(capture.observation.is_none());
    assert!(capture.evidence_bytes.is_none());
    assert!(capture.terminal_event.is_none());
    assert_eq!(capture.finish_receipt, PersistedFinishReceipt::NotRequired);

    let cleanup = ledger
        .load_runner_launch_cleanup_admission(&attempt.intent.sprint_id, &attempt.launch.launch_id)
        .expect("reload open verifier cleanup after rolled-back reconciliation")
        .cleanup_effect;
    assert!(cleanup.observation.is_none());
    assert!(cleanup.evidence_bytes.is_none());
    assert!(cleanup.terminal_event.is_none());
    assert_eq!(cleanup.finish_receipt, PersistedFinishReceipt::NotRequired);
    let capture_receipts: i64 = ledger
        .connection
        .query_row(
            "SELECT COUNT(*) FROM live_state_capture_receipts WHERE effect_id = ?1",
            [&attempt.intent.effect_id],
            |row| row.get(0),
        )
        .expect("count rolled-back typed capture receipts");
    assert_eq!(capture_receipts, 0);
}

#[test]
fn v23_raw_json_totality_rejects_malformed_noncanonical_and_crossed_nested_plans() {
    let fixture = prepare_v23_adversarial_fixture();
    let canonical = encode("v23 adversarial admission", &fixture.attempt.admission)
        .expect("encode exact v23 admission");
    let plan_digest = fixture
        .attempt
        .plan
        .plan_digest()
        .expect("digest exact v23 plan");
    let request_digest = fixture
        .attempt
        .admission
        .request
        .request_digest()
        .expect("digest exact v23 request");
    let exact: i64 = fixture
        .ledger
        .connection
        .query_row(
            "SELECT grok_live_state_capture_admission_matches(?1, ?2, ?3)",
            params![canonical, plan_digest.as_str(), request_digest.as_str()],
            |row| row.get(0),
        )
        .expect("exact canonical admission must match");
    assert_eq!(exact, 1);

    let mut crossed = serde_json::to_value(&fixture.attempt.admission)
        .expect("materialize crossed v23 admission JSON");
    crossed["request"]["plan"]["plan_id"] = serde_json::Value::String("crossed-plan".into());
    let crossed = serde_json::to_vec(&crossed).expect("encode crossed v23 admission JSON");
    for invalid in [b"{".to_vec(), b"null".to_vec(), b"[]".to_vec(), crossed] {
        assert!(
            fixture
                .ledger
                .connection
                .query_row(
                    "SELECT grok_live_state_capture_admission_matches(?1, ?2, ?3)",
                    params![invalid, plan_digest.as_str(), request_digest.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .is_err(),
            "malformed, wrong-shape, or crossed admission JSON must fail closed"
        );
    }
}

#[test]
fn v23_capture_readback_rejects_normalized_manifest_rows_crossed_from_evidence() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let evidence = v23_adversarial_persist_success(
        &mut fixture.ledger,
        &mut fixture.attempt,
        "normalized-cross",
    );
    fixture
        .ledger
        .connection
        .execute_batch("DROP TRIGGER live_state_capture_manifest_entries_no_update;")
        .expect("drop manifest immutability trigger for corruption injection");
    fixture
        .ledger
        .connection
        .execute(
            "UPDATE live_state_capture_manifest_entries
             SET content_digest = ?1 WHERE receipt_id = ?2 AND entry_ordinal = 0",
            params![digest('f').as_str(), evidence.receipt.receipt_id],
        )
        .expect("inject normalized manifest crossing");
    assert!(matches!(
        fixture
            .ledger
            .load_live_state_capture_evidence(&evidence.receipt.receipt_id),
        Err(LedgerError::Corrupt { .. } | LedgerError::Contract(_))
    ));
}

#[test]
fn v23_capture_readback_rejects_effect_payload_bytes_crossed_from_typed_evidence() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let evidence =
        v23_adversarial_persist_success(&mut fixture.ledger, &mut fixture.attempt, "payload-cross");
    fixture
        .ledger
        .connection
        .execute_batch("DROP TRIGGER effect_evidence_payloads_no_update;")
        .expect("drop payload immutability trigger for corruption injection");
    fixture
        .ledger
        .connection
        .execute(
            "UPDATE effect_evidence_payloads SET evidence_bytes = X'00'
             WHERE effect_id = ?1",
            [&evidence.receipt.effect_id],
        )
        .expect("inject v23 effect payload mismatch");
    assert!(
        fixture
            .ledger
            .load_live_state_capture_evidence(&evidence.receipt.receipt_id)
            .is_err(),
        "typed capture readback must reject crossed effect evidence bytes"
    );
}

#[test]
fn v23_capture_receipt_identity_cannot_collide_with_v9_completion() {
    let mut fixture = prepare_historical_v23_adversarial_fixture();
    assert_eq!(
        fixture
            .ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
            .expect("read exact historical capture schema"),
        23
    );
    let evidence =
        v23_adversarial_persist_success(&mut fixture.ledger, &mut fixture.attempt, "v9-collision");
    let error = fixture
        .ledger
        .connection
        .execute(
            "INSERT INTO v9_completion_receipts (
                receipt_id, sprint_id, final_snapshot, grant_hash, policy_version,
                final_verification_receipt_id, application_kind,
                application_receipt_id, rollback_reference_id,
                verified_no_op_receipt_id, final_report_id, provider_backend,
                provider_model, contract_version, completed_at_unix_ms, receipt_json
             ) VALUES (
                ?1, ?2, ?3, ?4, 1, ?5, 'VerifiedNoOp',
                NULL, NULL, 'missing-no-op', 'missing-report', 'fake',
                'deterministic', ?6, 9999, X'7B7D'
             )",
            params![
                evidence.receipt.receipt_id,
                evidence.receipt.sprint_id,
                evidence.receipt.expected_snapshot.as_str(),
                evidence.receipt.grant_hash.as_str(),
                fixture.final_verification_receipt_id,
                i64::from(CONTRACT_VERSION),
            ],
        )
        .expect_err("v9 completion ID must not collide with a capture receipt");
    assert!(
        error.to_string().contains("live-state capture"),
        "unexpected global receipt-namespace error: {error}"
    );
}

#[test]
fn v23_raw_claim_requires_exact_capture_companion_not_missing_crossed_or_ordinary_marker() {
    let fixture = prepare_v23_adversarial_fixture();
    let claim = v23_adversarial_exact_claim(&fixture.attempt);

    let transaction = fixture
        .ledger
        .connection
        .unchecked_transaction()
        .expect("start missing-companion transaction");
    assert!(insert_runner_effect_dispatch_claim(&transaction, &claim).is_err());
    transaction
        .rollback()
        .expect("roll back missing capture companion");

    let mut crossed_digest = claim.opaque_transport_request_digest.clone();
    crossed_digest = if crossed_digest == digest('f') {
        digest('e')
    } else {
        digest('f')
    };
    let crossed = LiveStateCaptureDispatchClaimAuthority {
        contract_version: CONTRACT_VERSION,
        dispatch_claim_id: claim.dispatch_claim_id.clone(),
        sprint_id: claim.sprint_id.clone(),
        admission_id: fixture.attempt.admission.admission_id.clone(),
        effect_id: claim.effect_id.clone(),
        opaque_transport_request_digest: crossed_digest,
    };
    let transaction = fixture
        .ledger
        .connection
        .unchecked_transaction()
        .expect("start crossed-companion transaction");
    transaction
        .execute(
            "INSERT INTO live_state_capture_dispatch_claim_authorities (
                dispatch_claim_id, sprint_id, admission_id, effect_id,
                authority_class, opaque_transport_request_digest,
                contract_version, authority_json
             ) VALUES (?1, ?2, ?3, ?4, 'SprintLiveStateCapture', ?5, ?6, ?7)",
            params![
                crossed.dispatch_claim_id,
                crossed.sprint_id,
                crossed.admission_id,
                crossed.effect_id,
                crossed.opaque_transport_request_digest.as_str(),
                i64::from(CONTRACT_VERSION),
                encode("crossed v23 claim companion", &crossed)
                    .expect("encode crossed v23 companion"),
            ],
        )
        .expect("preinsert structurally valid crossed companion");
    assert!(insert_runner_effect_dispatch_claim(&transaction, &claim).is_err());
    transaction
        .rollback()
        .expect("roll back crossed capture companion");

    let transaction = fixture
        .ledger
        .connection
        .unchecked_transaction()
        .expect("start ordinary-marker transaction");
    transaction
        .execute(
            "INSERT INTO runner_effect_dispatch_claim_authorities (
                dispatch_claim_id, authority_class, running_boundary_id,
                formal_check_admission_id, integration_admission_id,
                sprint_phase_event_id, rollback_reference_id, contract_version
             ) VALUES (?1, 'SprintFinalVerification', NULL, NULL, NULL, ?2, NULL, ?3)",
            params![
                claim.dispatch_claim_id,
                fixture.attempt.plan.source_event_id,
                i64::from(CONTRACT_VERSION),
            ],
        )
        .expect("preinsert ordinary authority marker");
    assert!(insert_runner_effect_dispatch_claim(&transaction, &claim).is_err());
    transaction
        .rollback()
        .expect("roll back ordinary capture marker");
}

#[test]
fn v23_claimless_and_generic_claimed_success_cannot_bypass_typed_capture_receipt() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let (claimed, authority) = v23_adversarial_claim(&mut fixture.ledger, &mut fixture.attempt);
    let (observation, event, evidence, evidence_bytes) =
        v23_adversarial_success_terminal(&fixture.ledger, &fixture.attempt, &claimed, "typed-only");
    assert!(
        fixture
            .ledger
            .record_effect_observation(&observation, &evidence_bytes, &event)
            .is_err(),
        "claimless generic observation cannot close a claimed capture"
    );
    let generic_failure = fixture
        .ledger
        .try_record_claimed_effect_observation(authority, &observation, &evidence_bytes, &event)
        .expect_err("generic claimed success cannot close SprintLiveStateCapture");
    let (_, authority) = generic_failure.into_parts();
    fixture
        .ledger
        .record_claimed_live_state_capture_observation(
            authority.expect("generic precommit rejection returns exact authority"),
            &observation,
            &evidence,
            &event,
        )
        .expect("typed retry persists exact capture receipt");
}

#[test]
fn v23_two_connection_success_race_serializes_to_one_typed_capture() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let mut stale =
        EventLedger::open(&fixture.database.path).expect("open stale v23 capture contender");
    let (claimed, authority) = v23_adversarial_claim(&mut fixture.ledger, &mut fixture.attempt);
    let (observation, event, evidence, evidence_bytes) = v23_adversarial_success_terminal(
        &fixture.ledger,
        &fixture.attempt,
        &claimed,
        "two-connection",
    );
    assert!(
        stale
            .record_effect_observation(&observation, &evidence_bytes, &event)
            .is_err(),
        "competing connection cannot write a claimless success"
    );
    fixture
        .ledger
        .record_claimed_live_state_capture_observation(authority, &observation, &evidence, &event)
        .expect("claim-owning connection commits sole typed success");
    assert_eq!(
        fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM live_state_capture_receipts WHERE sprint_id = ?1",
                [&fixture.spec.sprint_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("count v23 capture successes"),
        1
    );
    assert!(matches!(
        stale.admit_sprint_live_state_capture_for_dispatch(
            &fixture.attempt.admission,
            &fixture.attempt.intent,
            &fixture.attempt.proposed_event,
        ),
        Ok(SprintLiveStateCaptureDispatchAdmission::Existing { effect, .. })
            if effect.observation.as_ref() == Some(&observation)
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the adversarial retry-cut case verifies one atomic lifecycle"
)]
fn v23_retry_cut_includes_prior_lsv_cleanup_and_keeps_first_plan_readable() {
    let mut fixture = prepare_v23_adversarial_fixture();
    drop(
        fixture
            .attempt
            .permit
            .take()
            .expect("discard first capture permit before runner I/O"),
    );
    let failure_bytes = b"v23 capture rejected before any request byte".to_vec();
    let failed_at = fixture
        .attempt
        .admission
        .admitted_at_unix_ms
        .saturating_add(10);
    let observation = effect_observation(
        &fixture.attempt.intent,
        "observation-v23-adversarial-first-before-effect",
        EffectOutcome::FailedBeforeEffect {
            evidence_digest: Digest::sha256(&failure_bytes),
        },
        failed_at,
    );
    let event = effect_terminal_event(
        &fixture.attempt.intent,
        &fixture.attempt.proposed_event.event_id,
        &observation,
        fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("first capture failure sequence"),
        "event-v23-adversarial-first-before-effect",
    );
    fixture
        .ledger
        .record_unclaimed_live_state_capture_before_effect_terminal(
            &observation,
            &failure_bytes,
            &event,
        )
        .expect("persist first capture's definite pre-effect failure");
    let first_cleanup = fixture
        .ledger
        .with_runner_launch_cleanup_exclusion(
            &fixture.spec.sprint_id,
            &fixture.attempt.launch.launch_id,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "v23-adversarial-first-retry",
                    failed_at.saturating_add(10),
                ))
            },
        )
        .expect("close first failed LSV before retry");
    let first_cleanup_receipt_id = match first_cleanup.finish_receipt {
        PersistedFinishReceipt::WorkerCleanup(evidence) => evidence.receipt.receipt_id,
        other => panic!("expected first LSV cleanup receipt, got {other:?}"),
    };
    let first_plan = fixture.attempt.plan.clone();
    let second = v23_prepare_unadmitted_live_state_verifier_attempt(
        &mut fixture.ledger,
        &fixture.spec,
        &fixture.final_verification_receipt_id,
        &fixture.task_integration_receipt_id,
        "second",
        true,
    );
    assert!(
        second
            .plan
            .required_cleanup_receipt_ids
            .contains(&first_cleanup_receipt_id)
    );
    assert_eq!(
        second.plan.required_cleanup_receipt_ids.len(),
        first_plan.required_cleanup_receipt_ids.len() + 1
    );
    assert!(second.plan.source_event_sequence > first_plan.source_event_sequence);
    assert_eq!(
        fixture
            .ledger
            .load_sprint_live_state_capture_plan(&first_plan.plan_id)
            .expect("historical first capture plan remains readable after retry"),
        first_plan
    );
    fixture
        .ledger
        .with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
            &fixture.spec.sprint_id,
            &second.launch.launch_id,
            &second.plan.plan_id,
            |claim| {
                assert_eq!(claim.registered_session(), Some(&second.session));
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "v23-adversarial-second-unadmitted-retry",
                    second.session.registered_at_unix_ms.saturating_add(20),
                ))
            },
        )
        .expect(
            "historical failed-and-cleaned capture must not block later unadmitted retry cleanup",
        );
}

#[test]
fn v23_success_restart_never_remints_relaunches_redispatches_or_recaptures() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let evidence =
        v23_adversarial_persist_success(&mut fixture.ledger, &mut fixture.attempt, "restart-fence");
    fixture
        .ledger
        .with_runner_launch_cleanup_exclusion(
            &fixture.spec.sprint_id,
            &fixture.attempt.launch.launch_id,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "v23-adversarial-restart-fence",
                    evidence.receipt.captured_at_unix_ms.saturating_add(10),
                ))
            },
        )
        .expect("clean successful capture LSV before restart");
    let database_path = fixture.database.path.clone();
    let spec = fixture.spec.clone();
    let attempt = fixture.attempt;
    let final_verification_receipt_id = fixture.final_verification_receipt_id;
    let task_integration_receipt_id = fixture.task_integration_receipt_id;
    drop(fixture.ledger);

    let mut reopened = EventLedger::open(&database_path).expect("reopen successful v23 ledger");
    assert!(matches!(
        reopened.admit_sprint_live_state_capture_for_dispatch(
            &attempt.admission,
            &attempt.intent,
            &attempt.proposed_event,
        ),
        Ok(SprintLiveStateCaptureDispatchAdmission::Existing { effect, .. })
            if effect.observation.is_some() && effect.dispatch_claim.is_some()
    ));
    assert_eq!(
        reopened
            .load_live_state_capture_evidence(&evidence.receipt.receipt_id)
            .expect("reload sole successful capture after restart"),
        evidence
    );
    let cut = v23_adversarial_latest_cut(&reopened, &spec.sprint_id, "forbidden-recapture");
    assert!(
        reopened
            .derive_verified_no_op_live_state_capture_plan(
                cut,
                &attempt.policy,
                &spec.sprint_id,
                &final_verification_receipt_id,
                &task_integration_receipt_id,
            )
            .is_err(),
        "one successful capture permanently closes recapture planning"
    );
    assert_eq!(
        row_count(&reopened, "sprint_live_state_capture_admissions"),
        1
    );
    assert_eq!(
        row_count(&reopened, "live_state_capture_dispatch_claim_authorities"),
        1
    );
    assert_eq!(row_count(&reopened, "live_state_capture_receipts"), 1);
    assert_eq!(
        row_count(&reopened, "live_state_verifier_launch_purposes"),
        1
    );
}

#[test]
#[allow(clippy::too_many_lines)] // One round trip proves evidence fidelity and the downstream drift gate together.
fn v23_success_round_trip_retains_truthful_drift_and_completion_ineligibility() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let evidence =
        v23_adversarial_persist_success(&mut fixture.ledger, &mut fixture.attempt, "drift");
    let expected_evidence_bytes =
        encode("v23 drift capture evidence", &evidence).expect("encode exact v23 drift evidence");
    let persisted = fixture
        .ledger
        .load_effect(&fixture.attempt.intent.effect_id)
        .expect("reload truthful drift capture effect");
    assert_eq!(
        fixture
            .ledger
            .load_live_state_capture_evidence(&evidence.receipt.receipt_id)
            .expect("reload truthful drift capture evidence"),
        evidence
    );
    assert_eq!(
        persisted.evidence_bytes.as_deref(),
        Some(expected_evidence_bytes.as_slice())
    );
    assert_eq!(
        evidence.receipt.capture_started_at_unix_ms,
        fixture
            .attempt
            .admission
            .admitted_at_unix_ms
            .saturating_add(10)
    );
    assert_eq!(
        evidence.receipt.captured_at_unix_ms,
        evidence
            .receipt
            .capture_started_at_unix_ms
            .saturating_add(10)
    );
    assert_eq!(
        persisted
            .observation
            .as_ref()
            .expect("truthful drift capture has terminal observation")
            .observed_at_unix_ms,
        evidence.receipt.captured_at_unix_ms
    );
    assert_ne!(
        evidence.receipt.observed_snapshot,
        evidence.receipt.expected_snapshot
    );
    assert!(!evidence.matches_expected_snapshot());

    let cleanup = fixture
        .ledger
        .with_runner_launch_cleanup_exclusion(
            &fixture.spec.sprint_id,
            &fixture.attempt.launch.launch_id,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "v23-adversarial-drift",
                    evidence.receipt.captured_at_unix_ms.saturating_add(10),
                ))
            },
        )
        .expect("close truthful drift verifier launch");
    let cleanup_evidence = match cleanup.finish_receipt {
        PersistedFinishReceipt::WorkerCleanup(evidence) => evidence,
        other => panic!("expected drift verifier cleanup receipt, got {other:?}"),
    };
    let proof = fixture
        .ledger
        .assess_task_done(&fixture.spec.sprint_id, "task-1")
        .expect("assess drift completion TaskDone source")
        .proof
        .expect("drift completion source remains TaskDone");
    let accepted_at_unix_ms = cleanup_evidence
        .receipt
        .cleaned_at_unix_ms
        .saturating_add(20);
    let acceptance = AcceptanceReceipt {
        receipt_id: "acceptance-v23-drift".into(),
        sprint_id: fixture.spec.sprint_id.clone(),
        criterion_id: "tests".into(),
        snapshot_id: fixture.spec.base_snapshot.clone(),
        evidence: AcceptanceEvidence::Automated {
            verification_receipt_id: fixture.final_verification_receipt_id.clone(),
        },
        accepted_at_unix_ms,
    };
    fixture
        .ledger
        .persist_acceptance_receipt(&acceptance)
        .expect("persist drift completion acceptance");
    let body = "A truthful live capture observed workspace drift.".to_owned();
    let report = FinalReport {
        report_id: "report-v23-drift".into(),
        sprint_id: fixture.spec.sprint_id.clone(),
        final_snapshot: fixture.spec.base_snapshot.clone(),
        content_digest: FinalReport::digest_body(&body),
        body,
        created_at_unix_ms: acceptance.accepted_at_unix_ms.saturating_add(10),
    };
    let cleanup_receipt_ids = {
        let mut statement = fixture
            .ledger
            .connection
            .prepare(
                "SELECT receipt_id FROM worker_cleanup_receipts
                 WHERE sprint_id = ?1 ORDER BY receipt_id ASC",
            )
            .expect("prepare drift cleanup receipt query");
        statement
            .query_map([&fixture.spec.sprint_id], |row| row.get::<_, String>(0))
            .expect("query drift cleanup receipt IDs")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect drift cleanup receipt IDs")
    };
    let mut verification_receipts = proof
        .integration_receipt
        .task_verification_receipt_ids
        .clone();
    verification_receipts.push(fixture.final_verification_receipt_id.clone());
    verification_receipts.sort();
    let completion = CompletionReceipt {
        contract_version: CONTRACT_VERSION,
        receipt_id: "completion-v23-drift".into(),
        sprint_id: fixture.spec.sprint_id.clone(),
        grant_hash: fixture.spec.workspace_grant.grant_hash.clone(),
        policy_version: fixture.spec.workspace_grant.policy_version,
        final_snapshot: fixture.spec.base_snapshot.clone(),
        final_verification_receipt_id: fixture.final_verification_receipt_id.clone(),
        application: CompletionApplication::VerifiedNoOp {
            verified_no_op_receipt_id: "verified-no-op-v23-drift".into(),
        },
        worker_cleanup_receipt_ids: cleanup_receipt_ids,
        satisfied_criterion_ids: vec!["tests".into()],
        criterion_evidence_receipt_ids: vec![acceptance.receipt_id.clone()],
        task_integration_receipt_ids: vec![proof.integration_receipt.receipt_id],
        verification_receipts,
        provider_backend: fixture.spec.provider.backend_id.clone(),
        provider_model: fixture.spec.provider.model_id.clone(),
        final_report_id: report.report_id.clone(),
        completed_at_unix_ms: report.created_at_unix_ms.saturating_add(10),
    };
    let completion_event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("drift completion sequence"),
        event_id: "event-v23-drift-completed".into(),
        sprint_id: fixture.spec.sprint_id.clone(),
        task_id: None,
        worker_id: None,
        causation_id: None,
        correlation_id: "v23-drift-completion".into(),
        policy_hash: None,
        occurred_at_unix_ms: completion.completed_at_unix_ms,
        payload: AgentEventKind::CompletionRecorded(completion.receipt_id.clone()),
    };
    let assessment = fixture
        .ledger
        .assess_completion_eligibility_from_live_state_capture(
            &report,
            &completion,
            &evidence.receipt.receipt_id,
            &completion_event,
        )
        .expect("assess truthful drift completion candidate");
    assert!(!assessment.is_eligible());
    assert!(
        assessment
            .unmet_requirements
            .contains(&CompletionEligibilityRequirement::LiveStateCaptureExact)
    );
    assert!(
        assessment
            .unmet_requirements
            .contains(&CompletionEligibilityRequirement::VerifiedNoOpLiveManifestCaptureAuthorized)
    );
    assert!(
        assessment
            .unmet_requirements
            .contains(&CompletionEligibilityRequirement::ApplicationOrVerifiedNoOpExact)
    );
    let error = fixture
        .ledger
        .record_successful_completion_from_live_state_capture(
            &report,
            &completion,
            &evidence.receipt.receipt_id,
            &completion_event,
        )
        .expect_err("truthful drift cannot write a completion or derive a no-op receipt");
    assert!(matches!(
        error,
        LedgerError::ReferenceMismatch {
            entity: "completion live-state capture link",
            ..
        }
    ));
    assert_no_completion_writes(&fixture.ledger);
    assert_eq!(row_count(&fixture.ledger, "verified_no_op_receipts"), 0);
    assert_eq!(
        row_count(
            &fixture.ledger,
            "sprint_completion_live_state_capture_links"
        ),
        0
    );
}

#[test]
fn v23_claimed_unknown_and_exact_cleanup_commit_atomically_at_consecutive_events() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let (_, authority) = v23_adversarial_claim(&mut fixture.ledger, &mut fixture.attempt);
    drop(authority);
    let (observation, evidence_bytes, event) =
        v23_adversarial_unknown_terminal(&fixture.ledger, &fixture.attempt, "unknown-atomic");
    let cleanup_called = std::cell::Cell::new(0_u8);
    let (capture, cleanup) = fixture
        .ledger
        .with_claimed_live_state_capture_reconciliation_cleanup_exclusion(
            &fixture.spec.sprint_id,
            &fixture.attempt.launch.launch_id,
            &observation,
            &evidence_bytes,
            &event,
            |claim| {
                cleanup_called.set(cleanup_called.get().saturating_add(1));
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "v23-adversarial-unknown-atomic",
                    observation.observed_at_unix_ms.saturating_add(10),
                ))
            },
        )
        .expect("atomically reconcile claimed capture and verifier cleanup");
    assert_eq!(cleanup_called.get(), 1);
    assert_eq!(capture.observation.as_ref(), Some(&observation));
    assert_eq!(
        capture.evidence_bytes.as_deref(),
        Some(evidence_bytes.as_slice())
    );
    assert_eq!(capture.terminal_event.as_ref(), Some(&event));
    assert_eq!(capture.finish_receipt, PersistedFinishReceipt::NotRequired);
    assert_eq!(
        cleanup
            .terminal_event
            .as_ref()
            .expect("atomic cleanup terminal event")
            .sequence,
        event.sequence.saturating_add(1)
    );
    assert!(matches!(
        &cleanup.finish_receipt,
        PersistedFinishReceipt::WorkerCleanup(_)
    ));
    assert_eq!(
        fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM live_state_capture_receipts WHERE effect_id = ?1",
                [&fixture.attempt.intent.effect_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("count Unknown typed capture receipts"),
        0
    );

    let reopened = EventLedger::open(&fixture.database.path)
        .expect("reopen atomically reconciled claimed capture");
    assert_eq!(
        reopened
            .load_effect(&fixture.attempt.intent.effect_id)
            .expect("reload reconciled claimed capture"),
        capture
    );
    assert_eq!(
        reopened
            .load_effect(&cleanup.intent.effect_id)
            .expect("reload atomic verifier cleanup"),
        cleanup
    );
}

#[test]
fn v23_claimed_reconciliation_callback_and_late_precommit_failures_roll_back_both_effects() {
    let mut fixture = prepare_v23_adversarial_fixture();
    let (_, authority) = v23_adversarial_claim(&mut fixture.ledger, &mut fixture.attempt);
    drop(authority);
    let (observation, evidence_bytes, event) =
        v23_adversarial_unknown_terminal(&fixture.ledger, &fixture.attempt, "rollback-cuts");

    let callback_called = std::cell::Cell::new(false);
    fixture
        .ledger
        .with_claimed_live_state_capture_reconciliation_cleanup_exclusion(
            &fixture.spec.sprint_id,
            &fixture.attempt.launch.launch_id,
            &observation,
            &evidence_bytes,
            &event,
            |_| {
                callback_called.set(true);
                Err(reference_mismatch(
                    "v23 adversarial cleanup callback",
                    "injected native cleanup failure",
                ))
            },
        )
        .expect_err("cleanup callback failure must roll back capture reconciliation");
    assert!(callback_called.get());
    v23_assert_claimed_reconciliation_rolled_back(&fixture.ledger, &fixture.attempt);

    let colliding_receipt_id = fixture.task_integration_receipt_id.clone();
    let late_callback_called = std::cell::Cell::new(false);
    fixture
        .ledger
        .with_claimed_live_state_capture_reconciliation_cleanup_exclusion(
            &fixture.spec.sprint_id,
            &fixture.attempt.launch.launch_id,
            &observation,
            &evidence_bytes,
            &event,
            |claim| {
                late_callback_called.set(true);
                let mut terminal = cleanup_terminal_from_live_claim(
                    claim,
                    "v23-adversarial-late-precommit",
                    observation.observed_at_unix_ms.saturating_add(10),
                );
                terminal.evidence.receipt.receipt_id = colliding_receipt_id.clone();
                let cleanup_bytes = encode(
                    "v23 adversarial colliding cleanup evidence",
                    &terminal.evidence,
                )?;
                terminal.observation.outcome = EffectOutcome::Succeeded {
                    evidence_digest: Digest::sha256(&cleanup_bytes),
                };
                Ok(terminal)
            },
        )
        .expect_err("late cleanup receipt collision must roll back both observations");
    assert!(late_callback_called.get());
    v23_assert_claimed_reconciliation_rolled_back(&fixture.ledger, &fixture.attempt);
}

#[test]
#[allow(clippy::too_many_lines)] // Three recovery-ineligible lifecycle shapes must all stop before native cleanup.
fn v23_claimed_reconciliation_rejects_crossed_launch_success_and_prior_observation_without_callback()
 {
    let mut successful = prepare_v23_adversarial_fixture();
    let (claimed, success_authority) =
        v23_adversarial_claim(&mut successful.ledger, &mut successful.attempt);
    let crossed_launch_id = successful
        .ledger
        .connection
        .query_row(
            "SELECT launch_id FROM runner_launch_intents
             WHERE sprint_id = ?1 AND launch_id != ?2
             ORDER BY launch_id ASC LIMIT 1",
            params![
                successful.spec.sprint_id,
                successful.attempt.launch.launch_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .expect("load same-sprint crossed ordinary launch");
    let (crossed_observation, crossed_bytes, crossed_event) = v23_adversarial_unknown_terminal(
        &successful.ledger,
        &successful.attempt,
        "crossed-reconciliation-launch",
    );
    let crossed_callback = std::cell::Cell::new(false);
    successful
        .ledger
        .with_claimed_live_state_capture_reconciliation_cleanup_exclusion(
            &successful.spec.sprint_id,
            &crossed_launch_id,
            &crossed_observation,
            &crossed_bytes,
            &crossed_event,
            |_| {
                crossed_callback.set(true);
                unreachable!("crossed launch must reject before cleanup callback")
            },
        )
        .expect_err("crossed ordinary launch cannot reconcile capture claim");
    assert!(!crossed_callback.get());

    let (success_observation, success_event, success_evidence, _) =
        v23_adversarial_success_terminal(
            &successful.ledger,
            &successful.attempt,
            &claimed,
            "reconciliation-already-successful",
        );
    successful
        .ledger
        .record_claimed_live_state_capture_observation(
            success_authority,
            &success_observation,
            &success_evidence,
            &success_event,
        )
        .expect("persist successful capture before recovery rejection");
    let (unknown_after_success, unknown_after_success_bytes, unknown_after_success_event) =
        v23_adversarial_unknown_terminal(
            &successful.ledger,
            &successful.attempt,
            "reconciliation-after-success",
        );
    let success_callback = std::cell::Cell::new(false);
    successful
        .ledger
        .with_claimed_live_state_capture_reconciliation_cleanup_exclusion(
            &successful.spec.sprint_id,
            &successful.attempt.launch.launch_id,
            &unknown_after_success,
            &unknown_after_success_bytes,
            &unknown_after_success_event,
            |_| {
                success_callback.set(true);
                unreachable!("successful capture must reject before cleanup callback")
            },
        )
        .expect_err("already-successful capture cannot enter Unknown reconciliation");
    assert!(!success_callback.get());

    let mut observed = prepare_v23_adversarial_fixture();
    let (_, observation_authority) =
        v23_adversarial_claim(&mut observed.ledger, &mut observed.attempt);
    let known_failure_bytes = b"v23 claimed capture known post-effect failure".to_vec();
    let known_failure = effect_observation(
        &observed.attempt.intent,
        "observation-v23-adversarial-known-failure",
        EffectOutcome::FailedAfterKnownEffect {
            evidence_digest: Digest::sha256(&known_failure_bytes),
        },
        observed
            .attempt
            .admission
            .admitted_at_unix_ms
            .saturating_add(20),
    );
    let known_failure_event = effect_terminal_event(
        &observed.attempt.intent,
        &observed.attempt.proposed_event.event_id,
        &known_failure,
        observed
            .ledger
            .next_sequence(&observed.spec.sprint_id)
            .expect("known failure event sequence"),
        "event-v23-adversarial-known-failure",
    );
    observed
        .ledger
        .try_record_claimed_effect_observation(
            observation_authority,
            &known_failure,
            &known_failure_bytes,
            &known_failure_event,
        )
        .expect("persist claimed capture's definite known failure");
    let (
        unknown_after_observation,
        unknown_after_observation_bytes,
        unknown_after_observation_event,
    ) = v23_adversarial_unknown_terminal(
        &observed.ledger,
        &observed.attempt,
        "reconciliation-after-observation",
    );
    let observed_callback = std::cell::Cell::new(false);
    observed
        .ledger
        .with_claimed_live_state_capture_reconciliation_cleanup_exclusion(
            &observed.spec.sprint_id,
            &observed.attempt.launch.launch_id,
            &unknown_after_observation,
            &unknown_after_observation_bytes,
            &unknown_after_observation_event,
            |_| {
                observed_callback.set(true);
                unreachable!("observed capture must reject before cleanup callback")
            },
        )
        .expect_err("already-observed claimed capture cannot enter reconciliation");
    assert!(!observed_callback.get());
}

#[test]
fn v23_unclaimed_before_effect_terminal_reloads_without_claim_or_typed_receipt() {
    let mut fixture = prepare_v23_adversarial_fixture();
    drop(
        fixture
            .attempt
            .permit
            .take()
            .expect("abandon unclaimed capture before runner I/O"),
    );
    let evidence_bytes = b"v23 unclaimed capture failed before effect".to_vec();
    let observation = effect_observation(
        &fixture.attempt.intent,
        "observation-v23-adversarial-unclaimed-before-effect",
        EffectOutcome::FailedBeforeEffect {
            evidence_digest: Digest::sha256(&evidence_bytes),
        },
        fixture
            .attempt
            .admission
            .admitted_at_unix_ms
            .saturating_add(10),
    );
    let event = effect_terminal_event(
        &fixture.attempt.intent,
        &fixture.attempt.proposed_event.event_id,
        &observation,
        fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("unclaimed capture terminal sequence"),
        "event-v23-adversarial-unclaimed-before-effect",
    );
    let persisted = fixture
        .ledger
        .record_unclaimed_live_state_capture_before_effect_terminal(
            &observation,
            &evidence_bytes,
            &event,
        )
        .expect("close exact pristine unclaimed capture");
    assert!(persisted.dispatch_claim.is_none());
    assert_eq!(persisted.observation.as_ref(), Some(&observation));
    assert_eq!(
        persisted.evidence_bytes.as_deref(),
        Some(evidence_bytes.as_slice())
    );
    assert_eq!(persisted.terminal_event.as_ref(), Some(&event));
    assert_eq!(
        persisted.finish_receipt,
        PersistedFinishReceipt::NotRequired
    );
    assert_eq!(
        fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM live_state_capture_receipts WHERE effect_id = ?1",
                [&fixture.attempt.intent.effect_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("count unclaimed typed capture receipts"),
        0
    );
    assert_eq!(
        fixture
            .ledger
            .load_sprint_live_state_capture_admission(&fixture.attempt.admission.admission_id)
            .expect("reload immutable unclaimed capture admission"),
        fixture.attempt.admission
    );

    let reopened = EventLedger::open(&fixture.database.path)
        .expect("reopen unclaimed before-effect terminal ledger");
    assert_eq!(
        reopened
            .load_effect(&fixture.attempt.intent.effect_id)
            .expect("reload unclaimed before-effect capture"),
        persisted
    );
}
