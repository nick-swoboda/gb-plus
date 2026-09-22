struct V25DriftBlockedFixture {
    _database: TestDatabase,
    ledger: EventLedger,
    evidence: SprintTerminalEvidence,
    outcome: PersistedTerminalOutcome,
}

struct V25DriftReadyFixture {
    database: TestDatabase,
    ledger: EventLedger,
    evidence: SprintTerminalEvidence,
    capture: LiveStateCaptureEvidence,
    verifier_cleanup: WorkerCleanupEvidence,
}

fn prepare_v25_drift_ready_fixture(suffix: &str) -> V25DriftReadyFixture {
    let mut capture_fixture = prepare_v23_adversarial_fixture();
    let capture = v23_adversarial_persist_success(
        &mut capture_fixture.ledger,
        &mut capture_fixture.attempt,
        &format!("v25-{suffix}"),
    );
    let cleanup = capture_fixture
        .ledger
        .with_runner_launch_cleanup_exclusion(
            &capture_fixture.spec.sprint_id,
            &capture_fixture.attempt.launch.launch_id,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    &format!("v25-{suffix}"),
                    capture.receipt.captured_at_unix_ms.saturating_add(10),
                ))
            },
        )
        .expect("close the v25 drift fixture's live-state verifier");
    let verifier_cleanup = match cleanup.finish_receipt {
        PersistedFinishReceipt::WorkerCleanup(evidence) => evidence,
        other => panic!("expected v25 verifier cleanup evidence, got {other:?}"),
    };
    assert!(matches!(
        capture_fixture
            .ledger
            .load_command_domain_cleanup_completeness(
                &capture_fixture.spec.sprint_id,
                &capture_fixture.attempt.launch.launch_id,
                &capture_fixture.attempt.session.session_id,
                CommandDomainBackend::LinuxCgroupV2,
            )
            .expect("load the v25 verifier command-domain cleanup"),
        CommandDomainCleanupCompleteness::Complete(_)
    ));

    let evidence = SprintTerminalEvidence {
        contract_version: CONTRACT_VERSION,
        record_id: format!("terminal-v25-drift-{suffix}"),
        sprint_id: capture_fixture.spec.sprint_id.clone(),
        state: NonSuccessTerminalState::Blocked,
        reason: "Descriptor-relative capture proved live workspace drift.".into(),
        terminal_at_unix_ms: verifier_cleanup
            .receipt
            .cleaned_at_unix_ms
            .saturating_add(10),
    };

    V25DriftReadyFixture {
        database: capture_fixture.database,
        ledger: capture_fixture.ledger,
        evidence,
        capture,
        verifier_cleanup,
    }
}

fn prepare_v25_drift_blocked_fixture(suffix: &str) -> V25DriftBlockedFixture {
    let mut ready = prepare_v25_drift_ready_fixture(suffix);
    let outcome = ready
        .ledger
        .record_live_state_drift_blocked_outcome(
            &ready.evidence,
            &ready.capture.receipt.receipt_id,
        )
        .expect("persist exact schema-v25 drift Blocked authority");
    assert!(matches!(
        &outcome.proof,
        PersistedTerminalProof::LiveStateDriftBlocked {
            proof,
            capture_evidence,
            verifier_cleanup_evidence,
        } if proof.capture_receipt_id == ready.capture.receipt.receipt_id
            && **capture_evidence == ready.capture
            && **verifier_cleanup_evidence == ready.verifier_cleanup
    ));
    assert_eq!(
        row_count(
            &ready.ledger,
            "sprint_live_state_drift_blocked_proofs"
        ),
        1
    );

    V25DriftBlockedFixture {
        _database: ready.database,
        ledger: ready.ledger,
        evidence: ready.evidence,
        outcome,
    }
}

fn expected_v25_drift_blocked_proof(ready: &V25DriftReadyFixture) -> LiveStateDriftBlockedProof {
    let capture = &ready.capture.receipt;
    let cleanup = &ready.verifier_cleanup.receipt;
    let plan = ready
        .ledger
        .load_sprint_live_state_capture_plan(&capture.plan_id)
        .expect("load exact v25 capture plan");
    LiveStateDriftBlockedProof {
        contract_version: CONTRACT_VERSION,
        sprint_id: ready.evidence.sprint_id.clone(),
        terminal_record_id: ready.evidence.record_id.clone(),
        terminal_evidence_digest: Digest::sha256(
            &encode("v25 terminal evidence", &ready.evidence)
                .expect("encode v25 terminal evidence"),
        ),
        branch: capture.branch.clone(),
        capture_receipt_id: capture.receipt_id.clone(),
        capture_admission_id: capture.admission_id.clone(),
        capture_plan_id: capture.plan_id.clone(),
        capture_plan_digest: capture.plan_digest.clone(),
        capture_effect_id: capture.effect_id.clone(),
        capture_observation_id: capture.observation_id.clone(),
        capture_dispatch_claim_id: capture.dispatch_claim_id.clone(),
        runner_launch_id: capture.runner_launch_id.clone(),
        runner_session_id: capture.runner_session_id.clone(),
        capture_evidence_digest: Digest::sha256(
            &encode("v25 capture evidence", &ready.capture).expect("encode v25 capture evidence"),
        ),
        expected_snapshot: capture.expected_snapshot.clone(),
        observed_snapshot: capture.observed_snapshot.clone(),
        manifest_digest: capture.manifest_digest.clone(),
        grant_hash: capture.grant_hash.clone(),
        policy_hash: capture.policy_hash.clone(),
        policy_version: capture.policy_version,
        verifier_cleanup_receipt_id: cleanup.receipt_id.clone(),
        required_cleanup_set_digest: plan.required_cleanup_set_digest,
        capture_started_at_unix_ms: capture.capture_started_at_unix_ms,
        captured_at_unix_ms: capture.captured_at_unix_ms,
        verifier_cleaned_at_unix_ms: cleanup.cleaned_at_unix_ms,
        blocked_at_unix_ms: ready.evidence.terminal_at_unix_ms,
    }
}

#[test]
fn v25_sql_probe_rejects_missing_prior_command_domain_proof() {
    let mut ready = prepare_v25_drift_ready_fixture("sql-command-domain-probe");
    let proof = expected_v25_drift_blocked_proof(&ready);
    proof
        .validate()
        .expect("manually derived v25 proof is structurally valid");
    let selected_proof_id: String = ready
        .ledger
        .connection
        .query_row(
            "SELECT proof.proof_id
             FROM command_domain_cleanup_proofs proof
             WHERE proof.sprint_id = ?1
               AND proof.launch_id != ?2
             ORDER BY proof.proof_id
             LIMIT 1",
            params![proof.sprint_id, proof.runner_launch_id],
            |row| row.get(0),
        )
        .expect("fixture must retain a prior command-domain proof");
    let transaction = ready
        .ledger
        .connection
        .transaction()
        .expect("begin v25 raw SQL command-domain probe");
    transaction
        .execute_batch("DROP TRIGGER command_domain_cleanup_proofs_no_delete;")
        .expect("remove command-domain proof deletion fence for corruption probe");
    let delete_error = transaction
        .execute(
            "DELETE FROM command_domain_cleanup_proofs WHERE proof_id = ?1",
            [&selected_proof_id],
        )
        .expect_err("v27 capture validation must retain every prior command-domain proof");
    assert!(
        delete_error
            .to_string()
            .contains("FOREIGN KEY constraint failed"),
        "unexpected command-domain proof deletion error: {delete_error:?}"
    );
    assert_eq!(
        transaction
            .query_row(
                "SELECT COUNT(*) FROM command_domain_cleanup_proofs WHERE proof_id = ?1",
                [&selected_proof_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("confirm capture-referenced prior proof remains"),
        1,
        "the v27 FK must reject the missing-proof state before v25 drift admission"
    );
    transaction.rollback().expect("roll back v25 SQL probe");
}

#[test]
fn v25_populated_drift_blocked_proof_is_immutable() {
    let fixture = prepare_v25_drift_blocked_fixture("immutable");

    for statement in [
        "UPDATE sprint_live_state_drift_blocked_proofs
         SET capture_evidence_digest = capture_evidence_digest
         WHERE sprint_id = 'sprint-1'",
        "DELETE FROM sprint_live_state_drift_blocked_proofs
         WHERE sprint_id = 'sprint-1'",
    ] {
        assert!(
            fixture.ledger.connection.execute_batch(statement).is_err(),
            "populated v25 drift proof mutation unexpectedly succeeded: {statement}"
        );
    }

    assert_eq!(
        row_count(
            &fixture.ledger,
            "sprint_live_state_drift_blocked_proofs"
        ),
        1
    );
    assert_eq!(
        fixture
            .ledger
            .load_terminal_outcome(&fixture.evidence.sprint_id)
            .expect("reload immutable v25 drift outcome"),
        Some(fixture.outcome)
    );
}

#[test]
fn v25_drift_readback_rejects_canonical_normalized_corruption() {
    let mut fixture = prepare_v25_drift_blocked_fixture("corrupt-readback");
    let PersistedTerminalProof::LiveStateDriftBlocked { proof, .. } = &fixture.outcome.proof else {
        panic!("v25 corruption fixture must retain typed drift authority");
    };
    let mut corrupted = (**proof).clone();
    corrupted.capture_evidence_digest = if corrupted.capture_evidence_digest == digest('f') {
        digest('e')
    } else {
        digest('f')
    };
    corrupted
        .validate()
        .expect("crossed v25 proof remains structurally valid");
    let corrupted_json =
        encode("crossed v25 drift proof", &corrupted).expect("encode crossed v25 proof");

    let transaction = fixture
        .ledger
        .connection
        .transaction()
        .expect("begin isolated v25 corruption transaction");
    transaction
        .execute_batch("DROP TRIGGER sprint_live_state_drift_blocked_proofs_no_update;")
        .expect("remove only the v25 proof no-update trigger");
    assert_eq!(
        transaction
            .execute(
                "UPDATE sprint_live_state_drift_blocked_proofs
                 SET capture_evidence_digest = ?1, proof_json = ?2
                 WHERE sprint_id = ?3",
                params![
                    corrupted.capture_evidence_digest.as_str(),
                    corrupted_json,
                    corrupted.sprint_id,
                ],
            )
            .expect("cross normalized and canonical v25 proof data"),
        1
    );
    transaction
        .commit()
        .expect("commit isolated v25 corruption injection");

    assert!(matches!(
        fixture
            .ledger
            .load_terminal_outcome(&fixture.evidence.sprint_id),
        Err(LedgerError::Corrupt {
            entity: "live-state drift blocked proof",
            ..
        })
    ));
}
