#[derive(Clone)]
struct V15NoLaunchRequest {
    release: WorkerLeaseNeverLaunchedRelease,
    metadata: TaskAttemptDispositionMetadata,
    event: AgentEvent,
}

fn v15_finish_prepare_ready_sprint(
    max_attempts_per_task: u8,
) -> (TestDatabase, EventLedger, AgentEvent) {
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open v15 finish-test ledger");
    let (mut spec, graph) = sprint_fixture();
    spec.budget.max_attempts_per_task = max_attempts_per_task;
    ledger
        .create_sprint(&spec, &graph, 1_000)
        .expect("create v15 finish-test sprint");
    let (base, _, _, _, _, _, _, _) = completion_artifacts();
    ledger
        .persist_workspace_snapshot(&spec.sprint_id, &base)
        .expect("persist v15 finish-test base snapshot");
    let ready = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(&spec.sprint_id)
            .expect("task Ready sequence"),
        event_id: format!("finish-ready-{max_attempts_per_task}"),
        sprint_id: spec.sprint_id,
        task_id: Some("task-1".into()),
        worker_id: None,
        causation_id: None,
        correlation_id: format!("finish-budget-{max_attempts_per_task}"),
        policy_hash: None,
        occurred_at_unix_ms: 1_010,
        payload: AgentEventKind::TaskStateChanged {
            from: "Planned".into(),
            to: "Ready".into(),
        },
    };
    ledger.append_event(&ready).expect("enter task Ready");
    (database, ledger, ready)
}

fn v15_finish_lease(epoch: u64, worker_id: &str, acquired_at_unix_ms: u64) -> WorkerLease {
    WorkerLease::new(
        "sprint-1".into(),
        epoch,
        "task-1".into(),
        worker_id.into(),
        vec![PathScope::Workspace],
        acquired_at_unix_ms,
    )
    .expect("canonical finish-test lease")
}

fn v15_finish_acquisition_event(
    ledger: &EventLedger,
    lease: &WorkerLease,
    suffix: &str,
    causation_id: &str,
) -> AgentEvent {
    AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(&lease.sprint_id)
            .expect("lease acquisition sequence"),
        event_id: format!("finish-acquire-{suffix}"),
        sprint_id: lease.sprint_id.clone(),
        task_id: Some(lease.task_id.clone()),
        worker_id: Some(lease.worker_id.clone()),
        causation_id: Some(causation_id.into()),
        correlation_id: format!("finish-attempt-{suffix}"),
        policy_hash: None,
        occurred_at_unix_ms: lease.acquired_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Ready".into(),
            to: "Leased".into(),
        },
    }
}

fn v15_finish_acquire(
    ledger: &mut EventLedger,
    lease: &WorkerLease,
    suffix: &str,
    causation_id: &str,
) -> (TaskAttempt, AgentEvent) {
    let event = v15_finish_acquisition_event(ledger, lease, suffix, causation_id);
    let attempt = ledger
        .acquire_task_attempt(lease, &event)
        .expect("acquire exact v15 finish-test attempt");
    (attempt, event)
}

fn v15_finish_no_launch_request(
    ledger: &EventLedger,
    attempt: &TaskAttempt,
    suffix: &str,
    to_state: TaskState,
    disposed_at_unix_ms: u64,
) -> V15NoLaunchRequest {
    let evidence = crate::TaskAttemptEvidence::new(
        format!("finish-no-launch-evidence-{suffix}"),
        crate::TaskAttemptEvidenceKind::NeverLaunched,
        format!("no launch authority exists for {suffix}").into_bytes(),
    )
    .expect("construct exact no-launch evidence");
    let release = WorkerLeaseNeverLaunchedRelease {
        contract_version: CONTRACT_VERSION,
        release_id: format!("finish-no-launch-release-{suffix}"),
        attempt: attempt.clone(),
        absence_evidence: evidence,
        released_at_unix_ms: disposed_at_unix_ms,
    };
    let metadata = TaskAttemptDispositionMetadata {
        contract_version: CONTRACT_VERSION,
        disposition_id: format!("finish-no-launch-disposition-{suffix}"),
        attempt: attempt.clone(),
        from_state: TaskState::Leased,
        state_transition_event_id: format!("finish-no-launch-event-{suffix}"),
        disposed_at_unix_ms,
    };
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(&attempt.worker_lease.sprint_id)
            .expect("no-launch disposition sequence"),
        event_id: metadata.state_transition_event_id.clone(),
        sprint_id: attempt.worker_lease.sprint_id.clone(),
        task_id: Some(attempt.worker_lease.task_id.clone()),
        worker_id: Some(attempt.worker_lease.worker_id.clone()),
        causation_id: Some(attempt.opening_event_id.clone()),
        correlation_id: format!("finish-no-launch-{suffix}"),
        policy_hash: None,
        occurred_at_unix_ms: disposed_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Leased".into(),
            to: format!("{to_state:?}"),
        },
    };
    V15NoLaunchRequest {
        release,
        metadata,
        event,
    }
}

fn v15_finish_close_no_launch(
    ledger: &mut EventLedger,
    request: &V15NoLaunchRequest,
) -> TaskAttemptDisposition {
    ledger
        .close_never_launched_task_attempt(&request.release, &request.metadata, &request.event)
        .expect("close exact never-launched attempt")
}

fn v15_finish_authority_counts(ledger: &EventLedger) -> (i64, i64, i64, i64, i64) {
    (
        row_count(ledger, "worker_lease_acquisitions"),
        row_count(ledger, "task_attempts"),
        row_count(ledger, "agent_events"),
        row_count(ledger, "worker_lease_never_launched_releases"),
        row_count(ledger, "task_attempt_dispositions"),
    )
}

#[test]
fn v15_prelaunch_policy_outcome_authority_is_rejected_without_stranding_attempt() {
    let (_database, mut ledger, ready) = v15_finish_prepare_ready_sprint(2);
    let lease = v15_finish_lease(1, "worker-prelaunch-policy", 1_100);
    let (attempt, _) = v15_finish_acquire(
        &mut ledger,
        &lease,
        "prelaunch-policy",
        &ready.event_id,
    );
    let evidence_bytes = b"operator cancellation before launch admission".to_vec();
    let evidence = crate::TaskAttemptEvidence::new(
        "prelaunch-policy-evidence".into(),
        crate::TaskAttemptEvidenceKind::OperatorCanceled,
        evidence_bytes.clone(),
    )
    .expect("construct prelaunch policy evidence");
    let outcome = crate::TaskAttemptKnownCleanupOutcome::Canceled(
        crate::TaskAttemptCanceledCause {
            cancellation_id: "prelaunch-policy-cancellation".into(),
            evidence: evidence.clone(),
        },
    );
    let baseline = row_count(&ledger, "task_attempt_policy_cause_authorities");

    assert!(matches!(
        ledger.record_task_attempt_cleanup_outcome_authority(&attempt, &outcome, 1_150),
        Err(LedgerError::ReferenceMismatch {
            entity: "task attempt cleanup outcome authority",
            ..
        })
    ));
    assert_eq!(
        row_count(&ledger, "task_attempt_policy_cause_authorities"),
        baseline
    );

    let authority_json = format!(
        concat!(
            "{{\"authority_id\":\"{}\",\"attempt_id\":\"{}\",",
            "\"cause_kind\":\"OperatorCanceled\",",
            "\"subject_id\":\"prelaunch-policy-cancellation\",",
            "\"evidence_id\":\"{}\",\"evidence_digest\":\"{}\",",
            "\"decided_at_unix_ms\":1150}}"
        ),
        evidence.evidence_id,
        attempt.attempt_id,
        evidence.evidence_id,
        evidence.digest,
    )
    .into_bytes();
    let transaction = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start direct-SQL prelaunch policy bypass");
    let sql_error = transaction
        .execute(
            "INSERT INTO task_attempt_policy_cause_authorities (
                authority_id, attempt_id, sprint_id, task_id, cause_kind,
                subject_id, evidence_id, evidence_digest, evidence_bytes,
                contract_version, decided_at_unix_ms, authority_json
             ) VALUES (?1, ?2, ?3, ?4, 'OperatorCanceled', ?5, ?6, ?7,
                       ?8, ?9, ?10, ?11)",
            params![
                evidence.evidence_id,
                attempt.attempt_id,
                attempt.worker_lease.sprint_id,
                attempt.worker_lease.task_id,
                "prelaunch-policy-cancellation",
                evidence.evidence_id,
                evidence.digest.as_str(),
                evidence_bytes,
                i64::from(CONTRACT_VERSION),
                1_150_i64,
                authority_json,
            ],
        )
        .expect_err("SQL must reject policy authority without open launch cleanup");
    assert!(
        sql_error
            .to_string()
            .contains("policy cause authority must exactly bind"),
        "unexpected SQL rejection: {sql_error}"
    );
    transaction
        .rollback()
        .expect("rollback direct-SQL prelaunch policy bypass");
    assert_eq!(
        row_count(&ledger, "task_attempt_policy_cause_authorities"),
        baseline
    );

    let recovery = ledger
        .load_task_attempt_recovery_projection("sprint-1", "task-1", &attempt.attempt_id)
        .expect("rejected prelaunch authority leaves exact recovery projection");
    assert_eq!(recovery.facts, crate::TaskAttemptRecoveryFacts::NeverLaunched);
    assert_eq!(
        recovery.decision,
        crate::TaskAttemptRecoveryDecision::CloseNeverLaunchedThenRetry
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn v15_max_one_and_last_attempt_api_and_sql_reject_without_partial_rows() {
    for max_attempts in [1_u8, 2_u8] {
        let (_database, mut ledger, ready) = v15_finish_prepare_ready_sprint(max_attempts);
        let first_lease = v15_finish_lease(1, "worker-first", 1_100);
        let (first_attempt, _) =
            v15_finish_acquire(&mut ledger, &first_lease, "first", &ready.event_id);

        if max_attempts == 2 {
            let overlapping_lease = v15_finish_lease(2, "worker-overlap", 1_110);
            let overlapping_event = v15_finish_acquisition_event(
                &ledger,
                &overlapping_lease,
                "overlap",
                &first_attempt.opening_event_id,
            );
            let before_overlap = v15_finish_authority_counts(&ledger);
            assert!(matches!(
                ledger.acquire_task_attempt(&overlapping_lease, &overlapping_event),
                Err(LedgerError::ReferenceMismatch { .. })
            ));
            assert_eq!(v15_finish_authority_counts(&ledger), before_overlap);
        }

        let mut current_attempt = first_attempt;
        if max_attempts == 2 {
            let first_close = v15_finish_no_launch_request(
                &ledger,
                &current_attempt,
                "budget-first",
                TaskState::Ready,
                1_200,
            );
            assert!(matches!(
                v15_finish_close_no_launch(&mut ledger, &first_close),
                TaskAttemptDisposition::Retryable(_)
            ));
            let final_lease = v15_finish_lease(2, "worker-final", 1_300);
            let (final_attempt, _) = v15_finish_acquire(
                &mut ledger,
                &final_lease,
                "final",
                &first_close.event.event_id,
            );
            current_attempt = final_attempt;
        }

        let final_close = v15_finish_no_launch_request(
            &ledger,
            &current_attempt,
            &format!("budget-final-{max_attempts}"),
            TaskState::Failed,
            1_400,
        );
        assert!(matches!(
            v15_finish_close_no_launch(&mut ledger, &final_close),
            TaskAttemptDisposition::AttemptsExhausted(_)
        ));

        let over_limit_epoch = u64::from(max_attempts) + 1;
        let over_limit_lease = v15_finish_lease(over_limit_epoch, "worker-over-limit", 1_500);
        let over_limit_event = v15_finish_acquisition_event(
            &ledger,
            &over_limit_lease,
            &format!("over-limit-{max_attempts}"),
            &final_close.event.event_id,
        );
        let before_rejections = v15_finish_authority_counts(&ledger);
        let api_error = ledger
            .acquire_task_attempt(&over_limit_lease, &over_limit_event)
            .expect_err("API must reject an attempt above the immutable budget");
        assert!(matches!(
            api_error,
            LedgerError::ReferenceMismatch {
                entity: "task attempt acquisition",
                ..
            }
        ));
        assert_eq!(v15_finish_authority_counts(&ledger), before_rejections);

        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("open over-budget SQL transaction");
        let sql_error = worker_lease_authority::insert_acquisition(
            &transaction,
            &over_limit_lease,
            &over_limit_event,
        )
        .expect_err("raw SQL authority must reject an over-budget acquisition");
        assert!(
            sql_error
                .to_string()
                .contains("v15 lease acquisition violates attempt budget or coverage"),
            "unexpected SQL budget fence: {sql_error}"
        );
        transaction
            .rollback()
            .expect("roll back rejected over-budget SQL transaction");
        assert_eq!(v15_finish_authority_counts(&ledger), before_rejections);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn v15_orphan_acquisition_attempt_and_opening_event_fail_closed() {
    let (_database, mut ledger, ready) = v15_finish_prepare_ready_sprint(2);
    let lease = v15_finish_lease(1, "worker-orphan", 1_100);
    let opening = v15_finish_acquisition_event(&ledger, &lease, "orphan", &ready.event_id);
    let attempt = TaskAttempt::new(lease.clone(), 1, opening.event_id.clone())
        .expect("construct exact orphan attempt candidate");
    let baseline = v15_finish_authority_counts(&ledger);

    let acquisition_only = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open acquisition-only transaction");
    worker_lease_authority::insert_acquisition(&acquisition_only, &lease, &opening)
        .expect("stage acquisition without its attempt or event");
    acquisition_only
        .commit()
        .expect_err("acquisition without attempt/event must fail at commit");
    assert_eq!(v15_finish_authority_counts(&ledger), baseline);

    let acquisition_and_attempt = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open missing-event transaction");
    worker_lease_authority::insert_acquisition(&acquisition_and_attempt, &lease, &opening)
        .expect("stage acquisition");
    task_attempt_authority::insert(&acquisition_and_attempt, &attempt)
        .expect("stage matching attempt without opening event");
    acquisition_and_attempt
        .commit()
        .expect_err("acquisition and attempt without opening event must fail at commit");
    assert_eq!(v15_finish_authority_counts(&ledger), baseline);

    let attempt_only = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open attempt-only transaction");
    let attempt_error = task_attempt_authority::insert(&attempt_only, &attempt)
        .expect_err("attempt without acquisition must fail before commit");
    assert!(
        attempt_error
            .to_string()
            .contains("invalid or noncontiguous current task attempt"),
        "unexpected attempt coverage fence: {attempt_error}"
    );
    attempt_only
        .rollback()
        .expect("roll back rejected attempt-only transaction");
    assert_eq!(v15_finish_authority_counts(&ledger), baseline);

    let event_only = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open event-only transaction");
    let event_error = insert_agent_event(&event_only, &opening)
        .expect_err("opening event without acquisition and attempt must fail");
    assert!(
        event_error
            .to_string()
            .contains("Ready-to-Leased event requires exact atomic v15 task attempt"),
        "unexpected opening-event coverage fence: {event_error}"
    );
    event_only
        .rollback()
        .expect("roll back rejected event-only transaction");
    assert_eq!(v15_finish_authority_counts(&ledger), baseline);
}

#[test]
#[allow(clippy::too_many_lines)]
fn v15_two_connections_serialize_the_final_attempt_before_and_after_reopen() {
    for reopen_before_race in [false, true] {
        let (database, mut ledger, ready) = v15_finish_prepare_ready_sprint(2);
        let first_lease = v15_finish_lease(1, "worker-first-race", 1_100);
        let (first_attempt, _) =
            v15_finish_acquire(&mut ledger, &first_lease, "race-first", &ready.event_id);
        let first_close = v15_finish_no_launch_request(
            &ledger,
            &first_attempt,
            if reopen_before_race {
                "race-reopen-close"
            } else {
                "race-live-close"
            },
            TaskState::Ready,
            1_200,
        );
        assert!(matches!(
            v15_finish_close_no_launch(&mut ledger, &first_close),
            TaskAttemptDisposition::Retryable(_)
        ));

        if reopen_before_race {
            drop(ledger);
            ledger = EventLedger::open(&database.path).expect("reopen before final-slot race");
        }

        let main_lease = v15_finish_lease(2, "worker-race-main", 1_300);
        let other_lease = v15_finish_lease(2, "worker-race-other", 1_301);
        let suffix = if reopen_before_race { "reopen" } else { "live" };
        let main_event = v15_finish_acquisition_event(
            &ledger,
            &main_lease,
            &format!("race-main-{suffix}"),
            &first_close.event.event_id,
        );
        let mut other_event = v15_finish_acquisition_event(
            &ledger,
            &other_lease,
            &format!("race-other-{suffix}"),
            &first_close.event.event_id,
        );
        other_event.sequence = main_event.sequence;

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let other_barrier = Arc::clone(&barrier);
        let database_path = database.path.clone();
        let other = std::thread::spawn(move || {
            let mut contender =
                EventLedger::open(&database_path).expect("open second final-slot contender");
            other_barrier.wait();
            contender
                .acquire_task_attempt(&other_lease, &other_event)
                .map(|attempt| attempt.attempt_id)
                .map_err(|error| error.to_string())
        });
        barrier.wait();
        let main = ledger
            .acquire_task_attempt(&main_lease, &main_event)
            .map(|attempt| attempt.attempt_id)
            .map_err(|error| error.to_string());
        let other = other.join().expect("join final-slot contender");
        assert_ne!(
            main.is_ok(),
            other.is_ok(),
            "exactly one final attempt wins"
        );
        let winner = main
            .as_ref()
            .ok()
            .or_else(|| other.as_ref().ok())
            .expect("one race winner");

        drop(ledger);
        let reopened =
            EventLedger::open_read_only(&database.path).expect("reopen final-slot race read-only");
        assert_eq!(row_count(&reopened, "worker_lease_acquisitions"), 2);
        assert_eq!(row_count(&reopened, "task_attempts"), 2);
        assert_eq!(
            reopened
                .load_task_attempt(winner)
                .expect("load exact final-slot winner")
                .attempt_ordinal,
            2
        );
    }
}

fn v15_assert_raw_repair_rejected(
    ledger: &mut EventLedger,
    attempt: &TaskAttempt,
    from_state: TaskState,
    causation_id: &str,
    suffix: &str,
) {
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(&attempt.worker_lease.sprint_id)
            .expect("raw repair sequence"),
        event_id: format!("finish-old-repair-{suffix}"),
        sprint_id: attempt.worker_lease.sprint_id.clone(),
        task_id: Some(attempt.worker_lease.task_id.clone()),
        worker_id: Some(attempt.worker_lease.worker_id.clone()),
        causation_id: Some(causation_id.into()),
        correlation_id: format!("finish-old-repair-{suffix}"),
        policy_hash: None,
        occurred_at_unix_ms: 1_900,
        payload: AgentEventKind::TaskStateChanged {
            from: format!("{from_state:?}"),
            to: "Running".into(),
        },
    };
    let before = row_count(ledger, "agent_events");
    let transaction = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open raw repair transition transaction");
    let error = insert_agent_event(&transaction, &event)
        .expect_err("old in-lease repair transition must fail in SQL");
    assert!(
        error
            .to_string()
            .contains("invalid, stale, or dependency-unready v15 task transition"),
        "unexpected old-repair SQL fence: {error}"
    );
    transaction
        .rollback()
        .expect("roll back rejected raw repair transition");
    assert_eq!(row_count(ledger, "agent_events"), before);
}

#[test]
#[allow(clippy::too_many_lines)]
fn v15_raw_sql_rejects_both_old_in_lease_repair_transitions() {
    let database = TestDatabase::new();
    let mut verifying_ledger =
        EventLedger::open(&database.path).expect("open Verifying repair ledger");
    let (_policy, launch, _session) = prepare_command_domain_session(&mut verifying_ledger);
    let (_, result_snapshot, change_set, _, _, _, _, _) = completion_artifacts();
    verifying_ledger
        .persist_workspace_snapshot("sprint-1", &result_snapshot)
        .expect("persist Verifying result snapshot");
    verifying_ledger
        .persist_change_set("sprint-1", &change_set)
        .expect("persist Verifying change set");
    let attempt = verifying_ledger
        .load_task_attempt(
            &launch
                .worker_lease
                .as_ref()
                .expect("task-worker lease")
                .lease_id,
        )
        .expect("load Verifying attempt");
    let running = enter_test_task_attempt_running(&mut verifying_ledger, &launch, 1_160);
    let verifying_event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: verifying_ledger
            .next_sequence("sprint-1")
            .expect("Verifying sequence"),
        event_id: "finish-enter-verifying".into(),
        sprint_id: "sprint-1".into(),
        task_id: Some(attempt.worker_lease.task_id.clone()),
        worker_id: Some(attempt.worker_lease.worker_id.clone()),
        causation_id: Some(running.transition_event_id.clone()),
        correlation_id: "finish-verifying-repair".into(),
        policy_hash: Some(launch.policy_hash.clone()),
        occurred_at_unix_ms: 1_700,
        payload: AgentEventKind::TaskStateChanged {
            from: "Running".into(),
            to: "Verifying".into(),
        },
    };
    let verification = TaskAttemptVerificationBoundary {
        contract_version: CONTRACT_VERSION,
        boundary_id: "finish-verification-boundary".into(),
        attempt: attempt.clone(),
        runner_launch_id: launch.launch_id,
        runner_session_id: launch.session_id,
        change_set_id: change_set.change_set_id,
        sealed_snapshot: result_snapshot.snapshot_id,
        transition_event_id: verifying_event.event_id.clone(),
        terminal_non_cleanup_effects: Vec::new(),
        sealed_at_unix_ms: verifying_event.occurred_at_unix_ms,
    };
    verifying_ledger
        .transition_task_attempt_to_verifying(&verification, &verifying_event)
        .expect("enter exact Verifying phase");
    v15_assert_raw_repair_rejected(
        &mut verifying_ledger,
        &attempt,
        TaskState::Verifying,
        &verifying_event.event_id,
        "verifying-to-running",
    );

    let mut candidate = prepare_v15_candidate_fixture(false);
    let candidate_attempt = candidate.attempt.clone();
    let candidate_event_id = candidate.candidate.transition_event_id.clone();
    v15_assert_raw_repair_rejected(
        &mut candidate.ledger,
        &candidate_attempt,
        TaskState::Candidate,
        &candidate_event_id,
        "candidate-to-running",
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn v15_never_launched_replays_exhausts_and_survives_reopen() {
    let (database, mut ledger, ready) = v15_finish_prepare_ready_sprint(2);
    let first_lease = v15_finish_lease(1, "worker-no-launch-first", 1_100);
    let (first_attempt, _) = v15_finish_acquire(
        &mut ledger,
        &first_lease,
        "no-launch-first",
        &ready.event_id,
    );
    let first_close = v15_finish_no_launch_request(
        &ledger,
        &first_attempt,
        "replay-first",
        TaskState::Ready,
        1_200,
    );
    let first = v15_finish_close_no_launch(&mut ledger, &first_close);
    assert!(matches!(first, TaskAttemptDisposition::Retryable(_)));
    assert_eq!(v15_finish_close_no_launch(&mut ledger, &first_close), first);

    drop(ledger);
    let mut reopened = EventLedger::open(&database.path).expect("reopen first no-launch close");
    assert_eq!(
        v15_finish_close_no_launch(&mut reopened, &first_close),
        first
    );
    let final_lease = v15_finish_lease(2, "worker-no-launch-final", 1_300);
    let (final_attempt, _) = v15_finish_acquire(
        &mut reopened,
        &final_lease,
        "no-launch-final",
        &first_close.event.event_id,
    );
    let final_close = v15_finish_no_launch_request(
        &reopened,
        &final_attempt,
        "replay-final",
        TaskState::Failed,
        1_400,
    );
    let final_disposition = v15_finish_close_no_launch(&mut reopened, &final_close);
    assert!(matches!(
        final_disposition,
        TaskAttemptDisposition::AttemptsExhausted(_)
    ));

    drop(reopened);
    let mut recovered = EventLedger::open(&database.path).expect("recover final no-launch close");
    assert_eq!(
        v15_finish_close_no_launch(&mut recovered, &final_close),
        final_disposition
    );
    let history = recovered
        .load_task_attempt_history("sprint-1", "task-1")
        .expect("load exact no-launch recovery history");
    assert_eq!(history.task_state, TaskState::Failed);
    assert_eq!(history.attempts.len(), 2);
    assert!(matches!(
        history.attempts[0].disposition,
        Some(TaskAttemptDisposition::Retryable(_))
    ));
    assert!(matches!(
        history.attempts[1].disposition,
        Some(TaskAttemptDisposition::AttemptsExhausted(_))
    ));
    assert!(
        history
            .attempts
            .iter()
            .all(|entry| matches!(entry.lease_state, TaskAttemptLeaseState::Released { .. }))
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn v15_never_launched_and_launch_admission_race_has_one_recoverable_winner() {
    let (database, mut ledger, ready) = v15_finish_prepare_ready_sprint(2);
    let lease = v15_finish_lease(1, "worker-launch-race", 1_100);
    let (attempt, _) = v15_finish_acquire(&mut ledger, &lease, "launch-race", &ready.event_id);
    let close =
        v15_finish_no_launch_request(&ledger, &attempt, "launch-race", TaskState::Ready, 1_300);

    let policy = compiled_shadow_test_policy("finish-launch-race-policy");
    let mut launch = runner_launch(
        "finish-launch-race",
        "finish-launch-race-session",
        RunnerSessionPurpose::TaskWorker,
        Some(&lease.worker_id),
        &policy,
        1_200,
    );
    launch.worker_lease = Some(lease.clone());
    let (cleanup_intent, _, cleanup_request, cleanup_event) =
        test_runner_launch_cleanup_contracts(&ledger, &launch, WorkerCleanupBackend::LinuxCgroupV2)
            .expect("construct launch-race cleanup admission");

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let launch_barrier = Arc::clone(&barrier);
    let database_path = database.path.clone();
    let launch_id = launch.launch_id.clone();
    let launch_thread = std::thread::spawn(move || {
        let mut contender = EventLedger::open(&database_path).expect("open launch-race contender");
        launch_barrier.wait();
        contender
            .admit_runner_launch_with_cleanup(
                &launch,
                &policy,
                &cleanup_intent,
                &cleanup_request,
                &cleanup_event,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    });
    barrier.wait();
    let close_result = ledger
        .close_never_launched_task_attempt(&close.release, &close.metadata, &close.event)
        .map_err(|error| error.to_string());
    let launch_result = launch_thread.join().expect("join launch-race contender");
    assert_ne!(
        close_result.is_ok(),
        launch_result.is_ok(),
        "launch admission and no-launch closure cannot both commit"
    );

    drop(ledger);
    let mut recovered = EventLedger::open(&database.path).expect("reopen launch/no-launch race");
    if let Ok(closed) = close_result {
        assert!(matches!(closed, TaskAttemptDisposition::Retryable(_)));
        assert_eq!(row_count(&recovered, "runner_launch_intents"), 0);
        assert_eq!(row_count(&recovered, "task_attempt_dispositions"), 1);
        assert_eq!(v15_finish_close_no_launch(&mut recovered, &close), closed);
    } else {
        assert_eq!(row_count(&recovered, "runner_launch_intents"), 1);
        assert_eq!(row_count(&recovered, "task_attempt_dispositions"), 0);
        assert_eq!(
            recovered
                .load_runner_launch_cleanup_admission("sprint-1", &launch_id)
                .expect("recover exact launch-race admission")
                .launch
                .worker_lease,
            Some(lease.clone())
        );
        assert!(
            recovered
                .close_never_launched_task_attempt(&close.release, &close.metadata, &close.event)
                .is_err()
        );
        assert_eq!(
            recovered
                .load_active_worker_leases("sprint-1")
                .expect("launch winner retains active lease"),
            vec![lease]
        );
    }
}

#[cfg(unix)]
#[test]
fn v15_acquisition_post_commit_hardlink_exposes_exact_durable_recovery_identity() {
    let (database, mut ledger, ready) = v15_finish_prepare_ready_sprint(2);
    let lease = v15_finish_lease(1, "worker-acquisition-hardlink", 1_100);
    let event =
        v15_finish_acquisition_event(&ledger, &lease, "acquisition-hardlink", &ready.event_id);
    let expected = TaskAttempt::new(lease.clone(), 1, event.event_id.clone())
        .expect("construct expected acquisition authority");
    let baseline = v15_finish_authority_counts(&ledger);
    let hardlink = database
        .directory
        .join("task-attempt-acquisition-post-commit-hardlink.sqlite3");
    fs::hard_link(&database.path, &hardlink).expect("inject acquisition hardening fault");

    assert!(matches!(
        ledger.acquire_task_attempt(&lease, &event),
        Err(LedgerError::PostCommitStateUncertain {
            operation: "task attempt acquisition",
            recovery_id,
            ..
        }) if recovery_id == expected.attempt_id
    ));
    fs::remove_file(&hardlink).expect("remove acquisition hardening fault");

    assert_eq!(
        ledger
            .load_task_attempt(&expected.attempt_id)
            .expect("recover committed acquisition by exact identity"),
        expected
    );
    assert_eq!(
        ledger
            .load_active_worker_leases("sprint-1")
            .expect("recover committed active lease"),
        vec![lease.clone()]
    );
    let committed_counts = v15_finish_authority_counts(&ledger);
    assert_eq!(
        committed_counts,
        (
            baseline.0 + 1,
            baseline.1 + 1,
            baseline.2 + 1,
            baseline.3,
            baseline.4,
        )
    );
    assert!(ledger.acquire_task_attempt(&lease, &event).is_err());
    assert_eq!(v15_finish_authority_counts(&ledger), committed_counts);
    drop(ledger);

    let reopened = EventLedger::open_read_only(&database.path)
        .expect("reopen post-commit acquisition read-only");
    assert_eq!(
        reopened
            .load_task_attempt(&expected.attempt_id)
            .expect("read back acquisition after restart"),
        expected
    );
    assert_eq!(v15_finish_authority_counts(&reopened), committed_counts);
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)] // Every statement cut and the post-commit hardening fault share one exact authority fixture.
fn v15_never_launched_statement_cuts_and_commit_uncertainty_are_recoverable() {
    let (database, mut ledger, ready) = v15_finish_prepare_ready_sprint(2);
    let lease = v15_finish_lease(1, "worker-no-launch-cuts", 1_100);
    let (attempt, _) = v15_finish_acquire(&mut ledger, &lease, "no-launch-cuts", &ready.event_id);
    let close =
        v15_finish_no_launch_request(&ledger, &attempt, "statement-cuts", TaskState::Ready, 1_200);
    let disposition = task_attempt_authority::computed_never_launched_disposition(
        close.metadata.clone(),
        close.release.clone(),
        2,
    )
    .expect("compute exact cut-point disposition");
    let baseline = v15_finish_authority_counts(&ledger);

    let release_only = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open release-only crash cut");
    task_attempt_authority::insert_never_launched_release(
        &release_only,
        &close.release,
        &close.metadata.disposition_id,
    )
    .expect("stage release before simulated crash");
    release_only
        .rollback()
        .expect("simulate crash after release statement");
    assert_eq!(v15_finish_authority_counts(&ledger), baseline);

    let disposition_cut = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open disposition crash cut");
    task_attempt_authority::insert_never_launched_release(
        &disposition_cut,
        &close.release,
        &close.metadata.disposition_id,
    )
    .expect("stage release before disposition cut");
    task_attempt_authority::insert_disposition(&disposition_cut, &disposition)
        .expect("stage disposition before simulated crash");
    disposition_cut
        .rollback()
        .expect("simulate crash after disposition statement");
    assert_eq!(v15_finish_authority_counts(&ledger), baseline);

    let event_cut = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open event crash cut");
    task_attempt_authority::insert_never_launched_release(
        &event_cut,
        &close.release,
        &close.metadata.disposition_id,
    )
    .expect("stage release before event cut");
    task_attempt_authority::insert_disposition(&event_cut, &disposition)
        .expect("stage disposition before event cut");
    insert_agent_event(&event_cut, &close.event).expect("stage event before simulated crash");
    event_cut
        .rollback()
        .expect("simulate crash after event statement");
    assert_eq!(v15_finish_authority_counts(&ledger), baseline);

    let missing_event = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open deferred commit cut");
    task_attempt_authority::insert_never_launched_release(
        &missing_event,
        &close.release,
        &close.metadata.disposition_id,
    )
    .expect("stage commit-cut release");
    task_attempt_authority::insert_disposition(&missing_event, &disposition)
        .expect("stage commit-cut disposition");
    missing_event
        .commit()
        .expect_err("commit without the exact task event must fail closed");
    assert_eq!(v15_finish_authority_counts(&ledger), baseline);

    let hardlink = database
        .directory
        .join("never-launched-post-commit-hardlink.sqlite3");
    fs::hard_link(&database.path, &hardlink).expect("inject post-commit hardening fault");
    assert!(matches!(
        ledger.close_never_launched_task_attempt(
            &close.release,
            &close.metadata,
            &close.event,
        ),
        Err(LedgerError::PostCommitStateUncertain {
            operation: "never-launched disposition",
            recovery_id,
            ..
        }) if recovery_id == attempt.attempt_id
    ));
    fs::remove_file(&hardlink).expect("remove post-commit hardening fault");

    assert_eq!(
        ledger
            .close_never_launched_task_attempt(&close.release, &close.metadata, &close.event,)
            .expect("exact replay recovers the committed disposition"),
        disposition
    );
    assert_eq!(
        v15_finish_authority_counts(&ledger),
        (
            baseline.0,
            baseline.1,
            baseline.2 + 1,
            baseline.3 + 1,
            baseline.4 + 1,
        )
    );
}
