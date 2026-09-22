use crate::{TaskAttemptRecoveryDecision, TaskAttemptRecoveryFacts};

fn recovery_admit_task_launch(
    max_attempts: u8,
    suffix: &str,
) -> (
    TestDatabase,
    EventLedger,
    TaskAttempt,
    CompiledExecutionPolicy,
    RunnerLaunchIntent,
    PersistedRunnerLaunchCleanupAdmission,
) {
    let (database, mut ledger, ready) = v15_finish_prepare_ready_sprint(max_attempts);
    let worker_id = format!("worker-recovery-{suffix}");
    let lease = v15_finish_lease(1, &worker_id, 1_020);
    let (attempt, _) = v15_finish_acquire(&mut ledger, &lease, suffix, &ready.event_id);
    let policy = compiled_shadow_test_policy(&format!("policy-recovery-{suffix}"));
    let mut launch = runner_launch(
        &format!("launch-recovery-{suffix}"),
        &format!("session-recovery-{suffix}"),
        RunnerSessionPurpose::TaskWorker,
        Some(&worker_id),
        &policy,
        1_030,
    );
    launch.worker_lease = Some(lease);
    let (cleanup_intent, _, cleanup_request_bytes, proposal) =
        test_runner_launch_cleanup_contracts(
            &ledger,
            &launch,
            WorkerCleanupBackend::LinuxCgroupV2,
        )
        .expect("build recovery launch cleanup admission");
    let admission = ledger
        .admit_runner_launch_with_cleanup(
            &launch,
            &policy,
            &cleanup_intent,
            &cleanup_request_bytes,
            &proposal,
        )
        .expect("admit recovery launch");
    (database, ledger, attempt, policy, launch, admission)
}

#[test]
fn task_attempt_recovery_never_launched_is_ledger_derived_and_reopens() {
    let (database, mut ledger, ready) = v15_finish_prepare_ready_sprint(2);
    let lease = v15_finish_lease(1, "worker-recovery-never", 1_020);
    let (attempt, _) =
        v15_finish_acquire(&mut ledger, &lease, "recovery-never", &ready.event_id);

    assert_eq!(
        ledger
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::NeverLaunched,
            )
            .expect("derive no-launch recovery"),
        TaskAttemptRecoveryDecision::CloseNeverLaunchedThenRetry
    );
    assert_eq!(
        ledger
            .load_task_attempt_recovery_projection("sprint-1", "task-1", &attempt.attempt_id)
            .expect("authoritatively derive no-launch recovery"),
        LedgerTaskAttemptRecoveryProjection {
            facts: TaskAttemptRecoveryFacts::NeverLaunched,
            decision: TaskAttemptRecoveryDecision::CloseNeverLaunchedThenRetry,
        }
    );
    assert!(
        ledger
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::CurrentAuthority {
                    launch_id: "invented-launch".into(),
                    session_id: None,
                },
            )
            .is_err()
    );

    drop(ledger);
    let mut reopened = EventLedger::open(&database.path).expect("reopen recovery ledger");
    assert_eq!(
        reopened
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::NeverLaunched,
            )
            .expect("rederive no-launch recovery"),
        TaskAttemptRecoveryDecision::CloseNeverLaunchedThenRetry
    );

    let close = v15_finish_no_launch_request(
        &reopened,
        &attempt,
        "recovery-disposed",
        TaskState::Ready,
        1_100,
    );
    v15_finish_close_no_launch(&mut reopened, &close);
    assert_eq!(
        reopened
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::DurableHistoryOnly,
            )
            .expect("derive disposed recovery"),
        TaskAttemptRecoveryDecision::AlreadyDisposed
    );
    assert_eq!(
        reopened
            .load_task_attempt_recovery_projection("sprint-1", "task-1", &attempt.attempt_id)
            .expect("authoritatively derive disposed recovery"),
        LedgerTaskAttemptRecoveryProjection {
            facts: TaskAttemptRecoveryFacts::DurableHistoryOnly,
            decision: TaskAttemptRecoveryDecision::AlreadyDisposed,
        }
    );
    assert!(
        reopened
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::NeverLaunched,
            )
            .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Pre-session, Running, crossed identity, and restart are one Current-authority lifecycle.
fn task_attempt_recovery_current_authority_is_exact_cross_checked_and_reopens() {
    let (database, mut ledger, attempt, policy, launch, _) =
        recovery_admit_task_launch(2, "current");
    let before_session = TaskAttemptRecoveryFacts::CurrentAuthority {
        launch_id: launch.launch_id.clone(),
        session_id: None,
    };
    assert_eq!(
        ledger
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &before_session,
            )
            .expect("continue exact pre-session launch"),
        TaskAttemptRecoveryDecision::ContinueActive
    );
    assert_eq!(
        ledger
            .load_task_attempt_recovery_projection("sprint-1", "task-1", &attempt.attempt_id)
            .expect("authoritatively derive pre-session Current"),
        LedgerTaskAttemptRecoveryProjection {
            facts: before_session.clone(),
            decision: TaskAttemptRecoveryDecision::ContinueActive,
        }
    );
    assert!(
        ledger
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::UncertainAuthority {
                    evidence_id: launch.launch_id.clone(),
                },
            )
            .is_err(),
        "a routine open launch must not also select terminal Unknown"
    );
    // The static cleanup admission created by the shared fixture is durable at
    // 1_100. Session initialization and Running must follow that admission.
    let session = runner_session(&launch, 1_110);
    ledger
        .register_runner_session(&session, &policy)
        .expect("register exact recovery session");
    enter_test_task_attempt_running(&mut ledger, &launch, 1_120);
    let current = TaskAttemptRecoveryFacts::CurrentAuthority {
        launch_id: launch.launch_id.clone(),
        session_id: Some(session.session_id.clone()),
    };
    assert_eq!(
        ledger
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &current,
            )
            .expect("continue exact initialized launch"),
        TaskAttemptRecoveryDecision::ContinueActive
    );
    assert_eq!(
        ledger
            .load_task_attempt_recovery_projection("sprint-1", "task-1", &attempt.attempt_id)
            .expect("authoritatively derive initialized Current"),
        LedgerTaskAttemptRecoveryProjection {
            facts: current.clone(),
            decision: TaskAttemptRecoveryDecision::ContinueActive,
        }
    );
    for crossed in [
        TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id: "crossed-launch".into(),
            session_id: Some(session.session_id.clone()),
        },
        TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id: launch.launch_id.clone(),
            session_id: Some("crossed-session".into()),
        },
        before_session,
    ] {
        assert!(
            ledger
                .project_task_attempt_recovery_decision(
                    "sprint-1",
                    "task-1",
                    &attempt.attempt_id,
                    &crossed,
                )
                .is_err()
        );
    }
    drop(ledger);
    let reopened = EventLedger::open_read_only(&database.path).expect("reopen current recovery");
    assert_eq!(
        reopened
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &current,
            )
            .expect("rederive exact current authority"),
        TaskAttemptRecoveryDecision::ContinueActive
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "terminal and unresolved provider effects form one recovery fencing regression"
)]
fn task_attempt_recovery_provider_effects_use_attempt_lease_without_runner_binding() {
    let mut fixture = prepare_phase_recovery_fixture();
    fixture
        .ledger
        .register_runner_session(&runner_session(&fixture.launch, 1_220), &fixture.policy)
        .expect("register provider recovery worker session");
    let running =
        enter_test_task_attempt_running(&mut fixture.ledger, &fixture.launch, 1_230);
    let current = phase_current_projection(
        &fixture.launch,
        Some(fixture.launch.session_id.clone()),
    );

    let terminal_intent = phase_provider_intent(
        &fixture.attempt,
        &fixture.launch,
        "recovery-provider-terminal",
        fixture.spec.base_snapshot.clone(),
        &running.transition_event_id,
        1_240,
    );
    let terminal_proposal = effect_proposal_event(
        &terminal_intent,
        fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("terminal provider proposal sequence"),
        "recovery-provider-terminal-proposed",
    );
    fixture
        .ledger
        .record_effect_intent(
            &terminal_intent,
            EFFECT_REQUEST_BYTES,
            &terminal_proposal,
        )
        .expect("persist exact lease-owned provider request");
    let terminal_observation = effect_observation(
        &terminal_intent,
        "recovery-provider-terminal-observed",
        EffectOutcome::Succeeded {
            evidence_digest: Digest::sha256(EFFECT_EVIDENCE_BYTES),
        },
        1_250,
    );
    let terminal_event = effect_terminal_event(
        &terminal_intent,
        &terminal_proposal.event_id,
        &terminal_observation,
        fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("terminal provider observation sequence"),
        "recovery-provider-terminal-finished",
    );
    let persisted = fixture
        .ledger
        .record_effect_observation(
            &terminal_observation,
            EFFECT_EVIDENCE_BYTES,
            &terminal_event,
        )
        .expect("persist terminal provider observation");
    assert_eq!(
        persisted.reconciliation(),
        EffectReconciliation::TerminalKnown
    );
    assert_eq!(
        fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM effect_session_bindings WHERE effect_id = ?1",
                [&terminal_intent.effect_id],
                |row| row.get::<_, i64>(0),
            )
            .expect("count provider runner bindings"),
        0,
        "provider recovery authority must not invent a runner-session binding"
    );
    assert_phase_recovery_reopens(&fixture, &current);

    let unresolved_intent = phase_provider_intent(
        &fixture.attempt,
        &fixture.launch,
        "recovery-provider-unobserved",
        fixture.spec.base_snapshot.clone(),
        &running.transition_event_id,
        1_260,
    );
    let unresolved_proposal = effect_proposal_event(
        &unresolved_intent,
        fixture
            .ledger
            .next_sequence(&fixture.spec.sprint_id)
            .expect("unobserved provider proposal sequence"),
        "recovery-provider-unobserved-proposed",
    );
    fixture
        .ledger
        .record_effect_intent(
            &unresolved_intent,
            EFFECT_REQUEST_BYTES,
            &unresolved_proposal,
        )
        .expect("persist unobserved provider request");
    assert!(
        fixture
            .ledger
            .project_task_attempt_recovery_decision(
                &fixture.spec.sprint_id,
                &fixture.attempt.worker_lease.task_id,
                &fixture.attempt.attempt_id,
                &current.facts,
            )
            .is_err(),
        "unobserved provider request must fence CurrentAuthority recovery"
    );
    assert_eq!(
        fixture
            .ledger
            .load_task_attempt_recovery_projection(
                &fixture.spec.sprint_id,
                &fixture.attempt.worker_lease.task_id,
                &fixture.attempt.attempt_id,
            )
            .expect("derive unresolved provider recovery"),
        LedgerTaskAttemptRecoveryProjection {
            facts: TaskAttemptRecoveryFacts::UncertainAuthority {
                evidence_id: unresolved_intent.effect_id,
            },
            decision: TaskAttemptRecoveryDecision::TerminalizeUnknown,
        }
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Retry/fail budget and forged source identity share one canonical refusal fixture.
fn task_attempt_recovery_known_cleanup_uses_exact_source_and_budget() {
    for (max_attempts, expected) in [
        (2, TaskAttemptRecoveryDecision::CleanupThenRetry),
        (1, TaskAttemptRecoveryDecision::CleanupThenFail),
    ] {
        let suffix = format!("known-cleanup-{max_attempts}");
        let (_database, mut ledger, attempt, _, launch, admission) =
            recovery_admit_task_launch(max_attempts, &suffix);
        let preparation = test_launch_preparation_attempt(&admission, &suffix, 1_150);
        let refusal_bytes = format!("refused recovery source {suffix}").into_bytes();
        ledger
            .with_runner_launch_preparation_claim(&admission, &preparation, |_| {
                RunnerLaunchPreparationOutcome {
                    disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
                    native_evidence_bytes: refusal_bytes.clone(),
                    finished_at_unix_ms: 1_160,
                }
            })
            .expect("persist exact launch refusal source");
        let evidence = crate::TaskAttemptEvidence::new(
            preparation.attempt_id.clone(),
            crate::TaskAttemptEvidenceKind::LaunchRefusedBeforeNativeEffect,
            refusal_bytes.clone(),
        )
        .expect("construct canonical refusal evidence");
        let facts = TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id: launch.launch_id.clone(),
            session_id: None,
            outcome: TaskAttemptKnownCleanupOutcome::Retryable(
                crate::TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect {
                    launch_id: launch.launch_id.clone(),
                    evidence,
                },
            ),
        };
        assert_eq!(
            ledger
                .project_task_attempt_recovery_decision(
                    "sprint-1",
                    "task-1",
                    &attempt.attempt_id,
                    &facts,
                )
                .expect("derive exact known cleanup"),
            expected
        );
        assert_eq!(
            ledger
                .load_task_attempt_recovery_projection(
                    "sprint-1",
                    "task-1",
                    &attempt.attempt_id,
                )
                .expect("authoritatively derive exact known cleanup"),
            LedgerTaskAttemptRecoveryProjection {
                facts: facts.clone(),
                decision: expected,
            }
        );
        let forged_evidence = crate::TaskAttemptEvidence::new(
            format!("forged-refusal-{max_attempts}"),
            crate::TaskAttemptEvidenceKind::LaunchRefusedBeforeNativeEffect,
            refusal_bytes,
        )
        .expect("construct byte-exact forged-ID evidence");
        let forged = TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id: launch.launch_id.clone(),
            session_id: None,
            outcome: TaskAttemptKnownCleanupOutcome::Retryable(
                crate::TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect {
                    launch_id: launch.launch_id,
                    evidence: forged_evidence,
                },
            ),
        };
        let TaskAttemptRecoveryFacts::KnownCleanupRequired {
            outcome: forged_outcome,
            ..
        } = &forged
        else {
            unreachable!("constructed known-cleanup facts")
        };
        assert!(
            task_attempt_authority::require_current_known_cleanup_outcome_authority(
                &ledger.connection,
                &attempt,
                forged_outcome,
            )
            .is_err(),
            "shared disposition source validator must reject the forged evidence ID"
        );
        assert!(
            ledger
                .project_task_attempt_recovery_decision(
                    "sprint-1",
                    "task-1",
                    &attempt.attempt_id,
                    &forged,
                )
                .is_err(),
            "exact bytes with a caller-invented evidence ID must fail"
        );
    }
}

#[test]
fn task_attempt_recovery_known_source_precedes_native_preparation_uncertainty() {
    let (_database, mut ledger, attempt, _, launch, admission) =
        recovery_admit_task_launch(2, "known-over-preparation");
    let preparation =
        test_launch_preparation_attempt(&admission, "known-over-preparation", 1_150);
    ledger
        .with_runner_launch_preparation_claim(&admission, &preparation, |_| {
            RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::NativeEffectUncertain,
                native_evidence_bytes: b"native state requires cleanup reconciliation".to_vec(),
                finished_at_unix_ms: 1_160,
            }
        })
        .expect("persist native preparation uncertainty");
    let cancellation = TaskAttemptKnownCleanupOutcome::Canceled(crate::TaskAttemptCanceledCause {
        cancellation_id: "recovery-cancellation".into(),
        evidence: crate::TaskAttemptEvidence::new(
            "recovery-cancellation-evidence".into(),
            crate::TaskAttemptEvidenceKind::OperatorCanceled,
            b"operator canceled exact recovery attempt".to_vec(),
        )
        .expect("construct cancellation source"),
    });
    ledger
        .record_task_attempt_cleanup_outcome_authority(&attempt, &cancellation, 1_170)
        .expect("record exact cancellation source");
    let facts = TaskAttemptRecoveryFacts::KnownCleanupRequired {
        launch_id: launch.launch_id,
        session_id: None,
        outcome: cancellation,
    };
    assert_eq!(
        ledger
            .load_task_attempt_recovery_projection("sprint-1", "task-1", &attempt.attempt_id)
            .expect("derive preferred known cleanup over preparation uncertainty"),
        LedgerTaskAttemptRecoveryProjection {
            facts: facts.clone(),
            decision: TaskAttemptRecoveryDecision::CleanupThenFail,
        }
    );
    assert!(
        ledger
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::UncertainAuthority {
                    evidence_id: preparation.native_journal_id,
                },
            )
            .is_err(),
        "caller may not override a cleanup-capable known source with preparation uncertainty"
    );
}

#[test]
fn v15_task_attempt_recovery_uses_typed_source_tiebreaker_across_insertion_orders() {
    for candidate_first in [false, true] {
        let mut fixture = prepare_v15_candidate_fixture(false);
        let shared_source_id = "same-id-across-known-source-families";
        let worker_exit = TaskAttemptKnownCleanupOutcome::Retryable(
            crate::TaskAttemptRetryableCause::KnownWorkerExit {
                launch_id: fixture.launch.launch_id.clone(),
                session_id: fixture.launch.session_id.clone(),
                evidence: crate::TaskAttemptEvidence::new(
                    shared_source_id.into(),
                    crate::TaskAttemptEvidenceKind::KnownWorkerExit,
                    b"typed worker-exit source".to_vec(),
                )
                .expect("construct worker-exit source"),
            },
        );
        let candidate_rejection = TaskAttemptKnownCleanupOutcome::Retryable(
            crate::TaskAttemptRetryableCause::CandidateRejectedKnown {
                candidate_boundary_id: fixture.candidate.boundary_id.clone(),
                evidence: crate::TaskAttemptEvidence::new(
                    shared_source_id.into(),
                    crate::TaskAttemptEvidenceKind::CandidateRejectedKnown,
                    b"typed candidate-rejection source".to_vec(),
                )
                .expect("construct candidate-rejection source"),
            },
        );
        let insertion_order = if candidate_first {
            [&candidate_rejection, &worker_exit]
        } else {
            [&worker_exit, &candidate_rejection]
        };
        for outcome in insertion_order {
            fixture
                .ledger
                .record_task_attempt_cleanup_outcome_authority(
                    &fixture.attempt,
                    outcome,
                    1_400,
                )
                .expect("record colliding typed known-cleanup source");
        }

        let preferred = task_attempt_authority::preferred_known_cleanup_source(
            &fixture.ledger.connection,
            &fixture.attempt,
        )
        .expect("derive canonical typed source")
        .expect("preferred source exists");
        assert_eq!(preferred.source_id, shared_source_id);
        assert_eq!(
            preferred.source_kind,
            task_attempt_authority::KnownCleanupSourceKind::CandidateRejection
        );
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_recovery_projection(
                    &fixture.spec.sprint_id,
                    &fixture.attempt.worker_lease.task_id,
                    &fixture.attempt.attempt_id,
                )
                .expect("recovery loads the typed winner rather than a same-ID sibling"),
            LedgerTaskAttemptRecoveryProjection {
                facts: TaskAttemptRecoveryFacts::KnownCleanupRequired {
                    launch_id: fixture.launch.launch_id.clone(),
                    session_id: Some(fixture.launch.session_id.clone()),
                    outcome: candidate_rejection,
                },
                decision: TaskAttemptRecoveryDecision::CleanupThenRetry,
            }
        );
    }
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)] // One disposed attempt must reject all three independent source families and retain exact replay.
fn v15_disposed_attempt_rejects_new_worker_candidate_and_policy_sources() {
    let mut fixture = prepare_v15_candidate_fixture(false);
    let cancellation = TaskAttemptKnownCleanupOutcome::Canceled(crate::TaskAttemptCanceledCause {
        cancellation_id: "stale-source-cancellation".into(),
        evidence: crate::TaskAttemptEvidence::new(
            "stale-source-cancellation-evidence".into(),
            crate::TaskAttemptEvidenceKind::OperatorCanceled,
            b"canonical cancellation before cleanup".to_vec(),
        )
        .expect("construct cancellation source"),
    });
    fixture
        .ledger
        .record_task_attempt_cleanup_outcome_authority(&fixture.attempt, &cancellation, 1_350)
        .expect("record canonical cancellation source");
    let metadata = TaskAttemptDispositionMetadata {
        contract_version: CONTRACT_VERSION,
        disposition_id: "stale-source-disposition".into(),
        attempt: fixture.attempt.clone(),
        from_state: TaskState::Candidate,
        state_transition_event_id: "stale-source-canceled".into(),
        disposed_at_unix_ms: 1_450,
    };
    let cleanup_sequence = fixture
        .ledger
        .next_sequence(&fixture.spec.sprint_id)
        .expect("cleanup terminal sequence");
    let transition = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: cleanup_sequence + 1,
        event_id: metadata.state_transition_event_id.clone(),
        sprint_id: fixture.spec.sprint_id.clone(),
        task_id: Some(fixture.attempt.worker_lease.task_id.clone()),
        worker_id: Some(fixture.attempt.worker_lease.worker_id.clone()),
        causation_id: Some(fixture.candidate.transition_event_id.clone()),
        correlation_id: "stale-source-lifecycle".into(),
        policy_hash: Some(fixture.launch.policy_hash.clone()),
        occurred_at_unix_ms: metadata.disposed_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Candidate".into(),
            to: "Canceled".into(),
        },
    };
    fixture
        .ledger
        .with_task_attempt_cleanup_disposition_exclusion(
            &metadata,
            &cancellation,
            "stale-source-release",
            &transition,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "stale-source",
                    1_400,
                ))
            },
        )
        .expect("dispose candidate with canonical cancellation");

    let worker_exit = TaskAttemptKnownCleanupOutcome::Retryable(
        crate::TaskAttemptRetryableCause::KnownWorkerExit {
            launch_id: fixture.launch.launch_id.clone(),
            session_id: fixture.launch.session_id.clone(),
            evidence: crate::TaskAttemptEvidence::new(
                "post-disposition-worker-exit".into(),
                crate::TaskAttemptEvidenceKind::KnownWorkerExit,
                b"late worker-exit source".to_vec(),
            )
            .expect("construct late worker source"),
        },
    );
    let candidate_rejection = TaskAttemptKnownCleanupOutcome::Retryable(
        crate::TaskAttemptRetryableCause::CandidateRejectedKnown {
            candidate_boundary_id: fixture.candidate.boundary_id.clone(),
            evidence: crate::TaskAttemptEvidence::new(
                "post-disposition-candidate-rejection".into(),
                crate::TaskAttemptEvidenceKind::CandidateRejectedKnown,
                b"late candidate-rejection source".to_vec(),
            )
            .expect("construct late candidate source"),
        },
    );
    let blocked = TaskAttemptKnownCleanupOutcome::Blocked(
        crate::TaskAttemptBlockedCause::AuthorityExpansionRequired {
            authority_request_id: "post-disposition-authority-request".into(),
            evidence: crate::TaskAttemptEvidence::new(
                "post-disposition-blocked".into(),
                crate::TaskAttemptEvidenceKind::AuthorityExpansionRequired,
                b"late policy source".to_vec(),
            )
            .expect("construct late policy source"),
        },
    );
    let baseline = (
        row_count(&fixture.ledger, "task_attempt_worker_exit_authorities"),
        row_count(
            &fixture.ledger,
            "task_attempt_candidate_rejection_authorities",
        ),
        row_count(&fixture.ledger, "task_attempt_policy_cause_authorities"),
    );
    for outcome in [&worker_exit, &candidate_rejection, &blocked] {
        assert!(
            fixture
                .ledger
                .record_task_attempt_cleanup_outcome_authority(
                    &fixture.attempt,
                    outcome,
                    1_500,
                )
                .is_err(),
            "disposed attempt accepted a new source family"
        );
        assert_eq!(
            (
                row_count(&fixture.ledger, "task_attempt_worker_exit_authorities"),
                row_count(
                    &fixture.ledger,
                    "task_attempt_candidate_rejection_authorities",
                ),
                row_count(&fixture.ledger, "task_attempt_policy_cause_authorities"),
            ),
            baseline,
            "stale source rejection must write no authority rows"
        );
    }
    assert_eq!(
        fixture
            .ledger
            .record_task_attempt_cleanup_outcome_authority(
                &fixture.attempt,
                &cancellation,
                1_350,
            )
            .expect("exact durable source replay remains readable after release"),
        cancellation
    );
}

#[test]
fn task_attempt_recovery_rejects_crossed_uncertain_reference() {
    let (database, mut ledger, attempt, _, _launch, admission) =
        recovery_admit_task_launch(2, "uncertain");
    let preparation = test_launch_preparation_attempt(&admission, "uncertain", 1_150);
    ledger
        .with_runner_launch_preparation_claim(&admission, &preparation, |_| {
            RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::NativeEffectUncertain,
                native_evidence_bytes: b"native preparation survival is uncertain".to_vec(),
                finished_at_unix_ms: 1_160,
            }
        })
        .expect("persist exact native uncertainty");
    let uncertain = TaskAttemptRecoveryFacts::UncertainAuthority {
        evidence_id: preparation.native_journal_id.clone(),
    };

    assert_eq!(
        ledger
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &uncertain,
            )
            .expect("derive uncertainty from exact native journal"),
        TaskAttemptRecoveryDecision::TerminalizeUnknown
    );
    assert_eq!(
        ledger
            .load_task_attempt_recovery_projection("sprint-1", "task-1", &attempt.attempt_id)
            .expect("authoritatively derive native uncertainty"),
        LedgerTaskAttemptRecoveryProjection {
            facts: uncertain.clone(),
            decision: TaskAttemptRecoveryDecision::TerminalizeUnknown,
        }
    );
    assert!(
        ledger
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::UncertainAuthority {
                    evidence_id: "crossed-launch".into(),
                },
            )
            .is_err()
    );
    drop(ledger);
    let reopened = EventLedger::open_read_only(&database.path).expect("reopen uncertain recovery");
    assert_eq!(
        reopened
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &uncertain,
            )
            .expect("rederive exact native uncertainty"),
        TaskAttemptRecoveryDecision::TerminalizeUnknown
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Marker derivation, tamper rejection, restart, and closure are one recovery identity lifecycle.
fn task_attempt_recovery_matrix_is_derived_cross_checked_stable_and_closes() {
    let database = TestDatabase::new();
    // This matrix preserves the v15 quarantine branch where native cleanup is
    // intentionally unavailable. Current v27 commands cannot close capture
    // without both cleanup domains, so migrate this exact history afterward.
    let mut ledger = open_v26_test_ledger(&database);
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(&launch.worker_lease.as_ref().unwrap().lease_id)
        .expect("load recovery matrix attempt");
    let (uncertain_intent, uncertain_proposal, uncertain_permit) =
        persist_command_domain_intent(&mut ledger, &launch, "recovery-matrix-uncertain", 1_200);
    let uncertain_observation = persist_command_domain_observation(
        &mut ledger,
        &uncertain_intent,
        &uncertain_proposal,
        uncertain_permit,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_250,
    );
    let (metadata, transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "recovery-matrix-disposition",
        "recovery-matrix-task-unknown",
        1_300,
    );
    let marker = v15_unknown_marker(&metadata);
    let uncertain = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "recovery-matrix-native-survival".into(),
        authority_reference_ids: vec![uncertain_observation.observation_id],
        evidence: crate::TaskAttemptEvidence::new(
            "recovery-matrix-native-survival-evidence".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"native process survival cannot be proven for matrix".to_vec(),
        )
        .expect("construct matrix uncertainty"),
    };
    ledger
        .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
        .expect("create exact unknown matrix");

    let evidence_id = ledger
        .load_task_attempt_recovery_matrix_evidence_id("sprint-1")
        .expect("derive exact recovery matrix identity");
    assert!(evidence_id.starts_with("recovery-matrix-"));
    assert_eq!(evidence_id.len(), "recovery-matrix-".len() + 64);
    let facts = TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady {
        marker_id: marker.marker_id.clone(),
        evidence_id: evidence_id.clone(),
    };
    assert_eq!(
        ledger
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &facts,
            )
            .expect("derive terminal Unknown recovery"),
        TaskAttemptRecoveryDecision::TerminalizeSprintUnknown
    );
    assert_eq!(
        ledger
            .load_task_attempt_recovery_projection("sprint-1", "task-1", &attempt.attempt_id)
            .expect("authoritatively derive all-domain terminal recovery"),
        LedgerTaskAttemptRecoveryProjection {
            facts: facts.clone(),
            decision: TaskAttemptRecoveryDecision::TerminalizeSprintUnknown,
        }
    );
    for forged in [
        TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady {
            marker_id: "forged-marker".into(),
            evidence_id: evidence_id.clone(),
        },
        TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady {
            marker_id: marker.marker_id.clone(),
            evidence_id: format!("recovery-matrix-{}", "0".repeat(64)),
        },
    ] {
        assert!(
            ledger
                .project_task_attempt_recovery_decision(
                    "sprint-1",
                    "task-1",
                    &attempt.attempt_id,
                    &forged,
                )
                .is_err()
        );
    }
    let mutation = ledger.connection.execute(
        "UPDATE task_attempt_dispositions SET disposed_at_unix_ms = disposed_at_unix_ms + 1
         WHERE disposition_id = ?1",
        [&metadata.disposition_id],
    );
    assert!(mutation.is_err(), "immutable matrix rows must reject mutation");
    assert_eq!(
        ledger
            .load_task_attempt_recovery_matrix_evidence_id("sprint-1")
            .expect("matrix remains stable after rejected mutation"),
        evidence_id
    );
    drop(ledger);

    let mut reopened = EventLedger::open(&database.path).expect("reopen recovery matrix");
    assert_eq!(
        reopened
            .load_task_attempt_recovery_matrix_evidence_id("sprint-1")
            .expect("rederive stable recovery matrix"),
        evidence_id
    );
    assert_eq!(
        reopened
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &facts,
            )
            .expect("rederive terminal Unknown after restart"),
        TaskAttemptRecoveryDecision::TerminalizeSprintUnknown
    );
    let terminal =
        v15_sprint_unknown_evidence("sprint-1", "recovery-matrix-terminal", 1_400);
    reopened
        .terminalize_sprint_unknown(&marker, &terminal)
        .expect("close exact recovery matrix marker");
    assert!(
        reopened
            .load_task_attempt_recovery_matrix_evidence_id("sprint-1")
            .is_err()
    );
    assert!(
        reopened
            .project_task_attempt_recovery_decision(
                "sprint-1",
                "task-1",
                &attempt.attempt_id,
                &facts,
            )
            .is_err()
    );
}
