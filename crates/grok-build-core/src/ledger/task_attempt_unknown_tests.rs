fn v15_unknown_metadata(
    ledger: &EventLedger,
    attempt: &TaskAttempt,
    disposition_id: &str,
    event_id: &str,
    disposed_at_unix_ms: u64,
) -> (TaskAttemptDispositionMetadata, AgentEvent) {
    let metadata = TaskAttemptDispositionMetadata {
        contract_version: CONTRACT_VERSION,
        disposition_id: disposition_id.into(),
        attempt: attempt.clone(),
        from_state: TaskState::Running,
        state_transition_event_id: event_id.into(),
        disposed_at_unix_ms,
    };
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(&attempt.worker_lease.sprint_id)
            .expect("unknown transition sequence"),
        event_id: event_id.into(),
        sprint_id: attempt.worker_lease.sprint_id.clone(),
        task_id: Some(attempt.worker_lease.task_id.clone()),
        worker_id: Some(attempt.worker_lease.worker_id.clone()),
        causation_id: Some(attempt.opening_event_id.clone()),
        correlation_id: format!("{disposition_id}-lifecycle"),
        policy_hash: None,
        occurred_at_unix_ms: disposed_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Running".into(),
            to: "Unknown".into(),
        },
    };
    (metadata, event)
}

fn v15_unknown_marker(
    metadata: &TaskAttemptDispositionMetadata,
) -> SprintUnknownTerminalizationPending {
    SprintUnknownTerminalizationPending {
        contract_version: CONTRACT_VERSION,
        marker_id: format!("{}-marker", metadata.disposition_id),
        sprint_id: metadata.attempt.worker_lease.sprint_id.clone(),
        first_attempt_id: metadata.attempt.attempt_id.clone(),
        first_disposition_id: metadata.disposition_id.clone(),
        created_at_unix_ms: metadata.disposed_at_unix_ms,
    }
}

fn v15_sprint_unknown_evidence(
    sprint_id: &str,
    record_id: &str,
    terminal_at_unix_ms: u64,
) -> SprintTerminalEvidence {
    SprintTerminalEvidence {
        contract_version: CONTRACT_VERSION,
        record_id: record_id.into(),
        sprint_id: sprint_id.into(),
        state: NonSuccessTerminalState::Unknown,
        reason: "exact task-attempt authority remains unknown".into(),
        terminal_at_unix_ms,
    }
}

fn v15_acquire_task_attempt(
    ledger: &mut EventLedger,
    sprint_id: &str,
    task: &TaskSpec,
    worker_id: &str,
    lease_epoch: u64,
    ready_at_unix_ms: u64,
    acquired_at_unix_ms: u64,
) -> WorkerLease {
    let ready = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(sprint_id)
            .expect("two-attempt Ready sequence"),
        event_id: format!("{}-two-unknown-ready", task.task_id),
        sprint_id: sprint_id.into(),
        task_id: Some(task.task_id.clone()),
        worker_id: None,
        causation_id: None,
        correlation_id: format!("{}-two-unknown-lifecycle", task.task_id),
        policy_hash: None,
        occurred_at_unix_ms: ready_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Planned".into(),
            to: "Ready".into(),
        },
    };
    ledger.append_event(&ready).expect("ready independent task");
    let lease = WorkerLease::new(
        sprint_id.into(),
        lease_epoch,
        task.task_id.clone(),
        worker_id.into(),
        task.path_scopes.clone(),
        acquired_at_unix_ms,
    )
    .expect("construct independent task lease");
    let acquired = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger
            .next_sequence(sprint_id)
            .expect("two-attempt Leased sequence"),
        event_id: format!("{}-two-unknown-leased", task.task_id),
        sprint_id: sprint_id.into(),
        task_id: Some(task.task_id.clone()),
        worker_id: Some(worker_id.into()),
        causation_id: Some(ready.event_id),
        correlation_id: format!("{}-two-unknown-lifecycle", task.task_id),
        policy_hash: None,
        occurred_at_unix_ms: acquired_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Ready".into(),
            to: "Leased".into(),
        },
    };
    ledger
        .acquire_task_attempt(&lease, &acquired)
        .expect("acquire independent task attempt");
    lease
}

fn v15_admit_running_attempt(
    ledger: &mut EventLedger,
    lease: &WorkerLease,
    suffix: &str,
    launched_at_unix_ms: u64,
    registered_at_unix_ms: u64,
    started_at_unix_ms: u64,
) -> (RunnerLaunchIntent, TaskAttempt) {
    let policy = compiled_shadow_test_policy(&format!("two-unknown-policy-{suffix}"));
    let mut launch = runner_launch(
        &format!("two-unknown-launch-{suffix}"),
        &format!("two-unknown-session-{suffix}"),
        RunnerSessionPurpose::TaskWorker,
        Some(&lease.worker_id),
        &policy,
        launched_at_unix_ms,
    );
    launch.worker_lease = Some(lease.clone());
    let (cleanup_intent, _, cleanup_request_bytes, cleanup_event) =
        test_runner_launch_cleanup_contracts(ledger, &launch, WorkerCleanupBackend::LinuxCgroupV2)
            .expect("build independent launch cleanup admission");
    ledger
        .admit_runner_launch_with_cleanup(
            &launch,
            &policy,
            &cleanup_intent,
            &cleanup_request_bytes,
            &cleanup_event,
        )
        .expect("admit independent task runner");
    ledger
        .register_runner_session(&runner_session(&launch, registered_at_unix_ms), &policy)
        .expect("register independent task runner");
    let running = enter_test_task_attempt_running(ledger, &launch, started_at_unix_ms);
    (launch, running.attempt)
}

fn v15_prepare_two_running_attempts(
    ledger: &mut EventLedger,
) -> [(RunnerLaunchIntent, TaskAttempt); 2] {
    let (mut spec, mut graph) = sprint_fixture();
    spec.max_workers = 2;
    graph.tasks[0].path_scopes = vec![PathScope::Relative(PathBuf::from("task-a"))];
    graph.tasks.push(TaskSpec {
        task_id: "task-2".into(),
        goal: "Run as a second independent attempt".into(),
        dependencies: Vec::new(),
        path_scopes: vec![PathScope::Relative(PathBuf::from("task-b"))],
        acceptance_checks: vec!["tests".into()],
        base_snapshot: spec.base_snapshot.clone(),
        required: true,
    });
    ledger
        .create_sprint(&spec, &graph, 1_000)
        .expect("persist two-attempt sprint");
    ledger
        .persist_workspace_snapshot(
            &spec.sprint_id,
            &WorkspaceSnapshot {
                snapshot_id: spec.base_snapshot.clone(),
                grant_hash: spec.workspace_grant.grant_hash.clone(),
                created_at_unix_ms: 1_000,
            },
        )
        .expect("persist two-attempt base snapshot");
    let lease_a = v15_acquire_task_attempt(
        ledger,
        &spec.sprint_id,
        &graph.tasks[0],
        "worker-a",
        1,
        1_050,
        1_060,
    );
    let lease_b = v15_acquire_task_attempt(
        ledger,
        &spec.sprint_id,
        &graph.tasks[1],
        "worker-b",
        2,
        1_070,
        1_080,
    );
    [
        v15_admit_running_attempt(ledger, &lease_a, "a", 1_100, 1_110, 1_120),
        v15_admit_running_attempt(ledger, &lease_b, "b", 1_130, 1_140, 1_150),
    ]
}

fn v15_unknown_composite_counts(ledger: &EventLedger) -> [i64; 7] {
    [
        row_count(ledger, "task_attempt_dispositions"),
        row_count(ledger, "task_attempt_cleanup_result_coverage"),
        row_count(ledger, "worker_lease_releases"),
        row_count(ledger, "effect_observations"),
        row_count(ledger, "worker_cleanup_receipts"),
        row_count(ledger, "sprint_unknown_terminalization_pending"),
        row_count(ledger, "agent_events"),
    ]
}

#[test]
#[allow(clippy::too_many_lines)] // One end-to-end quarantine test covers source binding, replay, closure, and restart.
fn v15_unknown_quarantine_is_source_bound_frozen_replayable_and_closable() {
    let database = TestDatabase::new();
    // A quarantined attempt deliberately retains its native domain and cannot
    // satisfy v27's two-cleanup capture resolution. Preserve the v15 branch,
    // then migrate its commands as explicitly exempt historical authority.
    let mut ledger = open_v26_test_ledger(&database);
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(
            &launch
                .worker_lease
                .as_ref()
                .expect("task-worker lease")
                .lease_id,
        )
        .expect("load quarantine attempt");
    let (uncertain_intent, uncertain_proposal, uncertain_permit) =
        persist_command_domain_intent(&mut ledger, &launch, "quarantine-uncertain", 1_200);
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
    let (pending_intent, pending_proposal, pending_permit) =
        persist_command_domain_intent(&mut ledger, &launch, "quarantine-pending", 1_260);
    let (metadata, transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "quarantine-disposition",
        "quarantine-task-unknown",
        1_300,
    );
    let marker = v15_unknown_marker(&metadata);
    let mut authority_reference_ids = vec![
        uncertain_observation.observation_id.clone(),
        pending_intent.effect_id.clone(),
    ];
    authority_reference_ids.sort();
    let uncertain = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "quarantine-native-survival".into(),
        authority_reference_ids,
        evidence: crate::TaskAttemptEvidence::new(
            "quarantine-native-survival-evidence".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"native process survival cannot be proven".to_vec(),
        )
        .expect("construct quarantine evidence"),
    };
    let disposition = ledger
        .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
        .expect("atomically quarantine task attempt");
    assert!(matches!(
        disposition,
        TaskAttemptDisposition::UnknownQuarantined(_)
    ));
    let quarantine_history = ledger
        .load_task_attempt_history(
            &attempt.worker_lease.sprint_id,
            &attempt.worker_lease.task_id,
        )
        .expect("load optional-completion quarantine history");
    assert!(matches!(
        validate_attempted_optional_task_closure(
            &ledger.connection,
            &attempt.worker_lease.sprint_id,
            &attempt.worker_lease.task_id,
            &quarantine_history,
        ),
        Err(LedgerError::ReferenceMismatch {
            entity: "attempted optional task closure",
            ..
        })
    ));
    assert_eq!(
        ledger
            .load_active_worker_leases(&attempt.worker_lease.sprint_id)
            .expect("load quarantined active lease"),
        vec![attempt.worker_lease.clone()]
    );
    assert_eq!(
        ledger
            .load_task_attempt_history(
                &attempt.worker_lease.sprint_id,
                &attempt.worker_lease.task_id,
            )
            .expect("load pending quarantine history")
            .unknown_terminalization_pending,
        Some(marker.clone())
    );
    assert_eq!(
        ledger
            .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
            .expect("exact quarantine replay"),
        disposition
    );
    let late_known_source = TaskAttemptKnownCleanupOutcome::Blocked(
        crate::TaskAttemptBlockedCause::AuthorityExpansionRequired {
            authority_request_id: "quarantine-late-authority-request".into(),
            evidence: crate::TaskAttemptEvidence::new(
                "quarantine-late-known-source".into(),
                crate::TaskAttemptEvidenceKind::AuthorityExpansionRequired,
                b"known source must not enter a quarantined attempt".to_vec(),
            )
            .expect("construct late quarantined source"),
        },
    );
    assert!(
        ledger
            .record_task_attempt_cleanup_outcome_authority(
                &attempt,
                &late_known_source,
                1_320,
            )
            .is_err(),
        "open Unknown quarantine must reject new known-cleanup authority"
    );
    assert_eq!(
        row_count(&ledger, "task_attempt_policy_cause_authorities"),
        0,
        "quarantined source rejection must write nothing"
    );
    let pending_observation = persist_command_domain_observation(
        &mut ledger,
        &pending_intent,
        &pending_proposal,
        pending_permit,
        EffectOutcome::FailedBeforeEffect {
            evidence_digest: effect_evidence_digest(),
        },
        1_350,
    );
    assert_eq!(
        row_count(&ledger, "sprint_unknown_pending_observation_admissions"),
        1
    );
    assert_eq!(
        ledger
            .load_effect(&pending_intent.effect_id)
            .expect("reload admitted pending observation")
            .observation,
        Some(pending_observation.clone())
    );

    let generic = v15_sprint_unknown_evidence(
        &attempt.worker_lease.sprint_id,
        "generic-unknown-must-not-strand-marker",
        1_400,
    );
    assert!(matches!(
        ledger.record_unsuccessful_terminal_outcome(&generic),
        Err(LedgerError::ReferenceMismatch {
            entity: "sprint terminal evidence",
            ..
        })
    ));
    assert!(ledger.load_terminal_outcome("sprint-1").unwrap().is_none());

    let terminal = v15_sprint_unknown_evidence("sprint-1", "closed-sprint-unknown", 1_400);
    let persisted = ledger
        .terminalize_sprint_unknown(&marker, &terminal)
        .expect("close quarantined sprint Unknown");
    assert_eq!(persisted.evidence, terminal);
    assert_eq!(
        ledger
            .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
            .expect("exact quarantine disposition replay after marker closure"),
        disposition
    );
    assert_eq!(
        ledger
            .terminalize_sprint_unknown(&marker, &terminal)
            .expect("exact sprint Unknown replay"),
        persisted
    );
    let closed_history = ledger
        .load_task_attempt_history("sprint-1", "task-1")
        .expect("load closed quarantine history");
    assert_eq!(closed_history.sprint_state, SprintState::Unknown);
    assert!(closed_history.unknown_terminalization_pending.is_none());
    drop(ledger);

    drop(EventLedger::open(&database.path).expect("migrate quarantine ledger to current schema"));
    let reopened = EventLedger::open_read_only(&database.path).expect("reopen quarantine ledger");
    assert_eq!(
        reopened
            .load_task_attempt_disposition(&metadata.disposition_id)
            .expect("reload quarantine disposition"),
        disposition
    );
    assert_eq!(
        reopened
            .load_terminal_outcome("sprint-1")
            .expect("reload sprint Unknown")
            .expect("terminal exists"),
        persisted
    );
    assert_eq!(
        reopened
            .load_active_worker_leases("sprint-1")
            .expect("reload quarantined active lease"),
        vec![attempt.worker_lease]
    );
    drop(reopened);

    let mut corrupted = EventLedger::open(&database.path).expect("open closure corruption ledger");
    corrupted
        .connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TRIGGER sprint_unknown_terminalization_closure_requirements_no_delete;
             DELETE FROM sprint_unknown_terminalization_closure_requirements;
             PRAGMA foreign_keys = ON;",
        )
        .expect("remove reciprocal closure requirement through corruption bypass");
    assert!(matches!(
        corrupted.terminalize_sprint_unknown(&marker, &terminal),
        Err(LedgerError::Corrupt {
            entity: "sprint unknown terminalization closure requirement",
            ..
        })
    ));
    corrupted
        .connection
        .execute_batch(
            "DROP TRIGGER sprint_unknown_pending_observation_admissions_no_delete;
             DELETE FROM sprint_unknown_pending_observation_admissions;",
        )
        .expect("remove pending-observation admission through corruption bypass");
    assert!(matches!(
        corrupted.load_effect(&pending_intent.effect_id),
        Err(LedgerError::Corrupt {
            entity: "pending effect observation admission",
            ..
        })
    ));
}

#[test]
#[allow(clippy::too_many_lines)] // Two live attempts and the deferred close form one indivisible authority matrix.
fn v15_two_quarantines_share_one_marker_and_block_closure_until_both_resolve() {
    let database = TestDatabase::new();
    let mut ledger = open_v26_test_ledger(&database);
    let [(launch_a, attempt_a), (launch_b, attempt_b)] =
        v15_prepare_two_running_attempts(&mut ledger);
    let (uncertain_intent_a, uncertain_proposal_a, uncertain_permit_a) =
        persist_command_domain_intent(&mut ledger, &launch_a, "two-uncertain-a", 1_170);
    let uncertain_observation_a = persist_command_domain_observation(
        &mut ledger,
        &uncertain_intent_a,
        &uncertain_proposal_a,
        uncertain_permit_a,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_180,
    );
    let (uncertain_intent_b, uncertain_proposal_b, uncertain_permit_b) =
        persist_command_domain_intent(&mut ledger, &launch_b, "two-uncertain-b", 1_190);
    let uncertain_observation_b = persist_command_domain_observation(
        &mut ledger,
        &uncertain_intent_b,
        &uncertain_proposal_b,
        uncertain_permit_b,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_200,
    );
    let held_leases = vec![
        attempt_a.worker_lease.clone(),
        attempt_b.worker_lease.clone(),
    ];

    let (metadata_a, transition_a) = v15_unknown_metadata(
        &ledger,
        &attempt_a,
        "two-quarantine-disposition-a",
        "two-quarantine-task-unknown-a",
        1_300,
    );
    let marker = v15_unknown_marker(&metadata_a);
    let uncertain_a = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "two-quarantine-authority-a".into(),
        authority_reference_ids: vec![uncertain_observation_a.observation_id],
        evidence: crate::TaskAttemptEvidence::new(
            "two-quarantine-evidence-a".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"task A native process survival remains uncertain".to_vec(),
        )
        .expect("construct task A quarantine evidence"),
    };
    let disposition_a = ledger
        .quarantine_task_attempt_unknown(&metadata_a, &uncertain_a, &marker, &transition_a)
        .expect("quarantine first independent attempt");
    assert_eq!(
        ledger
            .load_active_worker_leases("sprint-1")
            .expect("both quarantined and unresolved leases remain held"),
        held_leases
    );
    assert_eq!(
        row_count(&ledger, "sprint_unknown_terminalization_pending"),
        1
    );
    assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 1);

    let terminal = v15_sprint_unknown_evidence("sprint-1", "two-quarantine-terminal", 1_500);
    assert!(matches!(
        ledger.terminalize_sprint_unknown(&marker, &terminal),
        Err(LedgerError::ReferenceMismatch {
            entity: "sprint unknown terminalization closure",
            ..
        })
    ));
    assert!(ledger.load_terminal_outcome("sprint-1").unwrap().is_none());
    assert_eq!(
        row_count(&ledger, "sprint_unknown_terminalization_closures"),
        0
    );

    let (metadata_b, transition_b) = v15_unknown_metadata(
        &ledger,
        &attempt_b,
        "two-quarantine-disposition-b",
        "two-quarantine-task-unknown-b",
        1_400,
    );
    let uncertain_b = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "two-quarantine-authority-b".into(),
        authority_reference_ids: vec![uncertain_observation_b.observation_id],
        evidence: crate::TaskAttemptEvidence::new(
            "two-quarantine-evidence-b".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"task B native process survival remains uncertain".to_vec(),
        )
        .expect("construct task B quarantine evidence"),
    };
    let disposition_b = ledger
        .quarantine_task_attempt_unknown(&metadata_b, &uncertain_b, &marker, &transition_b)
        .expect("quarantine second attempt under the exact first marker");
    assert_eq!(
        row_count(&ledger, "sprint_unknown_terminalization_pending"),
        1
    );
    assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 2);
    assert_eq!(
        ledger
            .load_active_worker_leases("sprint-1")
            .expect("both quarantined leases remain held"),
        held_leases
    );
    for task_id in ["task-1", "task-2"] {
        assert_eq!(
            ledger
                .load_task_attempt_history("sprint-1", task_id)
                .expect("load shared pending marker")
                .unknown_terminalization_pending,
            Some(marker.clone())
        );
    }

    let persisted_terminal = ledger
        .terminalize_sprint_unknown(&marker, &terminal)
        .expect("close only after both attempts have durable quarantine authority");
    assert_eq!(persisted_terminal.evidence, terminal);
    for task_id in ["task-1", "task-2"] {
        let history = ledger
            .load_task_attempt_history("sprint-1", task_id)
            .expect("load closed two-quarantine history");
        assert_eq!(history.sprint_state, SprintState::Unknown);
        assert!(history.unknown_terminalization_pending.is_none());
    }
    drop(ledger);

    drop(EventLedger::open(&database.path).expect("migrate two-quarantine ledger to current"));
    let reopened = EventLedger::open_read_only(&database.path).expect("reopen two quarantines");
    assert_eq!(
        reopened
            .load_task_attempt_disposition(&metadata_a.disposition_id)
            .expect("reload task A quarantine"),
        disposition_a
    );
    assert_eq!(
        reopened
            .load_task_attempt_disposition(&metadata_b.disposition_id)
            .expect("reload task B quarantine"),
        disposition_b
    );
    assert_eq!(
        reopened
            .load_active_worker_leases("sprint-1")
            .expect("reload both permanently held leases"),
        held_leases
    );
    assert_eq!(
        reopened
            .load_terminal_outcome("sprint-1")
            .expect("reload two-quarantine terminal")
            .expect("two-quarantine terminal exists"),
        persisted_terminal
    );
}

#[test]
fn v15_unknown_quarantine_rejects_invented_authority_in_api_and_sql() {
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open crossed quarantine ledger");
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(&launch.worker_lease.as_ref().unwrap().lease_id)
        .expect("load crossed quarantine attempt");
    let (metadata, transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "crossed-quarantine-disposition",
        "crossed-quarantine-task-unknown",
        1_300,
    );
    let marker = v15_unknown_marker(&metadata);
    let uncertain = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "crossed-quarantine".into(),
        authority_reference_ids: vec!["invented-authority".into()],
        evidence: crate::TaskAttemptEvidence::new(
            "crossed-quarantine-evidence".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"untrusted caller supplied uncertainty".to_vec(),
        )
        .expect("construct crossed uncertainty"),
    };
    assert!(
        ledger
            .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
            .is_err()
    );
    assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 0);
    assert_eq!(
        row_count(&ledger, "sprint_unknown_terminalization_pending"),
        0
    );

    let disposition = TaskAttemptDisposition::UnknownQuarantined(
        crate::TaskAttemptUnknownQuarantinedDisposition {
            metadata,
            uncertain_evidence: uncertain,
        },
    );
    let transaction = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start crossed direct-SQL quarantine");
    let error = task_attempt_authority::insert_disposition(&transaction, &disposition)
        .expect_err("schema rejects invented uncertainty reference");
    assert!(
        error
            .to_string()
            .contains("UnknownQuarantined requires the complete canonical attempt-scoped uncertain-authority set"),
        "unexpected quarantine schema error: {error}"
    );
    transaction.rollback().expect("rollback crossed quarantine");
}

#[test]
fn v15_unknown_quarantine_rejects_routine_launch_and_cleanup_authority_without_writes() {
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open routine-authority ledger");
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(&launch.worker_lease.as_ref().unwrap().lease_id)
        .expect("load routine-authority attempt");
    let cleanup_effect_id = ledger
        .load_runner_launch_cleanup_admission("sprint-1", &launch.launch_id)
        .expect("load mandatory launch cleanup")
        .cleanup_effect
        .intent
        .effect_id;
    let baseline = (
        row_count(&ledger, "task_attempt_dispositions"),
        row_count(&ledger, "sprint_unknown_terminalization_pending"),
        row_count(&ledger, "agent_events"),
    );

    for (suffix, authority_reference_id) in [
        ("launch", launch.launch_id),
        ("cleanup", cleanup_effect_id),
    ] {
        let disposition_id = format!("routine-{suffix}-quarantine");
        let event_id = format!("routine-{suffix}-unknown-event");
        let (metadata, transition) =
            v15_unknown_metadata(&ledger, &attempt, &disposition_id, &event_id, 1_300);
        let marker = v15_unknown_marker(&metadata);
        let uncertain = crate::TaskAttemptUncertainEvidence {
            uncertainty_id: format!("routine-{suffix}-uncertainty"),
            authority_reference_ids: vec![authority_reference_id],
            evidence: crate::TaskAttemptEvidence::new(
                format!("routine-{suffix}-uncertainty-evidence"),
                crate::TaskAttemptEvidenceKind::UncertainAuthority,
                format!("routine {suffix} authority is not uncertainty").into_bytes(),
            )
            .expect("construct routine-authority evidence"),
        };
        assert!(
            ledger
                .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
                .is_err()
        );
        assert_eq!(
            (
                row_count(&ledger, "task_attempt_dispositions"),
                row_count(&ledger, "sprint_unknown_terminalization_pending"),
                row_count(&ledger, "agent_events"),
            ),
            baseline,
            "rejected routine {suffix} authority must write nothing"
        );

        let disposition = TaskAttemptDisposition::UnknownQuarantined(
            crate::TaskAttemptUnknownQuarantinedDisposition {
                metadata,
                uncertain_evidence: uncertain,
            },
        );
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start routine-authority SQL bypass");
        let error = task_attempt_authority::insert_disposition(&transaction, &disposition)
            .expect_err("schema rejects routine authority as Unknown uncertainty");
        assert!(
            error
                .to_string()
                .contains("UnknownQuarantined requires the complete canonical attempt-scoped uncertain-authority set"),
            "unexpected routine-authority schema error: {error}"
        );
        transaction
            .rollback()
            .expect("rollback routine-authority SQL bypass");
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Replay, release, closure, and restart prove one atomic lifecycle.
fn v15_unknown_cleaned_is_atomic_replayable_released_and_closable() {
    let database = TestDatabase::new();
    let mut ledger = open_v26_test_ledger(&database);
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(&launch.worker_lease.as_ref().unwrap().lease_id)
        .expect("load unknown-cleaned attempt");
    let (intent, proposal, permit) =
        persist_command_domain_intent(&mut ledger, &launch, "unknown-command", 1_200);
    let observation = persist_command_domain_observation(
        &mut ledger,
        &intent,
        &proposal,
        permit,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_300,
    );
    let unknown = crate::TaskAttemptUnknownEvidence {
        effect_id: intent.effect_id.clone(),
        observation_id: observation.observation_id.clone(),
        evidence: crate::TaskAttemptEvidence::new(
            "unknown-command-evidence".into(),
            crate::TaskAttemptEvidenceKind::UnknownTerminalEffect,
            EFFECT_EVIDENCE_BYTES.to_vec(),
        )
        .expect("construct terminal unknown effect evidence"),
    };
    let (metadata, mut transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "unknown-cleaned-disposition",
        "unknown-cleaned-task-unknown",
        1_500,
    );
    transition.sequence += 1;
    let marker = v15_unknown_marker(&metadata);
    let disposition = ledger
        .with_task_attempt_unknown_cleaned_disposition_exclusion(
            &metadata,
            &unknown,
            "unknown-cleaned-release",
            &marker,
            &transition,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "unknown-cleaned",
                    1_400,
                ))
            },
        )
        .expect("atomically clean unknown attempt");
    assert!(matches!(
        disposition,
        TaskAttemptDisposition::UnknownCleaned(_)
    ));
    let cleaned_history = ledger
        .load_task_attempt_history(
            &attempt.worker_lease.sprint_id,
            &attempt.worker_lease.task_id,
        )
        .expect("load optional-completion unknown-cleaned history");
    assert!(matches!(
        validate_attempted_optional_task_closure(
            &ledger.connection,
            &attempt.worker_lease.sprint_id,
            &attempt.worker_lease.task_id,
            &cleaned_history,
        ),
        Err(LedgerError::ReferenceMismatch {
            entity: "attempted optional task closure",
            ..
        })
    ));
    assert!(
        ledger
            .load_active_worker_leases("sprint-1")
            .unwrap()
            .is_empty()
    );
    let invoked = Arc::new(AtomicBool::new(false));
    let replay_invoked = Arc::clone(&invoked);
    assert_eq!(
        ledger
            .with_task_attempt_unknown_cleaned_disposition_exclusion(
                &metadata,
                &unknown,
                "unknown-cleaned-release",
                &marker,
                &transition,
                move |_| {
                    replay_invoked.store(true, Ordering::SeqCst);
                    panic!("exact unknown-cleaned replay must not invoke native cleanup")
                },
            )
            .expect("exact unknown-cleaned replay"),
        disposition
    );
    assert!(!invoked.load(Ordering::SeqCst));

    let terminal =
        v15_sprint_unknown_evidence("sprint-1", "unknown-cleaned-sprint-terminal", 1_600);
    ledger
        .terminalize_sprint_unknown(&marker, &terminal)
        .expect("close cleaned sprint Unknown");
    let invoked_after_closure = Arc::new(AtomicBool::new(false));
    let replay_invoked_after_closure = Arc::clone(&invoked_after_closure);
    assert_eq!(
        ledger
            .with_task_attempt_unknown_cleaned_disposition_exclusion(
                &metadata,
                &unknown,
                "unknown-cleaned-release",
                &marker,
                &transition,
                move |_| {
                    replay_invoked_after_closure.store(true, Ordering::SeqCst);
                    panic!("closed-marker replay must not invoke native cleanup")
                },
            )
            .expect("exact UnknownCleaned replay after marker closure"),
        disposition
    );
    assert!(!invoked_after_closure.load(Ordering::SeqCst));
    drop(ledger);
    drop(EventLedger::open(&database.path).expect("migrate unknown-cleaned ledger to current"));
    let reopened = EventLedger::open_read_only(&database.path).expect("reopen unknown-cleaned");
    assert_eq!(
        reopened
            .load_task_attempt_disposition(&metadata.disposition_id)
            .expect("reload UnknownCleaned disposition"),
        disposition
    );
    assert!(
        reopened
            .load_active_worker_leases("sprint-1")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        reopened
            .load_task_attempt_history("sprint-1", "task-1")
            .expect("reload cleaned unknown history")
            .sprint_state,
        SprintState::Unknown
    );
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)] // One filesystem fault proves commit ambiguity, callback cardinality, replay, and restart.
fn v15_unknown_cleaned_post_commit_hardlink_is_recoverable_without_second_callback() {
    let database = TestDatabase::new();
    let mut ledger =
        EventLedger::open(&database.path).expect("open hardlink UnknownCleaned ledger");
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(&launch.worker_lease.as_ref().unwrap().lease_id)
        .expect("load hardlink UnknownCleaned attempt");
    let cleanup_effect_id = ledger
        .load_runner_launch_cleanup_admission("sprint-1", &launch.launch_id)
        .expect("load exact cleanup recovery authority")
        .cleanup_effect
        .intent
        .effect_id;
    let (intent, proposal, permit) =
        persist_command_domain_intent(&mut ledger, &launch, "hardlink-unknown-command", 1_200);
    let observation = persist_command_domain_observation(
        &mut ledger,
        &intent,
        &proposal,
        permit,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_300,
    );
    let unknown = crate::TaskAttemptUnknownEvidence {
        effect_id: intent.effect_id,
        observation_id: observation.observation_id,
        evidence: crate::TaskAttemptEvidence::new(
            "hardlink-unknown-evidence".into(),
            crate::TaskAttemptEvidenceKind::UnknownTerminalEffect,
            EFFECT_EVIDENCE_BYTES.to_vec(),
        )
        .expect("construct hardlink unknown evidence"),
    };
    let (metadata, mut transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "hardlink-unknown-cleaned-disposition",
        "hardlink-unknown-cleaned-transition",
        1_500,
    );
    transition.sequence += 1;
    let marker = v15_unknown_marker(&metadata);
    let baseline = v15_unknown_composite_counts(&ledger);
    let callback_count = Arc::new(AtomicU64::new(0));
    let first_callback_count = Arc::clone(&callback_count);
    let hardlink = database
        .directory
        .join("unknown-cleaned-post-commit-hardlink.sqlite3");
    let callback_database_path = database.path.clone();
    let callback_hardlink = hardlink.clone();

    let uncertain = ledger.with_task_attempt_unknown_cleaned_disposition_exclusion(
        &metadata,
        &unknown,
        "hardlink-unknown-cleaned-release",
        &marker,
        &transition,
        move |claim| {
            first_callback_count.fetch_add(1, Ordering::SeqCst);
            fs::hard_link(&callback_database_path, &callback_hardlink)
                .expect("inject post-callback UnknownCleaned hardening fault");
            Ok(cleanup_terminal_from_live_claim(
                claim,
                "hardlink-unknown-cleaned",
                1_400,
            ))
        },
    );
    assert!(
        matches!(
            uncertain,
        Err(LedgerError::PostCommitStateUncertain {
            operation: "task attempt unknown-cleaned disposition",
            ref recovery_id,
            ..
        }) if recovery_id == &cleanup_effect_id
        ),
        "unexpected UnknownCleaned hardlink result: {uncertain:?}"
    );
    fs::remove_file(&hardlink).expect("remove UnknownCleaned hardening fault");
    assert_eq!(callback_count.load(Ordering::SeqCst), 1);

    let disposition = ledger
        .load_task_attempt_disposition(&metadata.disposition_id)
        .expect("read back committed UnknownCleaned disposition");
    assert!(matches!(
        disposition,
        TaskAttemptDisposition::UnknownCleaned(_)
    ));
    assert!(
        ledger
            .load_effect(&cleanup_effect_id)
            .expect("read back committed cleanup effect")
            .observation
            .is_some()
    );
    assert!(
        ledger
            .load_active_worker_leases("sprint-1")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ledger
            .load_task_attempt_history("sprint-1", "task-1")
            .expect("read back committed Unknown marker")
            .unknown_terminalization_pending,
        Some(marker.clone())
    );
    let committed_counts = v15_unknown_composite_counts(&ledger);
    assert_eq!(
        committed_counts,
        [
            baseline[0] + 1,
            baseline[1] + 1,
            baseline[2] + 1,
            baseline[3] + 1,
            baseline[4] + 1,
            baseline[5] + 1,
            baseline[6] + 2,
        ]
    );

    let replay_callback_count = Arc::clone(&callback_count);
    assert_eq!(
        ledger
            .with_task_attempt_unknown_cleaned_disposition_exclusion(
                &metadata,
                &unknown,
                "hardlink-unknown-cleaned-release",
                &marker,
                &transition,
                move |_| {
                    replay_callback_count.fetch_add(1, Ordering::SeqCst);
                    panic!("durable UnknownCleaned replay must not rerun native cleanup")
                },
            )
            .expect("replay committed UnknownCleaned composite"),
        disposition
    );
    assert_eq!(callback_count.load(Ordering::SeqCst), 1);
    assert_eq!(v15_unknown_composite_counts(&ledger), committed_counts);
    drop(ledger);

    let reopened = EventLedger::open_read_only(&database.path)
        .expect("reopen post-commit UnknownCleaned ledger");
    assert_eq!(
        reopened
            .load_task_attempt_disposition(&metadata.disposition_id)
            .expect("reload post-commit UnknownCleaned disposition"),
        disposition
    );
    assert_eq!(v15_unknown_composite_counts(&reopened), committed_counts);
}

#[test]
#[allow(clippy::too_many_lines)] // Failed preflight and successful retry prove the complete atomic authority drain.
fn v15_unknown_cleaned_waits_for_sibling_result_then_drains_all_authority() {
    let database = TestDatabase::new();
    let mut ledger = open_v26_test_ledger(&database);
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(&launch.worker_lease.as_ref().unwrap().lease_id)
        .expect("load authority-drain attempt");
    let (unknown_intent, unknown_proposal, unknown_permit) =
        persist_command_domain_intent(&mut ledger, &launch, "authority-drain-unknown", 1_200);
    let (sibling_intent, sibling_proposal, sibling_permit) =
        persist_command_domain_intent(&mut ledger, &launch, "authority-drain-result", 1_250);
    let unknown_observation = persist_command_domain_observation(
        &mut ledger,
        &unknown_intent,
        &unknown_proposal,
        unknown_permit,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_300,
    );
    let unknown = crate::TaskAttemptUnknownEvidence {
        effect_id: unknown_intent.effect_id.clone(),
        observation_id: unknown_observation.observation_id.clone(),
        evidence: crate::TaskAttemptEvidence::new(
            "authority-drain-unknown-evidence".into(),
            crate::TaskAttemptEvidenceKind::UnknownTerminalEffect,
            EFFECT_EVIDENCE_BYTES.to_vec(),
        )
        .expect("construct authority-drain unknown evidence"),
    };
    let (metadata, mut transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "authority-drain-disposition",
        "authority-drain-task-unknown",
        1_600,
    );
    transition.sequence += 1;
    let marker = v15_unknown_marker(&metadata);
    let invoked = Arc::new(AtomicBool::new(false));
    let rejected_invoked = Arc::clone(&invoked);
    assert!(matches!(
        ledger.with_task_attempt_unknown_cleaned_disposition_exclusion(
            &metadata,
            &unknown,
            "authority-drain-release",
            &marker,
            &transition,
            move |_| {
                rejected_invoked.store(true, Ordering::SeqCst);
                panic!("unresolved sibling effect must reject before native cleanup")
            },
        ),
        Err(LedgerError::ReferenceMismatch {
            entity: "task attempt unknown-cleaned disposition",
            ..
        })
    ));
    assert!(!invoked.load(Ordering::SeqCst));
    assert_eq!(row_count(&ledger, "task_attempt_dispositions"), 0);
    assert_eq!(
        row_count(&ledger, "task_attempt_cleanup_result_coverage"),
        0
    );
    assert_eq!(
        row_count(&ledger, "sprint_unknown_terminalization_pending"),
        0
    );
    assert_eq!(
        ledger
            .load_active_worker_leases("sprint-1")
            .expect("failed composite retains the live lease"),
        vec![attempt.worker_lease.clone()]
    );
    assert!(
        ledger
            .load_unfinished_effects("sprint-1")
            .expect("load unresolved sibling effect")
            .iter()
            .any(|effect| effect.intent.effect_id == sibling_intent.effect_id)
    );

    let sibling_observation = persist_command_domain_observation(
        &mut ledger,
        &sibling_intent,
        &sibling_proposal,
        sibling_permit,
        EffectOutcome::Succeeded {
            evidence_digest: effect_evidence_digest(),
        },
        1_400,
    );
    assert_eq!(
        ledger
            .load_effect(&sibling_intent.effect_id)
            .expect("load exact sibling intent and result")
            .observation,
        Some(sibling_observation)
    );
    transition.sequence = ledger
        .next_sequence("sprint-1")
        .expect("authority-drain cleanup sequence")
        + 1;
    let disposition = ledger
        .with_task_attempt_unknown_cleaned_disposition_exclusion(
            &metadata,
            &unknown,
            "authority-drain-release",
            &marker,
            &transition,
            |claim| {
                Ok(cleanup_terminal_from_live_claim(
                    claim,
                    "authority-drain",
                    1_500,
                ))
            },
        )
        .expect("atomically clean after every sibling effect has an exact result");
    assert!(matches!(
        disposition,
        TaskAttemptDisposition::UnknownCleaned(_)
    ));
    assert!(
        ledger
            .load_unfinished_effects("sprint-1")
            .unwrap()
            .is_empty()
    );
    assert!(
        ledger
            .load_active_worker_leases("sprint-1")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        row_count(&ledger, "task_attempt_cleanup_result_coverage"),
        1
    );
    let effects = ledger
        .load_effects("sprint-1")
        .expect("load completely drained effect set");
    assert_eq!(effects.len(), 3);
    assert!(effects.iter().all(|effect| effect.observation.is_some()));
    assert_eq!(
        ledger
            .load_task_attempt_history("sprint-1", "task-1")
            .expect("load open authority-drain marker")
            .unknown_terminalization_pending,
        Some(marker.clone())
    );

    let terminal = v15_sprint_unknown_evidence("sprint-1", "authority-drain-terminal", 1_700);
    let persisted_terminal = ledger
        .terminalize_sprint_unknown(&marker, &terminal)
        .expect("close drained Unknown sprint");
    drop(ledger);

    drop(EventLedger::open(&database.path).expect("migrate authority-drain ledger to current"));
    let reopened = EventLedger::open_read_only(&database.path).expect("reopen authority drain");
    assert!(
        reopened
            .load_unfinished_effects("sprint-1")
            .unwrap()
            .is_empty()
    );
    assert!(
        reopened
            .load_active_worker_leases("sprint-1")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        reopened
            .load_task_attempt_disposition(&metadata.disposition_id)
            .expect("reload authority-drain disposition"),
        disposition
    );
    assert_eq!(
        reopened
            .load_terminal_outcome("sprint-1")
            .expect("reload authority-drain terminal")
            .expect("authority-drain terminal exists"),
        persisted_terminal
    );
    let reopened_history = reopened
        .load_task_attempt_history("sprint-1", "task-1")
        .expect("reload closed authority-drain history");
    assert_eq!(reopened_history.sprint_state, SprintState::Unknown);
    assert!(reopened_history.unknown_terminalization_pending.is_none());
}

#[test]
#[allow(clippy::too_many_lines)] // Real uncertainty setup and both deferred-closure bypass cuts form one regression.
fn v15_pending_unknown_direct_terminal_without_closure_requirement_is_rejected() {
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open direct unknown ledger");
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(&launch.worker_lease.as_ref().unwrap().lease_id)
        .expect("load direct unknown attempt");
    let (uncertain_intent, uncertain_proposal, uncertain_permit) =
        persist_command_domain_intent(&mut ledger, &launch, "direct-uncertain", 1_200);
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
        "direct-unknown-quarantine",
        "direct-unknown-task",
        1_300,
    );
    let marker = v15_unknown_marker(&metadata);
    let uncertain = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "direct-unknown-authority".into(),
        authority_reference_ids: vec![uncertain_observation.observation_id],
        evidence: crate::TaskAttemptEvidence::new(
            "direct-unknown-authority-evidence".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"direct unknown native survival evidence".to_vec(),
        )
        .expect("construct direct unknown evidence"),
    };
    ledger
        .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
        .expect("create open unknown marker");

    let terminal = v15_sprint_unknown_evidence("sprint-1", "direct-unknown-terminal", 1_400);
    let terminal_bytes = encode("sprint terminal evidence", &terminal).unwrap();
    let digest = Digest::sha256(&terminal_bytes);
    let transaction = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start direct terminal bypass");
    let error =
        insert_non_success_terminal_outcome(&transaction, &terminal, &terminal_bytes, &digest)
            .expect_err("schema rejects pending Unknown without closure requirement");
    assert!(
        error
            .to_string()
            .contains("pending sprint Unknown requires its exact deferred marker closure"),
        "unexpected direct terminal error: {error}"
    );
    transaction
        .rollback()
        .expect("rollback direct terminal bypass");
    assert!(ledger.load_terminal_outcome("sprint-1").unwrap().is_none());

    let event = normalized_terminal_event(
        &terminal,
        digest.clone(),
        ledger.next_sequence("sprint-1").unwrap(),
    );
    let transaction = ledger
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("start missing-closure commit cut");
    transaction
        .execute(
            "INSERT INTO sprint_unknown_terminalization_closure_requirements (
                marker_id, sprint_id, terminal_evidence_id, terminal_event_id,
                contract_version, closed_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                marker.marker_id,
                marker.sprint_id,
                terminal.record_id,
                terminal.record_id,
                i64::from(CONTRACT_VERSION),
                1_400_i64,
            ],
        )
        .expect("stage exact deferred closure requirement");
    insert_terminal_proof(
        &transaction,
        &terminal,
        &digest,
        &event,
        TerminalProofAdmission::Unknown,
    )
    .expect("stage Unknown proof marker");
    insert_non_success_terminal_outcome(&transaction, &terminal, &terminal_bytes, &digest)
        .expect("stage terminal after exact requirement");
    insert_agent_event(&transaction, &event).expect("stage normalized terminal event");
    let commit_error = transaction
        .commit()
        .expect_err("deferred coverage must reject a missing marker closure");
    assert!(
        commit_error
            .to_string()
            .contains("FOREIGN KEY constraint failed"),
        "unexpected missing-closure commit error: {commit_error}"
    );
    assert!(ledger.load_terminal_outcome("sprint-1").unwrap().is_none());
    assert_eq!(
        row_count(
            &ledger,
            "sprint_unknown_terminalization_closure_requirements"
        ),
        0
    );
}
