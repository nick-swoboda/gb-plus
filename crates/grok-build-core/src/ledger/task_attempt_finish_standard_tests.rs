fn v15_finish_matrix_counts(ledger: &EventLedger) -> [i64; 12] {
    [
        row_count(ledger, "task_attempt_dispositions"),
        row_count(ledger, "task_attempt_cleanup_result_coverage"),
        row_count(ledger, "task_attempt_integrated_result_coverage"),
        row_count(ledger, "worker_lease_releases"),
        row_count(ledger, "worker_cleanup_receipts"),
        row_count(ledger, "task_integration_receipts"),
        row_count(ledger, "effect_observations"),
        row_count(ledger, "effect_evidence_payloads"),
        row_count(ledger, "finish_receipt_ids"),
        row_count(ledger, "sprint_unknown_terminalization_pending"),
        row_count(ledger, "agent_events"),
        row_count(ledger, "worker_lease_never_launched_releases"),
    ]
}

fn v15_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

fn v15_install_statement_cut(
    ledger: &EventLedger,
    table: &str,
    identity_column: &str,
    identity: &str,
) {
    let identity = v15_sql_literal(identity);
    ledger
        .connection
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER v15_finish_matrix_statement_cut
             AFTER INSERT ON {table}
             WHEN NEW.{identity_column} = '{identity}'
             BEGIN
                 SELECT RAISE(ABORT, 'injected v15 finish-matrix statement cut');
             END;"
        ))
        .expect("install isolated v15 statement cut");
}

fn v15_remove_statement_cut(ledger: &EventLedger) {
    ledger
        .connection
        .execute_batch("DROP TRIGGER v15_finish_matrix_statement_cut;")
        .expect("remove isolated v15 statement cut");
}

#[cfg(unix)]
fn v15_install_postcommit_hardlink_fault(
    ledger: &EventLedger,
    table: &str,
    identity_column: &str,
    identity: &str,
    hardlink: &std::path::Path,
) {
    let source = ledger.database_path.clone();
    let hardlink = hardlink.to_owned();
    ledger
        .connection
        .create_scalar_function(
            "v15_finish_matrix_create_hardlink",
            0,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8,
            move |_| {
                fs::hard_link(&source, &hardlink)
                    .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
                Ok(1_i64)
            },
        )
        .expect("install post-commit hardlink injection function");
    let identity = v15_sql_literal(identity);
    ledger
        .connection
        .execute_batch(&format!(
            "CREATE TEMP TRIGGER v15_finish_matrix_postcommit_hardlink
             AFTER INSERT ON {table}
             WHEN NEW.{identity_column} = '{identity}'
             BEGIN
                 SELECT v15_finish_matrix_create_hardlink();
             END;"
        ))
        .expect("install post-commit hardlink injection trigger");
}

#[cfg(unix)]
fn v15_remove_postcommit_hardlink_fault(ledger: &EventLedger) {
    ledger
        .connection
        .execute_batch("DROP TRIGGER v15_finish_matrix_postcommit_hardlink;")
        .expect("remove post-commit hardlink injection trigger");
    ledger
        .connection
        .remove_function("v15_finish_matrix_create_hardlink", 0)
        .expect("remove post-commit hardlink injection function");
}

fn v15_assert_statement_cut_rolls_back<T>(
    ledger: &mut EventLedger,
    table: &str,
    identity_column: &str,
    identity: &str,
    baseline: [i64; 12],
    operation: impl FnOnce(&mut EventLedger) -> Result<T, LedgerError>,
) {
    v15_install_statement_cut(ledger, table, identity_column, identity);
    assert!(operation(ledger).is_err(), "injected statement cut must fail");
    v15_remove_statement_cut(ledger);
    assert_eq!(
        v15_finish_matrix_counts(ledger),
        baseline,
        "statement cut after {table}.{identity_column} must roll back every durable row"
    );
}

fn v15_assert_crossed_text_identity_rejected(
    ledger: &EventLedger,
    table: &str,
    identity_column: &str,
    key_column: &str,
    key: &str,
    crossed: &str,
    readback: impl Fn(&EventLedger) -> Result<(), LedgerError>,
) {
    let original: String = ledger
        .connection
        .query_row(
            &format!("SELECT {identity_column} FROM {table} WHERE {key_column} = ?1"),
            [key],
            |row| row.get(0),
        )
        .expect("load original indexed text identity");
    ledger
        .connection
        .execute(
            &format!("UPDATE {table} SET {identity_column} = ?1 WHERE {key_column} = ?2"),
            params![crossed, key],
        )
        .expect("cross one indexed text identity through corruption bypass");
    assert!(
        readback(ledger).is_err(),
        "crossed {table}.{identity_column} must fail canonical readback"
    );
    ledger
        .connection
        .execute(
            &format!("UPDATE {table} SET {identity_column} = ?1 WHERE {key_column} = ?2"),
            params![original, key],
        )
        .expect("restore original indexed text identity");
    readback(ledger).expect("restored text identity must reopen exactly");
}

fn v15_assert_crossed_integer_identity_rejected(
    ledger: &EventLedger,
    table: &str,
    identity_column: &str,
    key_column: &str,
    key: &str,
    crossed: i64,
    readback: impl Fn(&EventLedger) -> Result<(), LedgerError>,
) {
    let original: i64 = ledger
        .connection
        .query_row(
            &format!("SELECT {identity_column} FROM {table} WHERE {key_column} = ?1"),
            [key],
            |row| row.get(0),
        )
        .expect("load original indexed integer identity");
    ledger
        .connection
        .execute(
            &format!("UPDATE {table} SET {identity_column} = ?1 WHERE {key_column} = ?2"),
            params![crossed, key],
        )
        .expect("cross one indexed integer identity through corruption bypass");
    assert!(
        readback(ledger).is_err(),
        "crossed {table}.{identity_column} must fail canonical readback"
    );
    ledger
        .connection
        .execute(
            &format!("UPDATE {table} SET {identity_column} = ?1 WHERE {key_column} = ?2"),
            params![original, key],
        )
        .expect("restore original indexed integer identity");
    readback(ledger).expect("restored integer identity must reopen exactly");
}

fn v15_assert_crossed_null_text_identity_rejected(
    ledger: &EventLedger,
    table: &str,
    identity_column: &str,
    key_column: &str,
    key: &str,
    crossed: &str,
    readback: impl Fn(&EventLedger) -> Result<(), LedgerError>,
) {
    let original: Option<String> = ledger
        .connection
        .query_row(
            &format!("SELECT {identity_column} FROM {table} WHERE {key_column} = ?1"),
            [key],
            |row| row.get(0),
        )
        .expect("load original nullable indexed identity");
    assert!(
        original.is_none(),
        "nullable corruption helper requires an originally absent identity"
    );
    ledger
        .connection
        .execute(
            &format!("UPDATE {table} SET {identity_column} = ?1 WHERE {key_column} = ?2"),
            params![crossed, key],
        )
        .expect("cross one absent indexed identity through corruption bypass");
    assert!(
        readback(ledger).is_err(),
        "crossed {table}.{identity_column} must fail canonical readback"
    );
    ledger
        .connection
        .execute(
            &format!("UPDATE {table} SET {identity_column} = NULL WHERE {key_column} = ?1"),
            [key],
        )
        .expect("restore absent indexed identity");
    readback(ledger).expect("restored absent identity must reopen exactly");
}

#[derive(Clone, Copy, Debug)]
enum V15KnownCleanupKind {
    Retryable,
    PermanentFailure,
    Blocked,
    Canceled,
}

impl V15KnownCleanupKind {
    const fn suffix(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::PermanentFailure => "permanent-failure",
            Self::Blocked => "blocked",
            Self::Canceled => "canceled",
        }
    }

    const fn resulting_state(self) -> TaskState {
        match self {
            Self::Retryable => TaskState::Ready,
            Self::PermanentFailure => TaskState::Failed,
            Self::Blocked => TaskState::Blocked,
            Self::Canceled => TaskState::Canceled,
        }
    }

    fn matches(self, disposition: &TaskAttemptDisposition) -> bool {
        matches!(
            (self, disposition),
            (Self::Retryable, TaskAttemptDisposition::Retryable(_))
                | (
                    Self::PermanentFailure,
                    TaskAttemptDisposition::PermanentFailure(_)
                )
                | (Self::Blocked, TaskAttemptDisposition::Blocked(_))
                | (Self::Canceled, TaskAttemptDisposition::Canceled(_))
        )
    }
}

struct V15KnownCleanupFixture {
    database: TestDatabase,
    ledger: EventLedger,
    launch: RunnerLaunchIntent,
    attempt: TaskAttempt,
    outcome: TaskAttemptKnownCleanupOutcome,
    metadata: TaskAttemptDispositionMetadata,
    transition: AgentEvent,
    terminal: RunnerCleanupTerminalRecord,
}

fn v15_known_cleanup_outcome(
    kind: V15KnownCleanupKind,
    launch: &RunnerLaunchIntent,
) -> TaskAttemptKnownCleanupOutcome {
    let suffix = kind.suffix();
    match kind {
        V15KnownCleanupKind::Retryable => TaskAttemptKnownCleanupOutcome::Retryable(
            crate::TaskAttemptRetryableCause::KnownWorkerExit {
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                evidence: crate::TaskAttemptEvidence::new(
                    format!("v15-finish-matrix-{suffix}-evidence"),
                    crate::TaskAttemptEvidenceKind::KnownWorkerExit,
                    format!("known worker exit evidence:{suffix}").into_bytes(),
                )
                .expect("construct known worker-exit evidence"),
            },
        ),
        V15KnownCleanupKind::PermanentFailure => {
            TaskAttemptKnownCleanupOutcome::PermanentFailure(
                crate::TaskAttemptPermanentFailureCause::PermanentContractViolation {
                    violation_id: format!("v15-finish-matrix-{suffix}-violation"),
                    evidence: crate::TaskAttemptEvidence::new(
                        format!("v15-finish-matrix-{suffix}-evidence"),
                        crate::TaskAttemptEvidenceKind::PermanentContractViolation,
                        format!("permanent contract evidence:{suffix}").into_bytes(),
                    )
                    .expect("construct permanent-failure evidence"),
                },
            )
        }
        V15KnownCleanupKind::Blocked => TaskAttemptKnownCleanupOutcome::Blocked(
            crate::TaskAttemptBlockedCause::AuthorityExpansionRequired {
                authority_request_id: format!("v15-finish-matrix-{suffix}-authority"),
                evidence: crate::TaskAttemptEvidence::new(
                    format!("v15-finish-matrix-{suffix}-evidence"),
                    crate::TaskAttemptEvidenceKind::AuthorityExpansionRequired,
                    format!("authority expansion evidence:{suffix}").into_bytes(),
                )
                .expect("construct blocked evidence"),
            },
        ),
        V15KnownCleanupKind::Canceled => TaskAttemptKnownCleanupOutcome::Canceled(
            crate::TaskAttemptCanceledCause {
                cancellation_id: format!("v15-finish-matrix-{suffix}-cancellation"),
                evidence: crate::TaskAttemptEvidence::new(
                    format!("v15-finish-matrix-{suffix}-evidence"),
                    crate::TaskAttemptEvidenceKind::OperatorCanceled,
                    format!("operator cancellation evidence:{suffix}").into_bytes(),
                )
                .expect("construct cancellation evidence"),
            },
        ),
    }
}

fn v15_prepare_known_cleanup_fixture(kind: V15KnownCleanupKind) -> V15KnownCleanupFixture {
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open known-cleanup matrix ledger");
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(
            &launch
                .worker_lease
                .as_ref()
                .expect("task-worker lease")
                .lease_id,
        )
        .expect("load known-cleanup matrix attempt");
    let outcome = v15_known_cleanup_outcome(kind, &launch);
    ledger
        .record_task_attempt_cleanup_outcome_authority(&attempt, &outcome, 1_200)
        .expect("record independent known-cleanup outcome authority");
    let suffix = kind.suffix();
    let terminal = cleanup_terminal_record(
        &ledger,
        &launch,
        &format!("v15-finish-matrix-{suffix}-cleanup"),
        1_300,
    );
    let metadata = TaskAttemptDispositionMetadata {
        contract_version: CONTRACT_VERSION,
        disposition_id: format!("v15-finish-matrix-{suffix}-disposition"),
        attempt: attempt.clone(),
        from_state: TaskState::Running,
        state_transition_event_id: format!("v15-finish-matrix-{suffix}-transition"),
        disposed_at_unix_ms: 1_350,
    };
    let resulting_state = format!("{:?}", kind.resulting_state());
    let transition = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: terminal.event.sequence + 1,
        event_id: metadata.state_transition_event_id.clone(),
        sprint_id: attempt.worker_lease.sprint_id.clone(),
        task_id: Some(attempt.worker_lease.task_id.clone()),
        worker_id: Some(attempt.worker_lease.worker_id.clone()),
        causation_id: Some(attempt.opening_event_id.clone()),
        correlation_id: format!("v15-finish-matrix-{suffix}-lifecycle"),
        policy_hash: Some(launch.policy_hash.clone()),
        occurred_at_unix_ms: metadata.disposed_at_unix_ms,
        payload: AgentEventKind::TaskStateChanged {
            from: "Running".into(),
            to: resulting_state,
        },
    };
    V15KnownCleanupFixture {
        database,
        ledger,
        launch,
        attempt,
        outcome,
        metadata,
        transition,
        terminal,
    }
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)] // Four semantic results share five crash cuts, commit ambiguity, and exact replay.
fn v15_known_cleanup_dispositions_are_crash_binary_and_commit_recoverable() {
    for kind in [
        V15KnownCleanupKind::Retryable,
        V15KnownCleanupKind::PermanentFailure,
        V15KnownCleanupKind::Blocked,
        V15KnownCleanupKind::Canceled,
    ] {
        let mut fixture = v15_prepare_known_cleanup_fixture(kind);
        let baseline = v15_finish_matrix_counts(&fixture.ledger);
        let callback_count = Arc::new(AtomicU64::new(0));
        let cuts = [
            (
                "task_attempt_cleanup_result_coverage",
                "disposition_id",
                fixture.metadata.disposition_id.clone(),
            ),
            (
                "agent_events",
                "event_id",
                fixture.terminal.event.event_id.clone(),
            ),
            (
                "task_attempt_dispositions",
                "disposition_id",
                fixture.metadata.disposition_id.clone(),
            ),
            (
                "worker_lease_releases",
                "lease_id",
                fixture.attempt.worker_lease.lease_id.clone(),
            ),
            (
                "agent_events",
                "event_id",
                fixture.transition.event_id.clone(),
            ),
        ];
        for (table, identity_column, identity) in cuts {
            let metadata = fixture.metadata.clone();
            let outcome = fixture.outcome.clone();
            let transition = fixture.transition.clone();
            let terminal = fixture.terminal.clone();
            let callback_count = Arc::clone(&callback_count);
            let release_id = format!("v15-finish-matrix-{}-release", kind.suffix());
            v15_assert_statement_cut_rolls_back(
                &mut fixture.ledger,
                table,
                identity_column,
                &identity,
                baseline,
                move |ledger| {
                    ledger.with_task_attempt_cleanup_disposition_exclusion(
                        &metadata,
                        &outcome,
                        &release_id,
                        &transition,
                        move |_| {
                            callback_count.fetch_add(1, Ordering::SeqCst);
                            Ok(terminal)
                        },
                    )
                },
            );
            assert_eq!(
                fixture
                    .ledger
                    .load_active_worker_leases(&fixture.launch.sprint_id)
                    .expect("cut preserves active lease"),
                vec![fixture.attempt.worker_lease.clone()]
            );
        }

        let hardlink = fixture
            .database
            .directory
            .join(format!("v15-known-{}-postcommit.sqlite3", kind.suffix()));
        let source = fixture.database.path.clone();
        let metadata = fixture.metadata.clone();
        let outcome = fixture.outcome.clone();
        let transition = fixture.transition.clone();
        let terminal = fixture.terminal.clone();
        let cleanup_effect_id = terminal.observation.effect_id.clone();
        let callback = Arc::clone(&callback_count);
        let release_id = format!("v15-finish-matrix-{}-release", kind.suffix());
        let injected_hardlink = hardlink.clone();
        assert!(matches!(
            fixture
                .ledger
                .with_task_attempt_cleanup_disposition_exclusion(
                    &metadata,
                    &outcome,
                    &release_id,
                    &transition,
                    move |_| {
                        callback.fetch_add(1, Ordering::SeqCst);
                        fs::hard_link(&source, &injected_hardlink)
                            .expect("inject known-cleanup post-commit hardlink fault");
                        Ok(terminal)
                    },
                ),
            Err(LedgerError::PostCommitStateUncertain {
                operation: "task attempt cleanup disposition",
                recovery_id,
                ..
            }) if recovery_id == cleanup_effect_id
        ));
        fs::remove_file(&hardlink).expect("remove known-cleanup hardlink fault");
        assert_eq!(callback_count.load(Ordering::SeqCst), 6);

        let stored = fixture
            .ledger
            .with_task_attempt_cleanup_disposition_exclusion(
                &fixture.metadata,
                &fixture.outcome,
                &release_id,
                &fixture.transition,
                |_| panic!("exact committed replay must not invoke native cleanup"),
            )
            .expect("recover exact committed known-cleanup disposition");
        assert!(kind.matches(&stored));
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_disposition(&fixture.metadata.disposition_id)
                .expect("read exact recovered known-cleanup disposition"),
            stored
        );
        let committed = v15_finish_matrix_counts(&fixture.ledger);
        assert_eq!(committed[0], baseline[0] + 1);
        assert_eq!(committed[1], baseline[1] + 1);
        assert_eq!(committed[3], baseline[3] + 1);
        assert_eq!(committed[4], baseline[4] + 1);
        assert_eq!(committed[6], baseline[6] + 1);
        assert_eq!(committed[7], baseline[7] + 1);
        assert_eq!(committed[8], baseline[8] + 1);
        assert_eq!(committed[10], baseline[10] + 2);
        assert!(
            fixture
                .ledger
                .load_active_worker_leases(&fixture.launch.sprint_id)
                .expect("recovered cleanup released exact lease")
                .is_empty()
        );
        drop(fixture.ledger);
        let reopened = EventLedger::open_read_only(&fixture.database.path)
            .expect("reopen known-cleanup finish matrix");
        assert_eq!(v15_finish_matrix_counts(&reopened), committed);
        assert_eq!(
            reopened
                .load_task_attempt_disposition(&fixture.metadata.disposition_id)
                .expect("reopen exact known-cleanup disposition"),
            stored
        );
    }
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)] // Coverage, receipt, both events, disposition, commit ambiguity, replay, and reopen form one proof.
fn v15_integrated_disposition_is_crash_binary_and_commit_recoverable() {
    let database = TestDatabase::new();
    let (mut ledger, pending) = prepare_migrated_v16_pending_task_integration(&database);
    let (disposition, transition) = pending_integration_disposition(&pending);
    let disposition_id = disposition.metadata().disposition_id.clone();
    let baseline = v15_finish_matrix_counts(&ledger);
    let cuts = [
        (
            "task_attempt_integrated_result_coverage",
            "disposition_id",
            disposition_id.clone(),
        ),
        (
            "task_integration_receipts",
            "receipt_id",
            pending.evidence.receipt.receipt_id.clone(),
        ),
        (
            "agent_events",
            "event_id",
            pending.terminal.event_id.clone(),
        ),
        (
            "task_attempt_dispositions",
            "disposition_id",
            disposition_id.clone(),
        ),
        (
            "agent_events",
            "event_id",
            transition.event_id.clone(),
        ),
    ];
    for (table, identity_column, identity) in cuts {
        let disposition = disposition.clone();
        let observation = pending.observation.clone();
        let terminal = pending.terminal.clone();
        let evidence = pending.evidence.clone();
        let transition = transition.clone();
        v15_assert_statement_cut_rolls_back(
            &mut ledger,
            table,
            identity_column,
            &identity,
            baseline,
            move |ledger| {
                ledger.integrate_task_attempt(
                    &disposition,
                    &observation,
                    &terminal,
                    &evidence,
                    &transition,
                )
            },
        );
        assert!(
            ledger
                .load_effect(&pending.observation.effect_id)
                .expect("cut preserves pending integration effect")
                .observation
                .is_none()
        );
    }

    let hardlink = database
        .directory
        .join("v15-integrated-postcommit-hardlink.sqlite3");
    fs::hard_link(&database.path, &hardlink).expect("inject integration hardening fault");
    let effect_id = pending.observation.effect_id.clone();
    assert!(matches!(
        ledger.integrate_task_attempt(
            &disposition,
            &pending.observation,
            &pending.terminal,
            &pending.evidence,
            &transition,
        ),
        Err(LedgerError::PostCommitStateUncertain {
            operation: "task attempt integration disposition",
            recovery_id,
            ..
        }) if recovery_id == effect_id
    ));
    fs::remove_file(&hardlink).expect("remove integration hardening fault");

    assert_eq!(
        ledger
            .integrate_task_attempt(
                &disposition,
                &pending.observation,
                &pending.terminal,
                &pending.evidence,
                &transition,
            )
            .expect("recover exact committed Integrated disposition"),
        disposition
    );
    assert_eq!(
        ledger
            .load_task_attempt_disposition(&disposition_id)
            .expect("read exact recovered Integrated disposition"),
        disposition
    );
    let committed = v15_finish_matrix_counts(&ledger);
    assert_eq!(committed[0], baseline[0] + 1);
    assert_eq!(committed[2], baseline[2] + 1);
    assert_eq!(committed[5], baseline[5] + 1);
    assert_eq!(committed[6], baseline[6] + 1);
    assert_eq!(committed[7], baseline[7] + 1);
    assert_eq!(committed[8], baseline[8] + 1);
    assert_eq!(committed[10], baseline[10] + 2);
    assert_eq!(
        ledger
            .load_active_worker_leases(&pending.observation.sprint_id)
            .expect("Integrated attempt remains cleanup-held"),
        vec![pending.candidate.attempt.worker_lease.clone()]
    );
    drop(ledger);

    let reopened =
        EventLedger::open_read_only(&database.path).expect("reopen Integrated finish matrix");
    assert_eq!(v15_finish_matrix_counts(&reopened), committed);
    assert_eq!(
        reopened
            .load_task_attempt_disposition(&disposition_id)
            .expect("reopen exact Integrated disposition"),
        disposition
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Six authority cuts plus success, replay, callback cardinality, and reopen prove crash binary cleanup.
fn v15_unknown_cleaned_disposition_is_crash_binary_at_every_authority_cut() {
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open UnknownCleaned matrix ledger");
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(
            &launch
                .worker_lease
                .as_ref()
                .expect("UnknownCleaned task-worker lease")
                .lease_id,
        )
        .expect("load UnknownCleaned matrix attempt");
    let (intent, proposal, permit) =
        persist_command_domain_intent(&mut ledger, &launch, "finish-matrix-unknown", 1_200);
    let observation = persist_command_domain_observation(
        &mut ledger,
        &intent,
        &proposal,
        permit,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_250,
    );
    let unknown = crate::TaskAttemptUnknownEvidence {
        effect_id: intent.effect_id.clone(),
        observation_id: observation.observation_id.clone(),
        evidence: crate::TaskAttemptEvidence::new(
            "v15-finish-matrix-unknown-source".into(),
            crate::TaskAttemptEvidenceKind::UnknownTerminalEffect,
            EFFECT_EVIDENCE_BYTES.to_vec(),
        )
        .expect("construct UnknownCleaned source evidence"),
    };
    let terminal = cleanup_terminal_record(
        &ledger,
        &launch,
        "v15-finish-matrix-unknown-cleanup",
        1_300,
    );
    let (metadata, mut transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "v15-finish-matrix-unknown-cleaned-disposition",
        "v15-finish-matrix-unknown-cleaned-transition",
        1_350,
    );
    transition.sequence = terminal.event.sequence + 1;
    let marker = v15_unknown_marker(&metadata);
    let release_id = "v15-finish-matrix-unknown-cleaned-release";
    let baseline = v15_finish_matrix_counts(&ledger);
    let callback_count = Arc::new(AtomicU64::new(0));
    let cuts = [
        (
            "task_attempt_cleanup_result_coverage",
            "disposition_id",
            metadata.disposition_id.clone(),
        ),
        (
            "agent_events",
            "event_id",
            terminal.event.event_id.clone(),
        ),
        (
            "task_attempt_dispositions",
            "disposition_id",
            metadata.disposition_id.clone(),
        ),
        (
            "worker_lease_releases",
            "lease_id",
            attempt.worker_lease.lease_id.clone(),
        ),
        (
            "sprint_unknown_terminalization_pending",
            "marker_id",
            marker.marker_id.clone(),
        ),
        (
            "agent_events",
            "event_id",
            transition.event_id.clone(),
        ),
    ];
    for (table, identity_column, identity) in cuts {
        let metadata = metadata.clone();
        let unknown = unknown.clone();
        let marker = marker.clone();
        let transition = transition.clone();
        let terminal = terminal.clone();
        let callback_count = Arc::clone(&callback_count);
        v15_assert_statement_cut_rolls_back(
            &mut ledger,
            table,
            identity_column,
            &identity,
            baseline,
            move |ledger| {
                ledger.with_task_attempt_unknown_cleaned_disposition_exclusion(
                    &metadata,
                    &unknown,
                    release_id,
                    &marker,
                    &transition,
                    move |_| {
                        callback_count.fetch_add(1, Ordering::SeqCst);
                        Ok(terminal)
                    },
                )
            },
        );
        assert_eq!(
            ledger
                .load_active_worker_leases(&attempt.worker_lease.sprint_id)
                .expect("UnknownCleaned cut preserves active lease"),
            vec![attempt.worker_lease.clone()]
        );
    }

    let callback = Arc::clone(&callback_count);
    let stored = ledger
        .with_task_attempt_unknown_cleaned_disposition_exclusion(
            &metadata,
            &unknown,
            release_id,
            &marker,
            &transition,
            move |_| {
                callback.fetch_add(1, Ordering::SeqCst);
                Ok(terminal)
            },
        )
        .expect("commit UnknownCleaned after every cut rolled back");
    assert!(matches!(stored, TaskAttemptDisposition::UnknownCleaned(_)));
    assert_eq!(callback_count.load(Ordering::SeqCst), 7);
    assert_eq!(
        ledger
            .with_task_attempt_unknown_cleaned_disposition_exclusion(
                &metadata,
                &unknown,
                release_id,
                &marker,
                &transition,
                |_| panic!("exact UnknownCleaned replay must not invoke cleanup"),
            )
            .expect("replay exact UnknownCleaned disposition"),
        stored
    );
    let committed = v15_finish_matrix_counts(&ledger);
    assert_eq!(committed[0], baseline[0] + 1);
    assert_eq!(committed[1], baseline[1] + 1);
    assert_eq!(committed[3], baseline[3] + 1);
    assert_eq!(committed[4], baseline[4] + 1);
    assert_eq!(committed[6], baseline[6] + 1);
    assert_eq!(committed[7], baseline[7] + 1);
    assert_eq!(committed[8], baseline[8] + 1);
    assert_eq!(committed[9], baseline[9] + 1);
    assert_eq!(committed[10], baseline[10] + 2);
    assert!(
        ledger
            .load_active_worker_leases(&attempt.worker_lease.sprint_id)
            .expect("UnknownCleaned releases exact lease")
            .is_empty()
    );
    drop(ledger);

    let reopened =
        EventLedger::open_read_only(&database.path).expect("reopen UnknownCleaned finish matrix");
    assert_eq!(v15_finish_matrix_counts(&reopened), committed);
    assert_eq!(
        reopened
            .load_task_attempt_disposition(&metadata.disposition_id)
            .expect("reopen exact UnknownCleaned disposition"),
        stored
    );
    drop(reopened);

    let corrupted = EventLedger::open(&database.path)
        .expect("open isolated UnknownCleaned pointer-corruption matrix");
    corrupted
        .connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TRIGGER task_attempt_dispositions_no_update;",
        )
        .expect("open UnknownCleaned pointer-corruption bypass");
    let disposition_id = metadata.disposition_id.clone();
    let readback = |ledger: &EventLedger| {
        ledger
            .load_task_attempt_disposition(&disposition_id)
            .map(|_| ())
    };
    for (column, crossed) in [
        ("cause_effect_id", "crossed-unknown-effect"),
        ("cause_observation_id", "crossed-unknown-observation"),
        ("cleanup_receipt_id", "crossed-unknown-cleanup"),
        ("release_id", "crossed-unknown-release"),
    ] {
        v15_assert_crossed_text_identity_rejected(
            &corrupted,
            "task_attempt_dispositions",
            column,
            "disposition_id",
            &disposition_id,
            crossed,
            readback,
        );
    }
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)] // Disposition, marker, event, commit ambiguity, held lease, replay, and reopen form one proof.
fn v15_unknown_quarantine_is_crash_binary_and_commit_recoverable() {
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open quarantine matrix ledger");
    let (_policy, launch, _session) = prepare_command_domain_session(&mut ledger);
    let attempt = ledger
        .load_task_attempt(
            &launch
                .worker_lease
                .as_ref()
                .expect("quarantine task-worker lease")
                .lease_id,
        )
        .expect("load quarantine matrix attempt");
    let (intent, proposal, permit) =
        persist_command_domain_intent(&mut ledger, &launch, "finish-matrix-uncertain", 1_200);
    let observation = persist_command_domain_observation(
        &mut ledger,
        &intent,
        &proposal,
        permit,
        EffectOutcome::Unknown {
            evidence_digest: effect_evidence_digest(),
        },
        1_250,
    );
    let (metadata, transition) = v15_unknown_metadata(
        &ledger,
        &attempt,
        "v15-finish-matrix-quarantine-disposition",
        "v15-finish-matrix-quarantine-transition",
        1_300,
    );
    let marker = v15_unknown_marker(&metadata);
    let uncertain = crate::TaskAttemptUncertainEvidence {
        uncertainty_id: "v15-finish-matrix-quarantine-authority".into(),
        authority_reference_ids: vec![observation.observation_id],
        evidence: crate::TaskAttemptEvidence::new(
            "v15-finish-matrix-quarantine-evidence".into(),
            crate::TaskAttemptEvidenceKind::UncertainAuthority,
            b"native survival remains uncertain at the finish boundary".to_vec(),
        )
        .expect("construct quarantine uncertainty evidence"),
    };
    let baseline = v15_finish_matrix_counts(&ledger);
    let cuts = [
        (
            "task_attempt_dispositions",
            "disposition_id",
            metadata.disposition_id.clone(),
        ),
        (
            "sprint_unknown_terminalization_pending",
            "marker_id",
            marker.marker_id.clone(),
        ),
        (
            "agent_events",
            "event_id",
            transition.event_id.clone(),
        ),
    ];
    for (table, identity_column, identity) in cuts {
        let metadata = metadata.clone();
        let uncertain = uncertain.clone();
        let marker = marker.clone();
        let transition = transition.clone();
        v15_assert_statement_cut_rolls_back(
            &mut ledger,
            table,
            identity_column,
            &identity,
            baseline,
            move |ledger| {
                ledger.quarantine_task_attempt_unknown(
                    &metadata,
                    &uncertain,
                    &marker,
                    &transition,
                )
            },
        );
        assert_eq!(
            ledger
                .load_active_worker_leases(&attempt.worker_lease.sprint_id)
                .expect("quarantine cut preserves held lease"),
            vec![attempt.worker_lease.clone()]
        );
    }

    let hardlink = database
        .directory
        .join("v15-quarantine-postcommit-hardlink.sqlite3");
    v15_install_postcommit_hardlink_fault(
        &ledger,
        "agent_events",
        "event_id",
        &transition.event_id,
        &hardlink,
    );
    assert!(matches!(
        ledger.quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition),
        Err(LedgerError::PostCommitStateUncertain {
            operation: "task attempt unknown quarantine",
            recovery_id,
            ..
        }) if recovery_id == attempt.attempt_id
    ));
    v15_remove_postcommit_hardlink_fault(&ledger);
    fs::remove_file(&hardlink).expect("remove quarantine hardlink fault");

    let stored = ledger
        .quarantine_task_attempt_unknown(&metadata, &uncertain, &marker, &transition)
        .expect("recover exact committed quarantine disposition");
    assert!(matches!(
        stored,
        TaskAttemptDisposition::UnknownQuarantined(_)
    ));
    let committed = v15_finish_matrix_counts(&ledger);
    assert_eq!(committed[0], baseline[0] + 1);
    assert_eq!(committed[9], baseline[9] + 1);
    assert_eq!(committed[10], baseline[10] + 1);
    assert_eq!(
        ledger
            .load_active_worker_leases(&attempt.worker_lease.sprint_id)
            .expect("quarantine keeps exact lease held"),
        vec![attempt.worker_lease.clone()]
    );
    drop(ledger);

    let reopened =
        EventLedger::open_read_only(&database.path).expect("reopen quarantine finish matrix");
    assert_eq!(v15_finish_matrix_counts(&reopened), committed);
    assert_eq!(
        reopened
            .load_task_attempt_disposition(&metadata.disposition_id)
            .expect("reopen exact quarantine disposition"),
        stored
    );
    assert_eq!(
        reopened
            .load_active_worker_leases(&attempt.worker_lease.sprint_id)
            .expect("reopen held quarantine lease"),
        vec![attempt.worker_lease]
    );
    drop(reopened);

    let corrupted =
        EventLedger::open(&database.path).expect("open isolated quarantine identity matrix");
    corrupted
        .connection
        .execute_batch("DROP TRIGGER task_attempt_dispositions_no_update;")
        .expect("open quarantine identity corruption bypass");
    let disposition_id = metadata.disposition_id.clone();
    let readback = |ledger: &EventLedger| {
        ledger
            .load_task_attempt_disposition(&disposition_id)
            .map(|_| ())
    };
    v15_assert_crossed_text_identity_rejected(
        &corrupted,
        "task_attempt_dispositions",
        "uncertainty_id",
        "disposition_id",
        &disposition_id,
        "crossed-uncertainty-authority",
        readback,
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Every requested identity dimension is crossed alone and restored before the next readback.
fn v15_disposition_readback_rejects_the_complete_crossed_identity_matrix() {
    let mut cleanup = v15_prepare_known_cleanup_fixture(V15KnownCleanupKind::Retryable);
    let cleanup_disposition = cleanup
        .ledger
        .with_task_attempt_cleanup_disposition_exclusion(
            &cleanup.metadata,
            &cleanup.outcome,
            "v15-finish-matrix-identity-release",
            &cleanup.transition,
            |_| Ok(cleanup.terminal.clone()),
        )
        .expect("persist valid cleanup disposition for identity matrix");
    let cleanup_baseline = v15_finish_matrix_counts(&cleanup.ledger);
    let disposition_id = cleanup.metadata.disposition_id.clone();
    let cleanup_receipt_id = cleanup.terminal.evidence.receipt.receipt_id.clone();
    let lease_id = cleanup.attempt.worker_lease.lease_id.clone();
    cleanup
        .ledger
        .connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TRIGGER task_attempt_dispositions_no_update;
             DROP TRIGGER worker_cleanup_receipts_no_update;
             DROP TRIGGER worker_lease_releases_no_update;",
        )
        .expect("open isolated cleanup identity corruption matrix");
    let cleanup_readback = |ledger: &EventLedger| {
        ledger
            .load_task_attempt_disposition(&disposition_id)
            .map(|_| ())
    };
    for (column, crossed) in [
        ("attempt_id", "crossed-attempt"),
        ("worker_lease_id", "crossed-lease"),
        ("task_id", "crossed-task"),
        ("worker_id", "crossed-worker"),
        ("transition_event_id", "crossed-transition"),
        ("from_state", "Candidate"),
        ("disposition_kind", "AttemptsExhausted"),
        ("cause_kind", "LaunchRefusedBeforeNativeEffect"),
        ("cause_launch_id", "crossed-cause-launch"),
        ("cause_session_id", "crossed-cause-session"),
        ("cause_authority_id", "crossed-cause-authority"),
        ("cleanup_receipt_id", "crossed-disposition-cleanup"),
        ("release_id", "crossed-disposition-release"),
        ("evidence_id", "crossed-disposition-evidence"),
        ("evidence_kind", "OperatorCanceled"),
        ("evidence_digest", "crossed-disposition-digest"),
    ] {
        v15_assert_crossed_text_identity_rejected(
            &cleanup.ledger,
            "task_attempt_dispositions",
            column,
            "disposition_id",
            &disposition_id,
            crossed,
            cleanup_readback,
        );
    }
    v15_assert_crossed_integer_identity_rejected(
        &cleanup.ledger,
        "task_attempt_dispositions",
        "lease_epoch",
        "disposition_id",
        &disposition_id,
        99,
        cleanup_readback,
    );
    for column in ["cause_formal_check_id", "cause_candidate_boundary_id"] {
        v15_assert_crossed_null_text_identity_rejected(
            &cleanup.ledger,
            "task_attempt_dispositions",
            column,
            "disposition_id",
            &disposition_id,
            "crossed-absent-cause-pointer",
            cleanup_readback,
        );
    }
    for (column, crossed) in [
        ("launch_id", "crossed-launch"),
        ("session_id", "crossed-session"),
        ("effect_id", "crossed-effect"),
    ] {
        v15_assert_crossed_text_identity_rejected(
            &cleanup.ledger,
            "worker_cleanup_receipts",
            column,
            "receipt_id",
            &cleanup_receipt_id,
            crossed,
            cleanup_readback,
        );
    }
    v15_assert_crossed_text_identity_rejected(
        &cleanup.ledger,
        "worker_lease_releases",
        "cleanup_receipt_id",
        "lease_id",
        &lease_id,
        "crossed-cleanup-receipt",
        cleanup_readback,
    );
    cleanup
        .ledger
        .connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("restore cleanup identity foreign keys");
    assert_eq!(v15_finish_matrix_counts(&cleanup.ledger), cleanup_baseline);
    assert_eq!(
        cleanup
            .ledger
            .load_task_attempt_disposition(&disposition_id)
            .expect("cleanup identity matrix restores exact disposition"),
        cleanup_disposition
    );

    let integration_database = TestDatabase::new();
    let (mut integration_ledger, pending) =
        prepare_migrated_v16_pending_task_integration(&integration_database);
    let (integrated, transition) = pending_integration_disposition(&pending);
    integration_ledger
        .integrate_task_attempt(
            &integrated,
            &pending.observation,
            &pending.terminal,
            &pending.evidence,
            &transition,
        )
        .expect("persist valid Integrated disposition for identity matrix");
    let integration_baseline = v15_finish_matrix_counts(&integration_ledger);
    let integrated_id = integrated.metadata().disposition_id.clone();
    integration_ledger
        .connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TRIGGER task_attempt_dispositions_no_update;
             DROP TRIGGER task_attempt_integrated_result_coverage_no_update;",
        )
        .expect("open isolated integration identity corruption matrix");
    let integrated_readback = |ledger: &EventLedger| {
        ledger
            .load_task_attempt_disposition(&integrated_id)
            .map(|_| ())
    };
    v15_assert_crossed_text_identity_rejected(
        &integration_ledger,
        "task_attempt_dispositions",
        "candidate_boundary_id",
        "disposition_id",
        &integrated_id,
        "crossed-candidate-boundary",
        integrated_readback,
    );
    v15_assert_crossed_text_identity_rejected(
        &integration_ledger,
        "task_attempt_dispositions",
        "integration_receipt_id",
        "disposition_id",
        &integrated_id,
        "crossed-integration-receipt",
        integrated_readback,
    );
    v15_assert_crossed_text_identity_rejected(
        &integration_ledger,
        "task_attempt_integrated_result_coverage",
        "admission_id",
        "disposition_id",
        &integrated_id,
        "crossed-integration-admission",
        integrated_readback,
    );
    integration_ledger
        .connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("restore integration identity foreign keys");
    assert_eq!(
        v15_finish_matrix_counts(&integration_ledger),
        integration_baseline
    );
    assert_eq!(
        integration_ledger
            .load_task_attempt_disposition(&integrated_id)
            .expect("integration identity matrix restores exact disposition"),
        integrated
    );

    let (_never_launched_database, mut never_launched_ledger, ready) =
        v15_finish_prepare_ready_sprint(2);
    let lease = v15_finish_lease(1, "worker-never-launched-identity", 1_100);
    let (attempt, _) = v15_finish_acquire(
        &mut never_launched_ledger,
        &lease,
        "never-launched-identity",
        &ready.event_id,
    );
    let request = v15_finish_no_launch_request(
        &never_launched_ledger,
        &attempt,
        "identity",
        TaskState::Ready,
        1_150,
    );
    let never_launched =
        v15_finish_close_no_launch(&mut never_launched_ledger, &request);
    let never_launched_id = request.metadata.disposition_id.clone();
    never_launched_ledger
        .connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TRIGGER task_attempt_dispositions_no_update;",
        )
        .expect("open isolated never-launched release-pointer corruption matrix");
    let never_launched_readback = |ledger: &EventLedger| {
        ledger
            .load_task_attempt_disposition(&never_launched_id)
            .map(|_| ())
    };
    for (column, crossed) in [
        (
            "never_launched_release_id",
            "crossed-never-launched-release",
        ),
        ("release_id", "crossed-release"),
    ] {
        v15_assert_crossed_text_identity_rejected(
            &never_launched_ledger,
            "task_attempt_dispositions",
            column,
            "disposition_id",
            &never_launched_id,
            crossed,
            never_launched_readback,
        );
    }
    never_launched_ledger
        .connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("restore never-launched identity foreign keys");
    assert_eq!(
        never_launched_ledger
            .load_task_attempt_disposition(&never_launched_id)
            .expect("never-launched identity matrix restores exact disposition"),
        never_launched
    );
}

#[test]
#[allow(clippy::too_many_lines)] // One corruption must independently poison all three public projections, then restore exactly.
fn v15_crossed_integrated_receipt_poison_rejects_disposition_history_and_recovery() {
    let database = TestDatabase::new();
    let (mut ledger, pending) = prepare_migrated_v16_pending_task_integration(&database);
    let (integrated, transition) = pending_integration_disposition(&pending);
    ledger
        .integrate_task_attempt(
            &integrated,
            &pending.observation,
            &pending.terminal,
            &pending.evidence,
            &transition,
        )
        .expect("persist exact integrated pointer-poison fixture");
    let metadata = integrated.metadata();
    let lease = &metadata.attempt.worker_lease;
    let expected_history = ledger
        .load_task_attempt_history(&lease.sprint_id, &lease.task_id)
        .expect("load baseline integrated history");
    let expected_recovery = ledger
        .load_task_attempt_recovery_projection(
            &lease.sprint_id,
            &lease.task_id,
            &metadata.attempt.attempt_id,
        )
        .expect("load baseline integrated recovery projection");

    ledger
        .connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TRIGGER task_attempt_dispositions_no_update;",
        )
        .expect("open isolated integrated receipt-pointer corruption bypass");
    ledger
        .connection
        .execute(
            "UPDATE task_attempt_dispositions
             SET integration_receipt_id = 'crossed-integration-receipt'
             WHERE disposition_id = ?1",
            [&metadata.disposition_id],
        )
        .expect("cross only the normalized integration receipt pointer");
    assert!(
        ledger
            .load_task_attempt_disposition(&metadata.disposition_id)
            .is_err(),
        "crossed integration receipt pointer must poison direct disposition readback"
    );
    assert!(
        ledger
            .load_task_attempt_history(&lease.sprint_id, &lease.task_id)
            .is_err(),
        "crossed integration receipt pointer must poison canonical task history"
    );
    assert!(
        ledger
            .load_task_attempt_recovery_projection(
                &lease.sprint_id,
                &lease.task_id,
                &metadata.attempt.attempt_id,
            )
            .is_err(),
        "crossed integration receipt pointer must poison recovery projection"
    );

    ledger
        .connection
        .execute(
            "UPDATE task_attempt_dispositions SET integration_receipt_id = ?1
             WHERE disposition_id = ?2",
            params![
                pending.evidence.receipt.receipt_id,
                metadata.disposition_id,
            ],
        )
        .expect("restore exact integration receipt pointer");
    ledger
        .connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("restore integrated pointer foreign keys");
    assert_eq!(
        ledger
            .load_task_attempt_disposition(&metadata.disposition_id)
            .expect("restored integrated disposition reopens"),
        integrated
    );
    assert_eq!(
        ledger
            .load_task_attempt_history(&lease.sprint_id, &lease.task_id)
            .expect("restored integrated history reopens"),
        expected_history
    );
    assert_eq!(
        ledger
            .load_task_attempt_recovery_projection(
                &lease.sprint_id,
                &lease.task_id,
                &metadata.attempt.attempt_id,
            )
            .expect("restored integrated recovery projection reopens"),
        expected_recovery
    );
}
