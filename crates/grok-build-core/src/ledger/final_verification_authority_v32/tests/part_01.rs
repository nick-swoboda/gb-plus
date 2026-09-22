    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::{
        AcceptanceCriterion, ExecutionOrigin, PathScope, ProviderProfile,
        SPRINT_AUTHORITY_CONTRACT_VERSION_V2, SprintBudgetV2, TaskSpecV2, WorkerLease,
        WorkspaceGrant, WorkspaceNetworkPolicy, WorkspacePermissions,
    };

    use super::*;

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

    struct TestDatabase {
        path: PathBuf,
    }

    impl TestDatabase {
        fn new(label: &str) -> Self {
            let ordinal = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            Self {
                path: std::env::temp_dir().join(format!(
                    "grok-build-core-v32-{label}-{}-{ordinal}.sqlite3",
                    std::process::id()
                )),
            }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm", "-launch-cleanup.lock"] {
                let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = fs::remove_file(path);
            }
        }
    }

    fn digest(character: char) -> Digest {
        Digest::parse(character.to_string().repeat(64)).expect("valid digest")
    }

    fn task_source_projection_is_canonical(
        connection: &Connection,
        source: &crate::CurrentTaskDoneSourceReceiptV1,
        indexed_task_id: &str,
    ) -> i64 {
        connection
            .query_row(
                "SELECT grok_current_task_done_source_canonical_v32(
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                    ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
                 )",
                params![
                    source
                        .canonical_bytes()
                        .expect("encode exact TaskDone source"),
                    source
                        .canonical_digest()
                        .expect("digest exact TaskDone source")
                        .as_str(),
                    source.task_done_proof_id,
                    source.sprint_id,
                    indexed_task_id,
                    source.winning_attempt_id,
                    i64::from(source.winning_attempt_ordinal),
                    source.winning_lease_id,
                    i64::try_from(source.winning_lease_epoch)
                        .expect("test lease epoch fits SQLite"),
                    source.integration.integration_receipt_id(),
                    source.integration.sql_kind(),
                    source.integration.change_set_id(),
                    source.integration.empty_change_set_id(),
                    i64::from(source.integration.operation_count()),
                    source.input_snapshot.as_str(),
                    source.result_snapshot.as_str(),
                    source.zero_active_leases_proof_id,
                    i64::from(source.active_lease_count),
                    source.zero_replay_dispatch_authority_proof_id,
                    i64::from(source.replay_dispatch_authority_count),
                    i64::try_from(source.derived_at_unix_ms)
                        .expect("test derivation time fits SQLite"),
                ],
                |row| row.get(0),
            )
            .expect("evaluate TaskDone JSON/index parity UDF")
    }

    fn command() -> CommandSpec {
        CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into(), "--workspace".into()],
            working_directory: PathBuf::new(),
        }
    }

    fn current_pair(sprint_id: &str, cap: u8) -> (SprintSpecV2, TaskGraphV2) {
        let criteria = vec![
            AcceptanceCriterion {
                criterion_id: "automated".into(),
                description: "Automated verification succeeds".into(),
                kind: AcceptanceKind::Automated(command()),
            },
            AcceptanceCriterion {
                criterion_id: "human".into(),
                description: "Human accepts the exact rendered result".into(),
                kind: AcceptanceKind::HumanJudgment,
            },
        ];
        let mut tasks = vec![TaskSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            task_id: "ordinary".into(),
            purpose: TaskPurposeV2::Ordinary,
            goal: "Implement the objective".into(),
            dependencies: Vec::new(),
            path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
            acceptance_checks: vec!["automated".into(), "human".into()],
            base_snapshot: digest('b'),
            required: true,
        }];
        for slot_ordinal in 1..cap {
            let mut dependencies = vec!["ordinary".into()];
            if slot_ordinal > 1 {
                dependencies.push(format!("repair-{}", slot_ordinal - 1));
            }
            tasks.push(TaskSpecV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                task_id: format!("repair-{slot_ordinal}"),
                purpose: TaskPurposeV2::FinalVerificationRepairSlot { slot_ordinal },
                goal: format!("Repair verifier failure {slot_ordinal}"),
                dependencies,
                path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                acceptance_checks: vec!["automated".into(), "human".into()],
                base_snapshot: digest('b'),
                required: false,
            });
        }
        let graph_id = format!("graph-{sprint_id}");
        let mut graph = TaskGraphV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            graph_id: graph_id.clone(),
            sprint_id: sprint_id.into(),
            sprint_spec_digest: digest('0'),
            repair_slot_reserve_digest: digest('0'),
            tasks,
        };
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("repair reserve digest");
        let mut spec = SprintSpecV2 {
            sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
            sprint_id: sprint_id.into(),
            objective: "Ship exact current verification authority".into(),
            acceptance_criteria: criteria,
            provider: ProviderProfile {
                backend_id: "fake".into(),
                model_id: "deterministic".into(),
                execution_origin: ExecutionOrigin::HostIsolated,
            },
            budget: SprintBudgetV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                max_tasks: usize::from(cap) + 2,
                max_attempts_per_task: 2,
                max_final_verification_attempts: cap,
                max_tool_calls: 50,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: WorkspaceGrant {
                grant_id: format!("grant-{sprint_id}"),
                canonical_root: PathBuf::from("/work/project"),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                grant_hash: digest('a'),
            },
            base_snapshot: digest('b'),
            task_graph_id: graph_id,
            task_graph_payload_digest: graph.payload_digest().expect("graph payload digest"),
            repair_slot_reserve_digest: graph.repair_slot_reserve_digest.clone(),
        };
        graph.sprint_spec_digest = spec.canonical_digest().expect("sprint digest");
        // The graph payload deliberately excludes sprint_spec_digest, so the
        // reciprocal assignment above does not change the spec-bound payload.
        spec.task_graph_payload_digest = graph.payload_digest().expect("stable graph payload");
        graph
            .validate_for_sprint(&spec)
            .expect("valid current pair");
        (spec, graph)
    }

    fn two_required_task_pair(sprint_id: &str) -> (SprintSpecV2, TaskGraphV2) {
        let (mut spec, mut graph) = current_pair(sprint_id, 3);
        graph.tasks.insert(
            1,
            TaskSpecV2 {
                sprint_authority_version: SPRINT_AUTHORITY_CONTRACT_VERSION_V2,
                task_id: "ordinary-second".into(),
                purpose: TaskPurposeV2::Ordinary,
                goal: "Complete the second required slice".into(),
                dependencies: vec!["ordinary".into()],
                path_scopes: vec![PathScope::Relative(PathBuf::from("src/second"))],
                acceptance_checks: vec!["automated".into(), "human".into()],
                base_snapshot: digest('b'),
                required: true,
            },
        );
        for task in &mut graph.tasks {
            if matches!(
                task.purpose,
                TaskPurposeV2::FinalVerificationRepairSlot { .. }
            ) {
                task.dependencies.push("ordinary-second".into());
            }
        }
        graph.repair_slot_reserve_digest = graph
            .computed_repair_slot_reserve_digest()
            .expect("two-required repair reserve digest");
        spec.repair_slot_reserve_digest = graph.repair_slot_reserve_digest.clone();
        spec.task_graph_payload_digest =
            graph.payload_digest().expect("two-required graph payload");
        graph.sprint_spec_digest = spec.canonical_digest().expect("two-required sprint digest");
        spec.task_graph_payload_digest = graph
            .payload_digest()
            .expect("stable two-required graph payload");
        graph
            .validate_for_sprint(&spec)
            .expect("valid two-required current pair");
        (spec, graph)
    }

    fn task_set(
        sprint_id: &str,
        snapshot: char,
        repair: Option<(u8, char)>,
        recorded_at_unix_ms: u64,
    ) -> CompleteTaskDoneSetV1 {
        let ordinary_result = if repair.is_some() { 'c' } else { snapshot };
        let mut members = vec![CurrentTaskDoneMemberV1 {
            source_ordinal: 0,
            task_id: "ordinary".into(),
            task_done_proof_id: "task-done-ordinary".into(),
            integration_receipt_id: "integration-ordinary".into(),
            integration_evidence: CurrentTaskDoneIntegrationEvidenceV1::Changed,
            input_snapshot: digest('b'),
            result_snapshot: digest(ordinary_result),
        }];
        if let Some((slot, result)) = repair {
            members.push(CurrentTaskDoneMemberV1 {
                source_ordinal: 1,
                task_id: format!("repair-{slot}"),
                task_done_proof_id: format!("task-done-repair-{slot}"),
                integration_receipt_id: format!("integration-repair-{slot}"),
                integration_evidence: CurrentTaskDoneIntegrationEvidenceV1::Changed,
                input_snapshot: digest('c'),
                result_snapshot: digest(result),
            });
        }
        with_test_task_source_ids(CompleteTaskDoneSetV1 {
            set_version: CURRENT_SET_VERSION_V1,
            sprint_id: sprint_id.into(),
            snapshot_digest: digest(snapshot),
            members,
            recorded_at_unix_ms,
        })
    }

    fn verified_no_op_task_set(sprint_id: &str, recorded_at_unix_ms: u64) -> CompleteTaskDoneSetV1 {
        with_test_task_source_ids(CompleteTaskDoneSetV1 {
            set_version: CURRENT_SET_VERSION_V1,
            sprint_id: sprint_id.into(),
            snapshot_digest: digest('b'),
            members: vec![CurrentTaskDoneMemberV1 {
                source_ordinal: 0,
                task_id: "ordinary".into(),
                task_done_proof_id: "task-done-ordinary-no-op".into(),
                integration_receipt_id: "integration-ordinary-no-op".into(),
                integration_evidence: CurrentTaskDoneIntegrationEvidenceV1::VerifiedNoOp {
                    empty_change_set_id: "change-set-empty-ordinary".into(),
                },
                input_snapshot: digest('b'),
                result_snapshot: digest('b'),
            }],
            recorded_at_unix_ms,
        })
    }

    fn with_test_task_source_ids(mut set: CompleteTaskDoneSetV1) -> CompleteTaskDoneSetV1 {
        let (spec, graph) = current_pair(&set.sprint_id, 3);
        for member in &mut set.members {
            member.task_done_proof_id =
                super::super::current_task_done_source_v32::test_source_for_member(
                    &spec, &graph, member,
                )
                .expect("derive exact test TaskDone source")
                .task_done_proof_id;
        }
        set
    }

    fn criterion_set(
        sprint_id: &str,
        snapshot: char,
        _generation: u8,
        recorded_at_unix_ms: u64,
    ) -> CompleteCriterionEvidenceSetV1 {
        let (spec, _) = current_pair(sprint_id, 3);
        let receipts =
            super::super::current_criterion_evidence_v32::test_criterion_receipts_for_snapshot_v32(
                &spec,
                &digest(snapshot),
                recorded_at_unix_ms,
            )
            .expect("derive exact test criterion source receipts");
        CompleteCriterionEvidenceSetV1 {
            set_version: CURRENT_SET_VERSION_V1,
            sprint_id: sprint_id.into(),
            snapshot_digest: digest(snapshot),
            members: vec![
                CurrentCriterionEvidenceMemberV1 {
                    criterion_ordinal: 0,
                    criterion_id: "automated".into(),
                    evidence_receipt_id: receipts[0].receipt_id().to_owned(),
                    evidence_kind: CurrentCriterionEvidenceKindV1::Verified,
                    snapshot_digest: digest(snapshot),
                },
                CurrentCriterionEvidenceMemberV1 {
                    criterion_ordinal: 1,
                    criterion_id: "human".into(),
                    evidence_receipt_id: receipts[1].receipt_id().to_owned(),
                    evidence_kind: CurrentCriterionEvidenceKindV1::AcceptedByYou,
                    snapshot_digest: digest(snapshot),
                },
            ],
            recorded_at_unix_ms,
        }
    }

    fn admission_request(
        sprint_id: &str,
        request_id: &str,
        task_done_set: CompleteTaskDoneSetV1,
        criterion_evidence_set: CompleteCriterionEvidenceSetV1,
        admitted_at_unix_ms: u64,
    ) -> CurrentFinalVerificationAdmissionRequestV1 {
        CurrentFinalVerificationAdmissionRequestV1 {
            request_id: request_id.into(),
            sprint_id: sprint_id.into(),
            task_done_set,
            criterion_evidence_set,
            final_verification_check: command(),
            execution_policy_digest: digest('e'),
            coordinator_instance_id: "coordinator-1".into(),
            admitted_at_unix_ms,
        }
    }

    fn clean_capture(
        attempt: &FinalVerificationAttemptAuthorityV1,
        closure_id: &str,
        termination: CurrentFinalVerificationTerminationV1,
        terminal_at_unix_ms: u64,
    ) -> CurrentFinalVerificationCaptureClosureV1 {
        CurrentFinalVerificationCaptureClosureV1 {
            closure_version: CURRENT_OUTCOME_VERSION_V1,
            closure_id: closure_id.into(),
            sprint_id: attempt.sprint_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            termination,
            output_custody: CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                publication_receipt_id: format!("publication-{closure_id}"),
            },
            runner_cleanup_proof_id: Some(format!("runner-cleanup-{closure_id}")),
            command_domain_cleanup_proof_id: Some(format!("domain-cleanup-{closure_id}")),
            terminal_at_unix_ms,
        }
    }

    fn create_current_ledger(
        label: &str,
        sprint_id: &str,
        cap: u8,
    ) -> (TestDatabase, EventLedger, SprintSpecV2, TaskGraphV2) {
        let database = TestDatabase::new(label);
        let mut ledger = EventLedger::open(&database.path).expect("open current ledger");
        let (spec, graph) = current_pair(sprint_id, cap);
        ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("create current authority");
        (database, ledger, spec, graph)
    }

    const V34_ATOMIC_ADMISSION_TABLES: [&str; 3] = [
        "current_final_verification_attempts_v32",
        "current_final_verification_events_v34",
        "current_final_verification_operational_attempts_v34",
    ];

    fn assert_v34_admission_row_count(connection: &Connection, expected: i64, context: &str) {
        for table in V34_ATOMIC_ADMISSION_TABLES {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap_or_else(|error| panic!("{context}: count {table}: {error}"));
            assert_eq!(count, expected, "{context}: {table}");
        }
    }

    fn derive_transactional_v34_admission(
        transaction: &Transaction<'_>,
        request: &CurrentFinalVerificationAdmissionRequestV1,
    ) -> (
        PersistedCurrentFinalVerificationAttemptV1,
        CurrentFinalVerificationAuthorityEventV1,
        OperationalCurrentFinalVerificationAttemptV1,
    ) {
        let request_bytes = request.canonical_bytes().expect("canonical request");
        let request_digest = request.canonical_digest().expect("request digest");
        let current = load_current_sprint_authority(transaction, &request.sprint_id)
            .expect("load current authority");
        let admitted = admit_current_final_verification_attempt_in_transaction_v32(
            transaction,
            request,
            &request_bytes,
            &request_digest,
        )
        .expect("create transactional v32 parent");
        assert!(admitted.inserted, "crash-cut fixture must be fresh");
        let event = CurrentFinalVerificationAuthorityEventV1::try_new(
            &admitted.persisted,
            request_digest,
            1,
        )
        .expect("derive exact contiguous admission event");
        let operational = OperationalCurrentFinalVerificationAttemptV1::try_new(
            request,
            &current,
            &admitted.persisted,
            &event,
        )
        .expect("derive exact operational overlay");
        (admitted.persisted, event, operational)
    }

    fn assert_normal_v34_admission_after_rollback(
        database: &TestDatabase,
        request: &CurrentFinalVerificationAdmissionRequestV1,
        context: &str,
    ) {
        let reader = EventLedger::open_read_only(&database.path)
            .unwrap_or_else(|error| panic!("{context}: reopen rollback read-only: {error}"));
        assert_v34_admission_row_count(&reader.connection, 0, context);
        drop(reader);

        let mut writer = EventLedger::open(&database.path)
            .unwrap_or_else(|error| panic!("{context}: reopen rollback writable: {error}"));
        let admitted = writer
            .admit_operational_current_final_verification_attempt_v34(request)
            .unwrap_or_else(|error| panic!("{context}: normal admission failed: {error}"));
        let replay = writer
            .admit_operational_current_final_verification_attempt_v34(request)
            .unwrap_or_else(|error| panic!("{context}: exact replay failed: {error}"));
        assert_eq!(admitted, replay, "{context}: replay must be exact readback");
        assert_v34_admission_row_count(&writer.connection, 1, context);
    }

    fn run_v34_event_only_precommit_crash_cut() {
        let database = TestDatabase::new("v34-crash-after-valid-event-only-insert");
        let mut ledger = EventLedger::open(&database.path).expect("open event-only crash fixture");
        let (spec, graph) = current_pair("sprint-v34-event-only-crash", 3);
        ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("create event-only current authority");
        let request = admission_request(
            "sprint-v34-event-only-crash",
            "request-v34-event-only-crash",
            task_set("sprint-v34-event-only-crash", 'c', None, 20),
            criterion_set("sprint-v34-event-only-crash", 'c', 1, 21),
            30,
        );
        {
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin event-only crash-cut transaction");
            let (parent, event, operational) =
                derive_transactional_v34_admission(&transaction, &request);
            with_operational_admission_write_guard(
                OperationalAdmissionWriteGuardV1 {
                    attempt_id: parent.authority.attempt_id,
                    event_digest: event.event_digest.clone(),
                    operational_attempt_digest: operational.operational_attempt_digest,
                },
                || insert_operational_event_v34(&transaction, &event),
            )
            .expect("insert one valid event without its overlay");
            for table in [
                "current_final_verification_attempts_v32",
                "current_final_verification_events_v34",
            ] {
                let count = transaction
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .expect("count event-only transaction row");
                assert_eq!(count, 1, "event-only transaction: {table}");
            }
            let overlay_count = transaction
                .query_row(
                    "SELECT COUNT(*) FROM current_final_verification_operational_attempts_v34",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count absent event-only overlay");
            assert_eq!(overlay_count, 0);
            transaction
                .execute_batch(
                    "PRAGMA recursive_triggers = OFF;
                     DROP TRIGGER current_final_verification_events_v34_validate_insert;",
                )
                .expect("isolate the no-replace trigger inside no-child crash cut");
            let replacement_error = transaction
                .execute(
                    "INSERT OR REPLACE INTO current_final_verification_events_v34
                     SELECT * FROM current_final_verification_events_v34 WHERE event_id = ?1",
                    [event.event_id.as_str()],
                )
                .expect_err("event-only row cannot be replaced without a child");
            assert!(
                replacement_error
                    .to_string()
                    .contains("event identity already exists")
            );
        }
        drop(ledger);
        assert_normal_v34_admission_after_rollback(
            &database,
            &request,
            "event-only precommit crash cut",
        );
    }

    fn run_v34_overlay_precommit_crash_cut() {
        let database = TestDatabase::new("v34-crash-after-valid-overlay-insert");
        let mut ledger = EventLedger::open(&database.path).expect("open overlay crash fixture");
        let (spec, graph) = current_pair("sprint-v34-overlay-crash", 3);
        ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("create overlay current authority");
        let request = admission_request(
            "sprint-v34-overlay-crash",
            "request-v34-overlay-crash",
            task_set("sprint-v34-overlay-crash", 'c', None, 20),
            criterion_set("sprint-v34-overlay-crash", 'c', 1, 21),
            30,
        );
        {
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin overlay crash-cut transaction");
            let (parent, event, operational) =
                derive_transactional_v34_admission(&transaction, &request);
            with_operational_admission_write_guard(
                OperationalAdmissionWriteGuardV1 {
                    attempt_id: parent.authority.attempt_id,
                    event_digest: event.event_digest.clone(),
                    operational_attempt_digest: operational.operational_attempt_digest.clone(),
                },
                || {
                    insert_operational_event_v34(&transaction, &event)?;
                    insert_operational_attempt_v34(&transaction, &operational)
                },
            )
            .expect("insert one valid event and overlay without commit");
            assert_v34_admission_row_count(&transaction, 1, "event-and-overlay transaction");
        }
        drop(ledger);
        assert_normal_v34_admission_after_rollback(
            &database,
            &request,
            "event-and-overlay precommit crash cut",
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum V34EventIdentity {
        SprintSequence,
        EventId,
        EventDigest,
        AttemptKind,
    }

    impl V34EventIdentity {
        const ALL: [Self; 4] = [
            Self::SprintSequence,
            Self::EventId,
            Self::EventDigest,
            Self::AttemptKind,
        ];
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum V34OperationalIdentity {
        AttemptId,
        FinalVerificationAdmissionId,
        AttemptAuthorityDigest,
        RequestId,
        RequestDigest,
        AdmissionEventId,
        OperationalAttemptDigest,
        SprintAttempt,
        SprintOrdinal,
    }

    impl V34OperationalIdentity {
        const ALL: [Self; 9] = [
            Self::AttemptId,
            Self::FinalVerificationAdmissionId,
            Self::AttemptAuthorityDigest,
            Self::RequestId,
            Self::RequestDigest,
            Self::AdmissionEventId,
            Self::OperationalAttemptDigest,
            Self::SprintAttempt,
            Self::SprintOrdinal,
        ];
    }

    struct V34OperationalReplacement {
        attempt_id: String,
        sprint_id: String,
        attempt_ordinal: u8,
        final_verification_admission_id: String,
        attempt_authority_digest: String,
        request_id: String,
        request_digest: String,
        admission_event_id: String,
        operational_attempt_digest: String,
    }

    fn distinct_v34_hash(label: &str, existing: &str) -> String {
        let candidate = Digest::sha256(format!("v34-no-replace:{label}").as_bytes()).to_string();
        assert_ne!(
            candidate, existing,
            "test hash must be distinct for {label}"
        );
        candidate
    }

    fn assert_v34_no_replace_trigger_declares_every_identity(connection: &Connection) {
        let trigger_sql = |name: &str| {
            connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [name],
                    |row| row.get::<_, String>(0),
                )
                .unwrap_or_else(|error| panic!("load {name}: {error}"))
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let event = trigger_sql("current_final_verification_events_v34_no_replace");
        for identity in [
            "existing.sprint_id = NEW.sprint_id AND existing.event_sequence = NEW.event_sequence",
            "existing.event_id = NEW.event_id",
            "existing.event_digest = NEW.event_digest",
            "existing.attempt_id = NEW.attempt_id AND existing.event_kind = NEW.event_kind",
        ] {
            assert!(
                event.contains(identity),
                "missing event identity: {identity}"
            );
        }
        let operational =
            trigger_sql("current_final_verification_operational_attempts_v34_no_replace");
        for identity in [
            "existing.attempt_id = NEW.attempt_id",
            "existing.final_verification_admission_id = NEW.final_verification_admission_id",
            "existing.attempt_authority_digest = NEW.attempt_authority_digest",
            "existing.request_id = NEW.request_id",
            "existing.request_digest = NEW.request_digest",
            "existing.admission_event_id = NEW.admission_event_id",
            "existing.operational_attempt_digest = NEW.operational_attempt_digest",
            "existing.sprint_id = NEW.sprint_id AND existing.attempt_id = NEW.attempt_id",
            "existing.sprint_id = NEW.sprint_id AND existing.attempt_ordinal = NEW.attempt_ordinal",
        ] {
            assert!(
                operational.contains(identity),
                "missing operational identity: {identity}"
            );
        }
    }

    fn assert_v34_event_identity_replacement_blocked(
        connection: &Connection,
        admitted: &PersistedOperationalCurrentFinalVerificationAttemptV1,
        target: V34EventIdentity,
    ) {
        let source = &admitted.admission_event;
        let sprint_id = if target == V34EventIdentity::SprintSequence {
            source.sprint_id.clone()
        } else {
            format!("distinct-sprint-{target:?}")
        };
        let event_sequence = if target == V34EventIdentity::SprintSequence {
            source.event_sequence
        } else {
            source.event_sequence + 100
        };
        let event_id = if target == V34EventIdentity::EventId {
            source.event_id.clone()
        } else {
            distinct_v34_hash(&format!("event-id-{target:?}"), &source.event_id)
        };
        let attempt_id = if target == V34EventIdentity::AttemptKind {
            source.attempt_id.clone()
        } else {
            format!("distinct-attempt-{target:?}")
        };
        let event_kind = if target == V34EventIdentity::AttemptKind {
            source.event_kind.sql_kind()
        } else {
            CurrentFinalVerificationAuthorityEventKindV1::LaunchCommitted.sql_kind()
        };
        let event_digest = if target == V34EventIdentity::EventDigest {
            source.event_digest.to_string()
        } else {
            distinct_v34_hash(
                &format!("event-digest-{target:?}"),
                source.event_digest.as_str(),
            )
        };
        let error = connection
            .execute(
                "INSERT OR REPLACE INTO current_final_verification_events_v34 (
                    sprint_id, event_sequence, event_id, event_version, event_kind,
                    attempt_id, request_id, request_digest, occurred_at_unix_ms,
                    event_digest, event_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    sprint_id,
                    i64::try_from(event_sequence).expect("test event sequence fits SQLite"),
                    event_id,
                    i64::from(source.event_version),
                    event_kind,
                    attempt_id,
                    source.request_id,
                    source.request_digest.as_str(),
                    i64::try_from(source.occurred_at_unix_ms).expect("test event time fits SQLite"),
                    event_digest,
                    source.canonical_bytes().expect("canonical source event"),
                ],
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("event identity already exists"),
            "{target:?}: {error}"
        );
    }

    fn v34_operational_replacement(
        source: &OperationalCurrentFinalVerificationAttemptV1,
        target: V34OperationalIdentity,
    ) -> V34OperationalReplacement {
        let attempt_id = if matches!(
            target,
            V34OperationalIdentity::AttemptId | V34OperationalIdentity::SprintAttempt
        ) {
            source.attempt_id.clone()
        } else {
            format!("distinct-attempt-{target:?}")
        };
        let sprint_id = if matches!(
            target,
            V34OperationalIdentity::SprintAttempt | V34OperationalIdentity::SprintOrdinal
        ) {
            source.sprint_id.clone()
        } else {
            format!("distinct-sprint-{target:?}")
        };
        let attempt_ordinal = if target == V34OperationalIdentity::SprintOrdinal {
            source.attempt_ordinal
        } else {
            2
        };
        let selected_text = |identity, existing: &str, label: &str| {
            if target == identity {
                existing.to_owned()
            } else {
                format!("distinct-{label}-{target:?}")
            }
        };
        let selected_hash = |identity, existing: &str, label: &str| {
            if target == identity {
                existing.to_owned()
            } else {
                distinct_v34_hash(&format!("{label}-{target:?}"), existing)
            }
        };
        V34OperationalReplacement {
            attempt_id,
            sprint_id,
            attempt_ordinal,
            final_verification_admission_id: selected_text(
                V34OperationalIdentity::FinalVerificationAdmissionId,
                &source.final_verification_admission_id,
                "admission-id",
            ),
            attempt_authority_digest: selected_hash(
                V34OperationalIdentity::AttemptAuthorityDigest,
                source.attempt_authority_digest.as_str(),
                "authority-digest",
            ),
            request_id: selected_text(
                V34OperationalIdentity::RequestId,
                &source.request_id,
                "request-id",
            ),
            request_digest: selected_hash(
                V34OperationalIdentity::RequestDigest,
                source.request_digest.as_str(),
                "request-digest",
            ),
            admission_event_id: selected_hash(
                V34OperationalIdentity::AdmissionEventId,
                &source.admission_event_id,
                "admission-event-id",
            ),
            operational_attempt_digest: selected_hash(
                V34OperationalIdentity::OperationalAttemptDigest,
                source.operational_attempt_digest.as_str(),
                "operational-digest",
            ),
        }
    }

    fn assert_v34_operational_identity_replacement_blocked(
        connection: &Connection,
        admitted: &PersistedOperationalCurrentFinalVerificationAttemptV1,
        target: V34OperationalIdentity,
    ) {
        let source = &admitted.operational_attempt;
        let replacement = v34_operational_replacement(source, target);
        let error = connection
            .execute(
                "INSERT OR REPLACE INTO current_final_verification_operational_attempts_v34 (
                    attempt_id, operational_version, sprint_id, attempt_ordinal,
                    final_verification_admission_id, attempt_authority_digest,
                    diagnostic_v32_admission_event_id,
                    diagnostic_v32_admission_event_sequence, request_id,
                    request_digest, admission_event_id, admission_event_sequence,
                    sprint_spec_digest, task_graph_id, task_graph_digest,
                    task_graph_payload_digest, repair_slot_reserve_digest,
                    input_snapshot, complete_task_done_set_digest,
                    complete_criterion_evidence_set_digest, workspace_grant_hash,
                    verification_command_digest, execution_policy_digest,
                    coordinator_instance_id, admitted_at_unix_ms,
                    operational_attempt_digest, operational_json
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                    ?21, ?22, ?23, ?24, ?25, ?26, ?27
                 )",
                params![
                    replacement.attempt_id,
                    i64::from(source.operational_version),
                    replacement.sprint_id,
                    i64::from(replacement.attempt_ordinal),
                    replacement.final_verification_admission_id,
                    replacement.attempt_authority_digest,
                    source.diagnostic_v32_admission_event_id,
                    i64::try_from(source.diagnostic_v32_admission_event_sequence)
                        .expect("diagnostic event sequence fits SQLite"),
                    replacement.request_id,
                    replacement.request_digest,
                    replacement.admission_event_id,
                    i64::try_from(source.admission_event_sequence + 100)
                        .expect("admission event sequence fits SQLite"),
                    source.sprint_spec_digest.as_str(),
                    source.task_graph_id,
                    source.task_graph_digest.as_str(),
                    source.task_graph_payload_digest.as_str(),
                    source.repair_slot_reserve_digest.as_str(),
                    source.input_snapshot.as_str(),
                    source.complete_task_done_set_digest.as_str(),
                    source.complete_criterion_evidence_set_digest.as_str(),
                    source.workspace_grant_hash.as_str(),
                    source.verification_command_digest.as_str(),
                    source.execution_policy_digest.as_str(),
                    source.coordinator_instance_id,
                    i64::try_from(source.admitted_at_unix_ms)
                        .expect("operational admission time fits SQLite"),
                    replacement.operational_attempt_digest,
                    source.canonical_bytes().expect("canonical source overlay"),
                ],
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("operational-attempt identity already exists"),
            "{target:?}: {error}"
        );
    }

    fn initial_attempt_authority(
        request: &CurrentFinalVerificationAdmissionRequestV1,
        cap: u8,
    ) -> FinalVerificationAttemptAuthorityV1 {
        let request_digest = request.canonical_digest().expect("request digest");
        FinalVerificationAttemptAuthorityV1 {
            authority_version: crate::FINAL_VERIFICATION_ATTEMPT_AUTHORITY_VERSION_V1,
            attempt_id: mint_identity(ATTEMPT_ID_DOMAIN, request_digest.as_str().as_bytes()),
            sprint_id: request.sprint_id.clone(),
            attempt_ordinal: 1,
            max_final_verification_attempts: cap,
            final_verification_admission_id: mint_identity(
                ADMISSION_ID_DOMAIN,
                request_digest.as_str().as_bytes(),
            ),
            input_snapshot: request.task_done_set.snapshot_digest.clone(),
            complete_task_done_set_digest: request
                .task_done_set
                .canonical_digest()
                .expect("TaskDone set digest"),
            complete_criterion_evidence_set_digest: request
                .criterion_evidence_set
                .canonical_digest()
                .expect("criterion set digest"),
            final_verification_check: request.final_verification_check.clone(),
            execution_policy_digest: request.execution_policy_digest.clone(),
            provenance: FinalVerificationAttemptProvenanceV1 {
                coordinator_instance_id: request.coordinator_instance_id.clone(),
                admission_event_id: mint_identity(
                    ADMISSION_EVENT_ID_DOMAIN,
                    request_digest.as_str().as_bytes(),
                ),
                admission_event_sequence: 1,
                admitted_at_unix_ms: request.admitted_at_unix_ms,
            },
            predecessor: FinalVerificationAttemptPredecessorV1::Initial,
        }
    }

    fn activated_repair_fixture(
        label: &str,
        sprint_id: &str,
    ) -> (
        TestDatabase,
        CurrentFinalVerificationRepairActivationV1,
        CurrentFinalVerificationRepairCompletionRequestV1,
    ) {
        let (database, mut ledger, _, _) = create_current_ledger(label, sprint_id, 3);
        let first = ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                sprint_id,
                &format!("{sprint_id}-initial-request"),
                task_set(sprint_id, 'c', None, 20),
                criterion_set(sprint_id, 'c', 1, 21),
                30,
            ))
            .expect("admit repair fixture attempt");
        let failed = ledger
            .close_current_final_verification_attempt_v32(&clean_capture(
                &first.authority,
                &format!("{sprint_id}-failed-closure"),
                CurrentFinalVerificationTerminationV1::Exited { code: 7 },
                40,
            ))
            .expect("close repair fixture attempt");
        let activation = ledger
            .activate_current_final_verification_repair_v32(&failed.outcome_id, 50)
            .expect("activate repair fixture");
        let task_done_set = task_set(sprint_id, 'd', Some((1, 'd')), 60);
        let repair_task_done_proof_id = task_done_set
            .members
            .last()
            .expect("repair fixture appends one task")
            .task_done_proof_id
            .clone();
        let request = CurrentFinalVerificationRepairCompletionRequestV1 {
            request_id: format!("{sprint_id}-repair-request"),
            activation_id: activation.activation_id.clone(),
            repair_task_done_proof_id,
            integration_receipt_id: "integration-repair-1".into(),
            input_snapshot: digest('c'),
            result_snapshot: digest('d'),
            change_set_id: format!("{sprint_id}-repair-change"),
            operation_count: 1,
            task_done_set,
            criterion_evidence_set: criterion_set(sprint_id, 'd', 2, 61),
            completed_at_unix_ms: 70,
        };
        drop(ledger);
        (database, activation, request)
    }

    fn insert_repair_ready_direct(
        connection: &Connection,
        event: &super::super::current_repair_task_authority_v32::CurrentRepairTaskReadyEventV1,
        replace: bool,
    ) -> rusqlite::Result<usize> {
        let statement = if replace {
            "INSERT OR REPLACE INTO current_repair_task_ready_events_v32 (
                event_id, activation_id, sprint_id, task_id, slot_ordinal,
                occurred_at_unix_ms, event_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        } else {
            "INSERT INTO current_repair_task_ready_events_v32 (
                event_id, activation_id, sprint_id, task_id, slot_ordinal,
                occurred_at_unix_ms, event_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        };
        connection.execute(
            statement,
            params![
                event.event_id,
                event.activation_id,
                event.sprint_id,
                event.task_id,
                i64::from(event.slot_ordinal),
                i64::try_from(event.occurred_at_unix_ms).expect("test timestamp fits SQLite"),
                serde_json::to_vec(event).expect("canonical Ready event"),
            ],
        )
    }

    fn insert_repair_lease_direct(
        connection: &Connection,
        admission: &super::super::current_repair_task_authority_v32::CurrentRepairTaskLeaseAdmissionV1,
        replace: bool,
    ) -> rusqlite::Result<usize> {
        let statement = if replace {
            "INSERT OR REPLACE INTO current_repair_task_lease_admissions_v32 (
                lease_admission_id, activation_id, ready_event_id, sprint_id,
                task_id, slot_ordinal, lease_id, lease_epoch, worker_id,
                acquired_at_unix_ms, admission_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
        } else {
            "INSERT INTO current_repair_task_lease_admissions_v32 (
                lease_admission_id, activation_id, ready_event_id, sprint_id,
                task_id, slot_ordinal, lease_id, lease_epoch, worker_id,
                acquired_at_unix_ms, admission_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
        };
        connection.execute(
            statement,
            params![
                admission.lease_admission_id,
                admission.activation_id,
                admission.ready_event_id,
                admission.sprint_id,
                admission.task_id,
                i64::from(admission.slot_ordinal),
                admission.worker_lease.lease_id,
                i64::try_from(admission.worker_lease.lease_epoch)
                    .expect("test lease epoch fits SQLite"),
                admission.worker_lease.worker_id,
                i64::try_from(admission.worker_lease.acquired_at_unix_ms)
                    .expect("test timestamp fits SQLite"),
                serde_json::to_vec(admission).expect("canonical lease admission"),
            ],
        )
    }

    fn insert_repair_attempt_direct(
        connection: &Connection,
        admission: &super::super::current_repair_task_authority_v32::CurrentRepairTaskAttemptAdmissionV1,
        replace: bool,
    ) -> rusqlite::Result<usize> {
        let statement = if replace {
            "INSERT OR REPLACE INTO current_repair_task_attempt_admissions_v32 (
                attempt_admission_id, activation_id, ready_event_id,
                lease_admission_id, sprint_id, task_id, slot_ordinal,
                attempt_id, attempt_ordinal, admitted_at_unix_ms, admission_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
        } else {
            "INSERT INTO current_repair_task_attempt_admissions_v32 (
                attempt_admission_id, activation_id, ready_event_id,
                lease_admission_id, sprint_id, task_id, slot_ordinal,
                attempt_id, attempt_ordinal, admitted_at_unix_ms, admission_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
        };
        connection.execute(
            statement,
            params![
                admission.attempt_admission_id,
                admission.activation_id,
                admission.ready_event_id,
                admission.lease_admission_id,
                admission.sprint_id,
                admission.task_id,
                i64::from(admission.slot_ordinal),
                admission.task_attempt.attempt_id,
                i64::from(admission.task_attempt.attempt_ordinal),
                i64::try_from(admission.task_attempt.opened_at_unix_ms)
                    .expect("test timestamp fits SQLite"),
                serde_json::to_vec(admission).expect("canonical attempt admission"),
            ],
        )
    }

    #[test]
    fn current_repair_dormancy_chain_survives_restart_and_replays_after_completion() {
        let (database, activation, completion_request) =
            activated_repair_fixture("repair-dormancy-restart", "repair-dormancy-restart");
        let ledger = EventLedger::open(&database.path).expect("reopen activated repair");
        let permit = ledger
            .load_current_repair_activation_permit_v32(&activation.activation_id)
            .expect("load exact permit");
        let ready = super::super::current_repair_task_authority_v32::test_mint_ready(&permit, 51);
        let worker_lease = WorkerLease::new(
            activation.sprint_id.clone(),
            1,
            activation.repair_task_id.clone(),
            "worker-1".into(),
            vec![PathScope::Relative(PathBuf::from("src"))],
            52,
        )
        .expect("intrinsically valid exact task-scope lease");
        let lease = super::super::current_repair_task_authority_v32::test_mint_lease(
            &permit,
            &ready,
            worker_lease,
        );
        let attempt = super::super::current_repair_task_authority_v32::test_mint_attempt(
            &permit, &ready, &lease,
        );
        assert_eq!(
            attempt.task_attempt.opening_event_id,
            lease.lease_admission_id
        );
        let mut noncanonical = serde_json::to_vec(&ready).expect("Ready canonical bytes");
        noncanonical.push(b' ');
        assert!(
            ledger
                .connection
                .execute(
                    "INSERT INTO current_repair_task_ready_events_v32 (
                        event_id, activation_id, sprint_id, task_id, slot_ordinal,
                        occurred_at_unix_ms, event_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        ready.event_id,
                        ready.activation_id,
                        ready.sprint_id,
                        ready.task_id,
                        i64::from(ready.slot_ordinal),
                        i64::try_from(ready.occurred_at_unix_ms)
                            .expect("test timestamp fits SQLite"),
                        noncanonical,
                    ],
                )
                .is_err(),
            "trailing-space noncanonical Ready bytes fail the canonical CHECK"
        );
        insert_repair_ready_direct(&ledger.connection, &ready, false)
            .expect("insert exact repair Ready");
        insert_repair_lease_direct(&ledger.connection, &lease, false)
            .expect("insert exact repair lease");
        insert_repair_attempt_direct(&ledger.connection, &attempt, false)
            .expect("insert exact repair attempt");
        assert!(insert_repair_ready_direct(&ledger.connection, &ready, false).is_err());
        assert!(insert_repair_lease_direct(&ledger.connection, &lease, false).is_err());
        assert!(insert_repair_attempt_direct(&ledger.connection, &attempt, false).is_err());
        drop(ledger);

        let mut restarted = EventLedger::open(&database.path).expect("restart repair ledger");
        for (sql, id, expected) in [
            (
                "SELECT event_json FROM current_repair_task_ready_events_v32
                 WHERE event_id = ?1",
                ready.event_id.as_str(),
                serde_json::to_vec(&ready).expect("Ready canonical bytes"),
            ),
            (
                "SELECT admission_json FROM current_repair_task_lease_admissions_v32
                 WHERE lease_admission_id = ?1",
                lease.lease_admission_id.as_str(),
                serde_json::to_vec(&lease).expect("lease canonical bytes"),
            ),
            (
                "SELECT admission_json FROM current_repair_task_attempt_admissions_v32
                 WHERE attempt_admission_id = ?1",
                attempt.attempt_admission_id.as_str(),
                serde_json::to_vec(&attempt).expect("attempt canonical bytes"),
            ),
        ] {
            let stored: Vec<u8> = restarted
                .connection
                .query_row(sql, [id], |row| row.get(0))
                .expect("read exact repair row after restart");
            assert_eq!(stored, expected, "restart readback must be byte-exact");
        }
        restarted
            .complete_current_final_verification_repair_v32(&completion_request)
            .expect("complete repair and stale the live permit");
        assert!(
            restarted
                .load_current_repair_activation_permit_v32(&activation.activation_id)
                .is_err()
        );
        // Completion stales the activation: the live-activation trigger rejects
        // any fresh direct Ready insert.
        let stale_ready =
            super::super::current_repair_task_authority_v32::test_mint_ready(&permit, 53);
        assert!(insert_repair_ready_direct(&restarted.connection, &stale_ready, false).is_err());
    }

    #[test]
    fn direct_sql_rejects_crossed_activation_slot_sprint_and_scope_substitution() {
        let (database, activation, _) =
            activated_repair_fixture("repair-direct-sql", "repair-direct-sql");
        let ledger = EventLedger::open(&database.path).expect("reopen activated repair");
        let permit = ledger
            .load_current_repair_activation_permit_v32(&activation.activation_id)
            .expect("load exact permit");
        let ready = super::super::current_repair_task_authority_v32::test_mint_ready(&permit, 51);

        let (_absent_database, absent_ledger, _, _) =
            create_current_ledger("repair-direct-sql-absent", "repair-direct-sql", 3);
        assert!(
            insert_repair_ready_direct(&absent_ledger.connection, &ready, false).is_err(),
            "canonical Ready bytes cannot create authority when the exact activation row is absent"
        );

        let mut crossed_slot = ready.clone();
        crossed_slot.task_id = "repair-2".into();
        crossed_slot.slot_ordinal = 2;
        super::super::current_repair_task_authority_v32::test_remint_ready(&mut crossed_slot);
        assert!(insert_repair_ready_direct(&ledger.connection, &crossed_slot, false).is_err());

        let mut crossed_sprint = ready.clone();
        crossed_sprint.sprint_id = "another-sprint".into();
        super::super::current_repair_task_authority_v32::test_remint_ready(&mut crossed_sprint);
        assert!(insert_repair_ready_direct(&ledger.connection, &crossed_sprint, false).is_err());

        insert_repair_ready_direct(&ledger.connection, &ready, false)
            .expect("exact activated direct Ready is admitted");
        let substituted_lease = WorkerLease::new(
            activation.sprint_id.clone(),
            1,
            activation.repair_task_id.clone(),
            "worker-1".into(),
            vec![PathScope::Relative(PathBuf::from("src/repair/narrowed"))],
            52,
        )
        .expect("intrinsically valid substituted-scope lease");
        let substituted = super::super::current_repair_task_authority_v32::test_mint_lease(
            &permit,
            &ready,
            substituted_lease,
        );
        assert!(insert_repair_lease_direct(&ledger.connection, &substituted, false).is_err());

        let exact_lease = WorkerLease::new(
            activation.sprint_id.clone(),
            1,
            activation.repair_task_id.clone(),
            "worker-1".into(),
            vec![PathScope::Relative(PathBuf::from("src"))],
            52,
        )
        .expect("intrinsically valid exact task-scope lease");
        let lease = super::super::current_repair_task_authority_v32::test_mint_lease(
            &permit,
            &ready,
            exact_lease,
        );
        insert_repair_lease_direct(&ledger.connection, &lease, false)
            .expect("exact task-scope lease is admitted");
        let mut substituted_attempt =
            super::super::current_repair_task_authority_v32::test_mint_attempt(
                &permit, &ready, &lease,
            );
        substituted_attempt.task_attempt.worker_lease.path_scopes = vec![PathScope::Workspace];
        super::super::current_repair_task_authority_v32::test_remint_attempt(
            &mut substituted_attempt,
        );
        assert!(
            insert_repair_attempt_direct(&ledger.connection, &substituted_attempt, false).is_err()
        );
        let attempt = super::super::current_repair_task_authority_v32::test_mint_attempt(
            &permit, &ready, &lease,
        );
        insert_repair_attempt_direct(&ledger.connection, &attempt, false)
            .expect("exact lease-linked attempt remains admissible");
    }

    #[test]
    fn repair_authority_tables_reject_replace_before_and_after_children() {
        let (database, activation, _) =
            activated_repair_fixture("repair-no-replace", "repair-no-replace");
        let ledger = EventLedger::open(&database.path).expect("reopen activated repair");
        let permit = ledger
            .load_current_repair_activation_permit_v32(&activation.activation_id)
            .expect("load exact permit");
        let ready = super::super::current_repair_task_authority_v32::test_mint_ready(&permit, 51);
        insert_repair_ready_direct(&ledger.connection, &ready, false).expect("Ready before child");
        assert!(insert_repair_ready_direct(&ledger.connection, &ready, true).is_err());
        let worker_lease = WorkerLease::new(
            activation.sprint_id.clone(),
            1,
            activation.repair_task_id.clone(),
            "worker-1".into(),
            vec![PathScope::Relative(PathBuf::from("src"))],
            52,
        )
        .expect("intrinsically valid exact task-scope lease");
        let lease = super::super::current_repair_task_authority_v32::test_mint_lease(
            &permit,
            &ready,
            worker_lease,
        );
        insert_repair_lease_direct(&ledger.connection, &lease, false)
            .expect("lease before attempt child");
        assert!(insert_repair_lease_direct(&ledger.connection, &lease, true).is_err());
        let attempt = super::super::current_repair_task_authority_v32::test_mint_attempt(
            &permit, &ready, &lease,
        );
        insert_repair_attempt_direct(&ledger.connection, &attempt, false)
            .expect("attempt terminal child in current layer");
        assert!(insert_repair_attempt_direct(&ledger.connection, &attempt, true).is_err());
        // Parent replacements remain blocked after all current children exist.
        assert!(insert_repair_ready_direct(&ledger.connection, &ready, true).is_err());
        assert!(insert_repair_lease_direct(&ledger.connection, &lease, true).is_err());
        let stored: Vec<u8> = ledger
            .connection
            .query_row(
                "SELECT admission_json FROM current_repair_task_attempt_admissions_v32
                 WHERE attempt_admission_id = ?1",
                [attempt.attempt_admission_id.as_str()],
                |row| row.get(0),
            )
            .expect("attempt unchanged after replacement attacks");
        assert_eq!(
            stored,
            serde_json::to_vec(&attempt).expect("attempt canonical bytes")
        );
    }

    #[test]
    fn concurrent_direct_repair_inserts_have_one_sql_winner_per_activation() {
        let (database, activation, _) =
            activated_repair_fixture("repair-concurrent", "repair-concurrent");
        let ledger = EventLedger::open(&database.path).expect("reopen activated repair");
        let permit = ledger
            .load_current_repair_activation_permit_v32(&activation.activation_id)
            .expect("load exact permit");
        let ready = super::super::current_repair_task_authority_v32::test_mint_ready(&permit, 51);
        drop(ledger);

        let open_direct = |path: PathBuf| {
            let connection = Connection::open(path).expect("open direct connection");
            connection
                .busy_timeout(std::time::Duration::from_secs(10))
                .expect("set direct busy timeout");
            super::super::register_schema_functions(&connection)
                .expect("register direct schema functions");
            connection
        };

        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = database.path.clone();
            let ready = ready.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let connection = open_direct(path);
                barrier.wait();
                insert_repair_ready_direct(&connection, &ready, false)
            }));
        }
        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("join readiness writer"))
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);
        let verifier = open_direct(database.path.clone());
        let (count, stored): (i64, Vec<u8>) = verifier
            .query_row(
                "SELECT COUNT(*), MAX(event_json)
                 FROM current_repair_task_ready_events_v32 WHERE activation_id = ?1",
                [activation.activation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read raced Ready row");
        assert_eq!(count, 1, "identical Ready race leaves exactly one row");
        assert_eq!(
            stored,
            serde_json::to_vec(&ready).expect("Ready canonical bytes")
        );

        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for (worker, epoch, acquired_at) in [("worker-1", 1_u64, 52_u64), ("worker-2", 2, 53)] {
            let worker_lease = WorkerLease::new(
                activation.sprint_id.clone(),
                epoch,
                activation.repair_task_id.clone(),
                worker.into(),
                vec![PathScope::Relative(PathBuf::from("src"))],
                acquired_at,
            )
            .expect("intrinsically valid racing lease");
            let lease = super::super::current_repair_task_authority_v32::test_mint_lease(
                &permit,
                &ready,
                worker_lease,
            );
            let path = database.path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let connection = open_direct(path);
                barrier.wait();
                insert_repair_lease_direct(&connection, &lease, false)
            }));
        }
        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("join lease writer"))
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        let rejection = outcomes
            .iter()
            .find_map(|result| result.as_ref().err())
            .expect("losing lease insert is rejected")
            .to_string();
        assert!(
            rejection.contains("current repair lease identity already exists")
                || rejection.contains("UNIQUE constraint failed"),
            "loser must fail on activation uniqueness: {rejection}"
        );
        let lease_count: i64 = verifier
            .query_row(
                "SELECT COUNT(*) FROM current_repair_task_lease_admissions_v32
                 WHERE activation_id = ?1",
                [activation.activation_id.as_str()],
                |row| row.get(0),
            )
            .expect("count raced lease rows");
        assert_eq!(lease_count, 1, "lease race leaves exactly one winner row");
    }

    #[test]
    fn v32_migration_is_exact_idempotent_and_preserves_every_v31_object() {
        fn migrate_exact_v31_to_v32(connection: &mut Connection) {
            let version: i64 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .expect("read source schema version");
            if version == 32 {
                return;
            }
            assert_eq!(version, 31, "test helper accepts only exact v31 or v32");
            crate::ledger::tests::schema_template::validate_schema_cached(connection, 31)
                .expect("v31 source image is exact before v32 migration");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("start exact v32 migration");
            transaction
                .execute_batch(super::super::MIGRATIONS[31])
                .expect("apply primary v32 migration");
            transaction
                .execute_batch(super::super::current_criterion_evidence_v32::MIGRATION_V32)
                .expect("apply criterion-evidence v32 sidecar");
            transaction
                .execute_batch(super::super::current_task_done_source_v32::MIGRATION_V32)
                .expect("apply TaskDone-source v32 sidecar");
            transaction
                .execute_batch(super::super::current_repair_task_authority_v32::MIGRATION_V32)
                .expect("apply repair-task v32 sidecar");
            transaction
                .pragma_update(None, "user_version", 32_i64)
                .expect("mark exact v32 schema");
            transaction.commit().expect("commit exact v32 migration");
        }

        let database = crate::ledger::tests::schema_template::exact_database_at(
            31,
            "fv32-idempotent-source",
        );
        let mut connection =
            Connection::open(&database.path).expect("open exact v31 source database");
        super::super::register_schema_functions(&connection).expect("register schema functions");
        let before = super::super::load_schema_objects(&connection).expect("load v31 schema");
        migrate_exact_v31_to_v32(&mut connection);
        migrate_exact_v31_to_v32(&mut connection);
        crate::ledger::tests::schema_template::validate_schema_cached(&connection, 32)
            .expect("direct migration produced the exact complete v32 source image");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read schema version");
        assert_eq!(version, 32);
        let after = super::super::load_schema_objects(&connection).expect("load v32 schema");
        for historical in before {
            assert!(
                after.iter().any(|candidate| candidate == &historical),
                "v32 changed historical schema object {}",
                historical.name
            );
        }
    }

    #[test]
    fn current_fresh_database_has_no_late_parent_foreign_key_violations() {
        let database = TestDatabase::new("fresh-foreign-key-check");
        let ledger = EventLedger::open(&database.path).expect("migrate fresh database to current");
        let mut statement = ledger
            .connection
            .prepare("PRAGMA foreign_key_check")
            .expect("prepare complete foreign-key audit");
        let violations = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .expect("run complete foreign-key audit")
            .collect::<Result<Vec<_>, _>>()
            .expect("read complete foreign-key audit");
        assert!(
            violations.is_empty(),
            "fresh current migration has unresolved late-parent foreign keys: {violations:?}"
        );
    }

    #[test]
    fn v32_production_admission_stays_dormant_without_current_source_receipts() {
        let (_database, mut ledger, spec, graph) =
            create_current_ledger("dormant-source-authority", "sprint-dormant-source", 3);
        let request = admission_request(
            "sprint-dormant-source",
            "dormant-source-request",
            task_set("sprint-dormant-source", 'c', None, 20),
            criterion_set("sprint-dormant-source", 'c', 1, 21),
            30,
        );

        let result = without_test_source_fixture_seeding(|| {
            ledger.admit_current_final_verification_attempt_v32(&request)
        });
        assert!(
            result.is_err(),
            "the production path must not mint or admit without real current sources"
        );
        let source = super::super::current_task_done_source_v32::test_source_for_member(
            &spec,
            &graph,
            &request.task_done_set.members[0],
        )
        .expect("derive exact source without persisting it");
        let raw_source =
            super::super::current_task_done_source_v32::test_insert_source_without_permit(
                &ledger.connection,
                &source,
            );
        assert!(
            format!("{raw_source:?}").contains(
                "current TaskDone source requires exact admitted source and task membership"
            ),
            "direct SQL must not acquire the connection-local source-write permit"
        );
        for table in [
            "current_task_done_sources_v32",
            "current_task_done_sets_v32",
            "current_task_done_set_seals_v32",
            "current_automated_verification_sources_v32",
            "current_human_acceptance_prompts_v32",
            "current_human_acceptance_decisions_v32",
            "current_criterion_evidence_receipts_v32",
            "current_criterion_evidence_sets_v32",
            "current_criterion_evidence_set_seals_v32",
            "current_final_verification_attempts_v32",
        ] {
            let count: i64 = ledger
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("count rolled-back authority rows");
            assert_eq!(count, 0, "failed admission left authority in {table}");
        }

        let admitted = ledger
            .admit_current_final_verification_attempt_v32(&request)
            .expect("test-only exact sources make the otherwise identical request admissible");
        assert_eq!(admitted.authority.attempt_ordinal, 1);
    }

    #[test]
    fn v32_migration_rejects_any_drift_in_the_exact_v31_source_image() {
        let database = crate::ledger::tests::schema_template::exact_database_at(
            31,
            "fv32-drift-source",
        );
        let mut connection =
            Connection::open(&database.path).expect("open exact v31 source database");
        super::super::register_schema_functions(&connection).expect("register schema functions");
        let view_name = connection
            .query_row(
                "SELECT name FROM sqlite_schema WHERE type = 'view' ORDER BY name LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("v31 has a view");
        connection
            .execute_batch(&format!("DROP VIEW \"{}\"", view_name.replace('"', "\"\"")))
            .expect("introduce source drift");
        assert!(matches!(
            super::super::run_migrations(&mut connection),
            Err(LedgerError::Corrupt {
                entity: "ledger schema migration source",
                ..
            })
        ));
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read unchanged version");
        assert_eq!(version, 31);
    }

    #[test]
    fn v32_sprint_creation_and_exact_replay_require_complete_criterion_projection() {
        let database = TestDatabase::new("criterion-projection");
        let mut ledger = EventLedger::open(&database.path).expect("open projection ledger");
        let (spec, graph) = current_pair("sprint-criterion-projection", 3);
        let created = ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("create sprint with criterion projection");
        let projected = ledger
            .load_current_sprint_criteria_v32(&spec.sprint_id)
            .expect("load complete criterion projection");
        assert_eq!(projected.len(), spec.acceptance_criteria.len());
        assert!(
            projected
                .iter()
                .zip(&spec.acceptance_criteria)
                .all(|(projection, criterion)| projection.criterion == *criterion)
        );

        let replay = ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("exact replay revalidates complete projection");
        assert_eq!(replay, created);
        let count: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_sprint_criteria_v32 WHERE sprint_id = ?1",
                [spec.sprint_id.as_str()],
                |row| row.get(0),
            )
            .expect("count projected criteria");
        assert_eq!(
            usize::try_from(count).expect("nonnegative criterion count"),
            spec.acceptance_criteria.len()
        );

        drop(ledger);
        let reopened = EventLedger::open(&database.path).expect("restart projection ledger");
        assert_eq!(
            reopened
                .load_current_sprint_authority_v32(&spec.sprint_id)
                .expect("authority readback requires projection"),
            created
        );
        assert_eq!(
            reopened
                .load_current_sprint_criteria_v32(&spec.sprint_id)
                .expect("projection survives restart"),
            projected
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One custody test proves exact request bytes, digest derivation, SQL rejection, and restart readback.
    fn v32_admission_request_bytes_derive_digest_and_ids_in_rust_and_sql() {
        let (database, mut ledger, _, _) =
            create_current_ledger("request-custody", "sprint-request-custody", 3);
        let request = admission_request(
            "sprint-request-custody",
            "request-custody-1",
            task_set("sprint-request-custody", 'c', None, 20),
            criterion_set("sprint-request-custody", 'c', 1, 21),
            30,
        );
        let expected_bytes = request.canonical_bytes().expect("canonical request bytes");
        let expected_digest = request
            .canonical_digest()
            .expect("canonical request digest");
        let admitted = ledger
            .admit_current_final_verification_attempt_v32(&request)
            .expect("admit request whose exact bytes are retained");
        let stored: (Vec<u8>, String) = ledger
            .connection
            .query_row(
                "SELECT request_json, request_digest
                 FROM current_final_verification_attempts_v32 WHERE attempt_id = ?1",
                [admitted.authority.attempt_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read exact stored request");
        assert_eq!(stored.0, expected_bytes);
        assert_eq!(stored.1, expected_digest.as_str());
        validate_attempt_request_binding(&request, &admitted.authority)
            .expect("Rust readback derives the same authority identities");

        drop(ledger);
        let reopened = EventLedger::open(&database.path).expect("restart request ledger");
        assert_eq!(
            reopened
                .load_current_final_verification_attempt_v32(&admitted.authority.attempt_id)
                .expect("restart recomputes request bindings"),
            admitted
        );

        let (_raw_database, mut raw, spec, graph) =
            create_current_ledger("request-raw", "sprint-request-raw", 3);
        let raw_request = admission_request(
            "sprint-request-raw",
            "request-raw-1",
            task_set("sprint-request-raw", 'c', None, 20),
            criterion_set("sprint-request-raw", 'c', 1, 21),
            30,
        );
        let transaction = raw
            .connection
            .transaction()
            .expect("begin source-set write");
        persist_task_done_set(&transaction, &spec, &graph, &raw_request.task_done_set)
            .expect("persist exact TaskDone set");
        persist_criterion_evidence_set(&transaction, &spec, &raw_request.criterion_evidence_set)
            .expect("persist exact criterion set");
        transaction.commit().expect("commit exact source sets");

        let exact_authority = initial_attempt_authority(&raw_request, 3);
        let mut forged_authority = exact_authority.clone();
        forged_authority.attempt_id = "attacker-selected-attempt".into();
        forged_authority.final_verification_admission_id = "attacker-selected-admission".into();
        forged_authority.provenance.admission_event_id = "attacker-selected-event".into();
        let request_bytes = raw_request
            .canonical_bytes()
            .expect("encode raw admission request");
        let request_digest = raw_request.canonical_digest().expect("raw request digest");
        let insert = |claimed_request_digest: &str,
                      authority: &FinalVerificationAttemptAuthorityV1| {
            let authority_bytes = authority.canonical_bytes().expect("encode authority");
            let authority_digest = authority.canonical_digest().expect("authority digest");
            raw.connection.execute(
                "INSERT INTO current_final_verification_attempts_v32 (
                    attempt_id, request_id, request_digest, request_json, sprint_id,
                    attempt_ordinal, max_final_verification_attempts,
                    final_verification_admission_id, input_snapshot,
                    complete_task_done_set_digest,
                    complete_criterion_evidence_set_digest, predecessor_kind,
                    authority_digest, admitted_at_unix_ms, authority_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 3, ?6, ?7, ?8, ?9,
                           'Initial', ?10, ?11, ?12)",
                params![
                    authority.attempt_id,
                    raw_request.request_id,
                    claimed_request_digest,
                    &request_bytes,
                    authority.sprint_id,
                    authority.final_verification_admission_id,
                    authority.input_snapshot.as_str(),
                    authority.complete_task_done_set_digest.as_str(),
                    authority.complete_criterion_evidence_set_digest.as_str(),
                    authority_digest.as_str(),
                    i64::try_from(authority.provenance.admitted_at_unix_ms)
                        .expect("timestamp fits"),
                    authority_bytes,
                ],
            )
        };
        assert!(insert(digest('9').as_str(), &forged_authority).is_err());
        assert!(insert(request_digest.as_str(), &forged_authority).is_err());
        insert(request_digest.as_str(), &exact_authority)
            .expect("exact request-derived SQL authority is admitted");
        assert_eq!(
            raw.load_current_final_verification_attempt_v32(&exact_authority.attempt_id)
                .expect("read exact direct-SQL authority")
                .authority,
            exact_authority
        );
    }

    #[test]
    fn v32_attempt_idempotency_serializes_exact_and_crossed_two_connection_replays() {
        let (database, ledger, _, _) =
            create_current_ledger("attempt-race-exact", "sprint-attempt-race-exact", 3);
        let path = database.path.clone();
        let request = admission_request(
            "sprint-attempt-race-exact",
            "attempt-race-request",
            task_set("sprint-attempt-race-exact", 'c', None, 20),
            criterion_set("sprint-attempt-race-exact", 'c', 1, 21),
            30,
        );
        drop(ledger);
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let path = path.clone();
                let request = request.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut ledger = EventLedger::open(path).expect("open racing ledger");
                    barrier.wait();
                    ledger
                        .admit_current_final_verification_attempt_v32(&request)
                        .map_err(|error| format!("{error:?}"))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("join exact admission"))
            .collect::<Vec<_>>();
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(
            results[0].as_ref().expect("first exact replay"),
            results[1].as_ref().expect("second exact replay")
        );
        let reopened = EventLedger::open(&database.path).expect("reopen exact race");
        let count: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_attempts_v32",
                [],
                |row| row.get(0),
            )
            .expect("count exact-race attempts");
        assert_eq!(count, 1);
        drop(reopened);

        let (crossed_database, crossed_ledger, _, _) =
            create_current_ledger("attempt-race-crossed", "sprint-attempt-race-crossed", 3);
        let crossed_path = crossed_database.path.clone();
        let first = admission_request(
            "sprint-attempt-race-crossed",
            "attempt-crossed-request",
            task_set("sprint-attempt-race-crossed", 'c', None, 20),
            criterion_set("sprint-attempt-race-crossed", 'c', 1, 21),
            30,
        );
        let mut second = first.clone();
        second.execution_policy_digest = digest('f');
        drop(crossed_ledger);
        let barrier = Arc::new(Barrier::new(3));
        let handles = [first, second]
            .into_iter()
            .map(|request| {
                let path = crossed_path.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut ledger = EventLedger::open(path).expect("open crossed racing ledger");
                    barrier.wait();
                    ledger
                        .admit_current_final_verification_attempt_v32(&request)
                        .map_err(|error| format!("{error:?}"))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("join crossed admission"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .all(|error| error.contains("ReferenceMismatch"))
        );
        let reopened = EventLedger::open(&crossed_database.path).expect("reopen crossed race");
        let count: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_attempts_v32",
                [],
                |row| row.get(0),
            )
            .expect("count crossed-race attempts");
        assert_eq!(count, 1);
    }

    #[test]
    fn v32_repair_idempotency_serializes_exact_and_crossed_two_connection_replays() {
        let (database, _activation, request) =
            activated_repair_fixture("repair-race-exact", "sprint-repair-race-exact");
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let path = database.path.clone();
                let request = request.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut ledger = EventLedger::open(path).expect("open repair racing ledger");
                    barrier.wait();
                    ledger
                        .complete_current_final_verification_repair_v32(&request)
                        .map_err(|error| format!("{error:?}"))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("join exact repair"))
            .collect::<Vec<_>>();
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(
            results[0].as_ref().expect("first exact repair"),
            results[1].as_ref().expect("second exact repair")
        );
        let reopened = EventLedger::open(&database.path).expect("reopen exact repair race");
        let count: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_repair_completions_v32",
                [],
                |row| row.get(0),
            )
            .expect("count exact-race repair completions");
        assert_eq!(count, 1);
        drop(reopened);

        let (crossed_database, _activation, first) =
            activated_repair_fixture("repair-race-crossed", "sprint-repair-race-crossed");
        let mut second = first.clone();
        second.change_set_id = "crossed-repair-change".into();
        let barrier = Arc::new(Barrier::new(3));
        let handles = [first, second]
            .into_iter()
            .map(|request| {
                let path = crossed_database.path.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut ledger = EventLedger::open(path).expect("open crossed repair ledger");
                    barrier.wait();
                    ledger
                        .complete_current_final_verification_repair_v32(&request)
                        .map_err(|error| format!("{error:?}"))
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("join crossed repair"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .all(|error| error.contains("ReferenceMismatch"))
        );
        let reopened =
            EventLedger::open(&crossed_database.path).expect("reopen crossed repair race");
        let count: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_repair_completions_v32",
                [],
                |row| row.get(0),
            )
            .expect("count crossed-race repair completions");
        assert_eq!(count, 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One causal matrix covers Rust, direct SQL, equality, strict predecessor order, and restart readback.
    fn v32_repair_source_and_successor_causality_is_closed_in_rust_sql_and_readback() {
        let (future_database, activation, mut future) =
            activated_repair_fixture("repair-future", "sprint-repair-future");
        future.task_done_set.recorded_at_unix_ms = 71;
        future.criterion_evidence_set = criterion_set("sprint-repair-future", 'd', 2, 71);
        let mut ledger = EventLedger::open(&future_database.path).expect("open future fixture");
        assert!(matches!(
            ledger.complete_current_final_verification_repair_v32(&future),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let current = ledger
            .load_current_sprint_authority_v32(&future.task_done_set.sprint_id)
            .expect("load future fixture authority");
        let transaction = ledger
            .connection
            .transaction()
            .expect("begin future set write");
        let task_set_digest = persist_task_done_set(
            &transaction,
            &current.spec,
            &current.graph,
            &future.task_done_set,
        )
        .expect("persist future TaskDone set");
        let criterion_set_digest = persist_criterion_evidence_set(
            &transaction,
            &current.spec,
            &future.criterion_evidence_set,
        )
        .expect("persist future criterion set");
        transaction.commit().expect("commit future source sets");
        let request_digest = future.canonical_digest().expect("future request digest");
        let completion = CurrentFinalVerificationRepairCompletionV1 {
            completion_version: CURRENT_OUTCOME_VERSION_V1,
            completion_id: mint_identity(
                REPAIR_COMPLETION_ID_DOMAIN,
                &encode_ledger(
                    "future repair completion identity",
                    &RepairCompletionIdentity {
                        request_digest: &request_digest,
                        sprint_id: &activation.sprint_id,
                        failed_attempt_id: &activation.failed_attempt_id,
                    },
                )
                .expect("encode future completion identity"),
            ),
            sprint_id: activation.sprint_id.clone(),
            activation_id: activation.activation_id.clone(),
            failed_attempt_id: activation.failed_attempt_id.clone(),
            repair_task_id: activation.repair_task_id.clone(),
            repair_task_done_proof_id: future.repair_task_done_proof_id.clone(),
            integration_receipt_id: future.integration_receipt_id.clone(),
            input_snapshot: future.input_snapshot.clone(),
            result_snapshot: future.result_snapshot.clone(),
            change_set_id: future.change_set_id.clone(),
            operation_count: future.operation_count,
            complete_task_done_set_digest: task_set_digest,
            complete_criterion_evidence_set_digest: criterion_set_digest,
            completed_at_unix_ms: future.completed_at_unix_ms,
        };
        let raw_future = ledger.connection.execute(
            "INSERT INTO current_final_verification_repair_completions_v32 (
                completion_id, request_id, request_digest, sprint_id,
                activation_id, failed_attempt_id, repair_task_id,
                repair_task_done_proof_id, integration_receipt_id,
                input_snapshot, result_snapshot, change_set_id, operation_count,
                complete_task_done_set_digest,
                complete_criterion_evidence_set_digest,
                completed_at_unix_ms, completion_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                       ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                completion.completion_id,
                future.request_id,
                request_digest.as_str(),
                completion.sprint_id,
                completion.activation_id,
                completion.failed_attempt_id,
                completion.repair_task_id,
                completion.repair_task_done_proof_id,
                completion.integration_receipt_id,
                completion.input_snapshot.as_str(),
                completion.result_snapshot.as_str(),
                completion.change_set_id,
                i64::from(completion.operation_count),
                completion.complete_task_done_set_digest.as_str(),
                completion.complete_criterion_evidence_set_digest.as_str(),
                i64::try_from(completion.completed_at_unix_ms).expect("timestamp fits"),
                encode_ledger("future repair completion", &completion)
                    .expect("encode future completion"),
            ],
        );
        assert!(raw_future.is_err());
        drop(ledger);

        let (equal_database, _activation, mut equal) =
            activated_repair_fixture("repair-equal", "sprint-repair-equal");
        equal.task_done_set.recorded_at_unix_ms = equal.completed_at_unix_ms;
        equal.criterion_evidence_set =
            criterion_set("sprint-repair-equal", 'd', 2, equal.completed_at_unix_ms);
        let mut equal_ledger =
            EventLedger::open(&equal_database.path).expect("open equal-time repair fixture");
        let equal_completion = equal_ledger
            .complete_current_final_verification_repair_v32(&equal)
            .expect("source sets recorded at completion time are admitted");
        drop(equal_ledger);
        let reopened = EventLedger::open(&equal_database.path).expect("restart equal-time fixture");
        assert_eq!(
            reopened
                .load_current_final_verification_repair_completion_v32(
                    &equal_completion.completion_id,
                )
                .expect("equal-time completion survives readback"),
            equal_completion
        );
        drop(reopened);

        let (barrier_database, _activation, request) =
            activated_repair_fixture("repair-successor-time", "sprint-repair-successor-time");
        let mut barrier_ledger =
            EventLedger::open(&barrier_database.path).expect("open successor-time fixture");
        let completion = barrier_ledger
            .complete_current_final_verification_repair_v32(&request)
            .expect("complete predecessor repair");
        let early = admission_request(
            "sprint-repair-successor-time",
            "early-successor",
            request.task_done_set.clone(),
            request.criterion_evidence_set.clone(),
            69,
        );
        assert!(matches!(
            barrier_ledger.admit_current_final_verification_attempt_v32(&early),
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let equal_successor = barrier_ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-repair-successor-time",
                "equal-successor",
                request.task_done_set,
                request.criterion_evidence_set,
                completion.completed_at_unix_ms,
            ))
            .expect("successor admission may equal repair completion time");
        drop(barrier_ledger);
        let reopened =
            EventLedger::open(&barrier_database.path).expect("restart successor-time fixture");
        assert_eq!(
            reopened
                .load_current_final_verification_repair_completion_v32(&completion.completion_id)
                .expect("repair predecessor survives restart"),
            completion
        );
        assert_eq!(
            reopened
                .load_current_final_verification_attempt_v32(&equal_successor.authority.attempt_id,)
                .expect("equal-time successor survives restart"),
            equal_successor
        );
    }

    #[test]
    fn v32_ordinary_verified_no_op_is_explicit_typed_and_restart_exact() {
        let (database, mut ledger, spec, graph) =
            create_current_ledger("verified-no-op", "sprint-verified-no-op", 3);
        let no_op = verified_no_op_task_set("sprint-verified-no-op", 20);
        no_op
            .validate_for(&spec, &graph)
            .expect("explicit ordinary VerifiedNoOp is a legal TaskDone source");
        let admitted = ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-verified-no-op",
                "admit-verified-no-op",
                no_op.clone(),
                criterion_set("sprint-verified-no-op", 'b', 1, 21),
                30,
            ))
            .expect("admit exact explicit no-op snapshot");
        let set_digest = admitted.authority.complete_task_done_set_digest.clone();
        let expected_source = super::super::current_task_done_source_v32::test_source_for_member(
            &spec,
            &graph,
            &no_op.members[0],
        )
        .expect("derive exact no-op source");
        let source = ledger
            .load_current_task_done_source_v32(&no_op.members[0].task_done_proof_id)
            .expect("load exact source through validated readback");
        assert_eq!(source, expected_source);
        assert_eq!(
            task_source_projection_is_canonical(&ledger.connection, &source, &source.task_id),
            1
        );
        assert_eq!(
            task_source_projection_is_canonical(
                &ledger.connection,
                &source,
                "crossed-indexed-task"
            ),
            0,
            "one crossed indexed column must invalidate canonical JSON parity"
        );

        let mut changed_without_progress = no_op.clone();
        changed_without_progress.members[0].integration_evidence =
            CurrentTaskDoneIntegrationEvidenceV1::Changed;
        assert!(
            changed_without_progress
                .validate_for(&spec, &graph)
                .is_err()
        );

        let mut no_op_with_progress = no_op.clone();
        no_op_with_progress.members[0].result_snapshot = digest('c');
        no_op_with_progress.snapshot_digest = digest('c');
        assert!(no_op_with_progress.validate_for(&spec, &graph).is_err());

        let mut no_op_without_empty_change_set = no_op.clone();
        no_op_without_empty_change_set.members[0].integration_evidence =
            CurrentTaskDoneIntegrationEvidenceV1::VerifiedNoOp {
                empty_change_set_id: " ".into(),
            };
        assert!(
            no_op_without_empty_change_set
                .validate_for(&spec, &graph)
                .is_err()
        );

        let mut repair_no_op = task_set("sprint-verified-no-op", 'd', Some((1, 'd')), 40);
        repair_no_op.members[1].integration_evidence =
            CurrentTaskDoneIntegrationEvidenceV1::VerifiedNoOp {
                empty_change_set_id: "change-set-empty-repair".into(),
            };
        repair_no_op.members[1].result_snapshot = digest('c');
        repair_no_op.snapshot_digest = digest('c');
        assert!(repair_no_op.validate_for(&spec, &graph).is_err());

        drop(ledger);
        let reopened = EventLedger::open(&database.path).expect("reopen no-op ledger");
        let readback = load_task_done_set_optional(&reopened.connection, set_digest.as_str())
            .expect("read no-op set after restart")
            .expect("persisted no-op set exists");
        assert_eq!(readback, no_op);
        assert_eq!(
            reopened
                .load_current_task_done_source_v32(&expected_source.task_done_proof_id)
                .expect("TaskDone source survives exact restart readback"),
            expected_source
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Direct-SQL coverage keeps every nullable no-op substitution in one auditable case.
    fn v32_direct_sql_cannot_erase_or_cross_verified_no_op_typing() {
        let (_database, mut ledger, spec, graph) =
            create_current_ledger("raw-verified-no-op", "sprint-raw-verified-no-op", 3);
        let no_op = verified_no_op_task_set("sprint-raw-verified-no-op", 20);
        let set_digest = no_op.canonical_digest().expect("digest no-op set");
        ledger
            .connection
            .execute(
                "INSERT INTO current_task_done_sets_v32 (
                    set_digest, sprint_id, snapshot_digest, member_count,
                    recorded_at_unix_ms, set_json
                 ) VALUES (?1, ?2, ?3, 1, 20, ?4)",
                params![
                    set_digest.as_str(),
                    no_op.sprint_id,
                    no_op.snapshot_digest.as_str(),
                    no_op.canonical_bytes().expect("encode no-op set"),
                ],
            )
            .expect("insert canonical no-op set envelope");
        let transaction = ledger
            .connection
            .transaction()
            .expect("begin exact no-op source fixture");
        super::super::current_task_done_source_v32::test_seed_sources_for_set(
            &transaction,
            &spec,
            &graph,
            &no_op,
        )
        .expect("seed exact no-op source without sealing the raw set");
        transaction.commit().expect("commit exact no-op source");

        for (integration_kind, empty_change_set_id) in
            [("Changed", None::<&str>), ("VerifiedNoOp", None::<&str>)]
        {
            let result = ledger.connection.execute(
                "INSERT INTO current_task_done_members_v32 (
                    set_digest, sprint_id, member_ordinal, task_id, task_done_proof_id,
                    integration_receipt_id, integration_kind,
                    empty_change_set_id, input_snapshot, result_snapshot
                 ) VALUES (?1, 'sprint-raw-verified-no-op', 0, 'ordinary',
                           'raw-proof', 'raw-integration', ?2, ?3, ?4, ?4)",
                params![
                    set_digest.as_str(),
                    integration_kind,
                    empty_change_set_id,
                    digest('b').as_str(),
                ],
            );
            assert!(
                result.is_err(),
                "invalid direct-SQL shape {integration_kind}"
            );
        }

        let crossed_member = ledger.connection.execute(
            "INSERT INTO current_task_done_members_v32 (
                    set_digest, sprint_id, member_ordinal, task_id, task_done_proof_id,
                    integration_receipt_id, integration_kind,
                    empty_change_set_id, input_snapshot, result_snapshot
                 ) VALUES (?1, 'sprint-raw-verified-no-op', 0, 'ordinary',
                           'raw-proof', 'raw-integration', 'Changed', NULL, ?2, ?3)",
            params![
                set_digest.as_str(),
                digest('b').as_str(),
                digest('c').as_str()
            ],
        );
        assert!(
            crossed_member.is_err(),
            "direct SQL cannot manufacture a member without its exact source receipt"
        );
        assert!(
            format!("{crossed_member:?}")
                .contains("current TaskDone member requires one exact immutable source receipt"),
            "the explicit source trigger, not nullable composite-FK behavior, must reject Changed/NULL"
        );
        let source_crossed_member = ledger.connection.execute(
            "INSERT INTO current_task_done_members_v32 (
                    set_digest, sprint_id, member_ordinal, task_id, task_done_proof_id,
                    integration_receipt_id, integration_kind,
                    empty_change_set_id, input_snapshot, result_snapshot
                 ) VALUES (?1, 'sprint-raw-verified-no-op', 0, 'ordinary',
                           ?2, 'crossed-integration', 'VerifiedNoOp', ?3, ?4, ?4)",
            params![
                set_digest.as_str(),
                no_op.members[0].task_done_proof_id,
                no_op.members[0].integration_evidence.empty_change_set_id(),
                digest('b').as_str(),
            ],
        );
        assert!(
            format!("{source_crossed_member:?}")
                .contains("current TaskDone member requires one exact immutable source receipt"),
            "a genuine source cannot be crossed onto another integration identity"
        );
        let crossed_seal = ledger.connection.execute(
            "INSERT INTO current_task_done_set_seals_v32 (
                set_digest, sprint_id, snapshot_digest, sealed_at_unix_ms
             ) VALUES (?1, 'sprint-raw-verified-no-op', ?2, 20)",
            params![set_digest.as_str(), digest('b').as_str()],
        );
        assert!(crossed_seal.is_err());
    }

    #[test]
    fn v32_task_done_seal_rejects_an_exact_source_backed_required_task_subset() {
        let database = TestDatabase::new("partial-required-task-set");
        let mut ledger = EventLedger::open(&database.path).expect("open current ledger");
        let (spec, graph) = two_required_task_pair("sprint-partial-required-task-set");
        ledger
            .create_current_sprint_authority_v32(&spec, &graph, 10)
            .expect("create two-required-task authority");
        let partial = task_set("sprint-partial-required-task-set", 'c', None, 20);
        assert!(
            partial.validate_for(&spec, &graph).is_err(),
            "Rust must classify the one-of-two required-task set as incomplete"
        );
        let transaction = ledger
            .connection
            .transaction()
            .expect("begin exact source fixture transaction");
        super::super::current_task_done_source_v32::test_seed_sources_for_set(
            &transaction,
            &spec,
            &graph,
            &partial,
        )
        .expect("seed the one genuine source without claiming set completeness");
        transaction.commit().expect("commit exact inert source");

        let set_digest = partial
            .canonical_digest()
            .expect("digest partial TaskDone set");
        ledger
            .connection
            .execute(
                "INSERT INTO current_task_done_sets_v32 (
                    set_digest, sprint_id, snapshot_digest, member_count,
                    recorded_at_unix_ms, set_json
                 ) VALUES (?1, ?2, ?3, 1, 20, ?4)",
                params![
                    set_digest.as_str(),
                    partial.sprint_id,
                    partial.snapshot_digest.as_str(),
                    partial
                        .canonical_bytes()
                        .expect("encode partial TaskDone set"),
                ],
            )
            .expect("stage canonical partial TaskDone envelope");
        let member = &partial.members[0];
        ledger
            .connection
            .execute(
                "INSERT INTO current_task_done_members_v32 (
                    set_digest, sprint_id, member_ordinal, task_id,
                    task_done_proof_id, integration_receipt_id,
                    integration_kind, empty_change_set_id,
                    input_snapshot, result_snapshot
                 ) VALUES (?1, ?2, 0, ?3, ?4, ?5, 'Changed', NULL, ?6, ?7)",
                params![
                    set_digest.as_str(),
                    partial.sprint_id,
                    member.task_id,
                    member.task_done_proof_id,
                    member.integration_receipt_id,
                    member.input_snapshot.as_str(),
                    member.result_snapshot.as_str(),
                ],
            )
            .expect("exact source permits staging one inert TaskDone member");
        let seal = ledger.connection.execute(
            "INSERT INTO current_task_done_set_seals_v32 (
                set_digest, sprint_id, snapshot_digest, sealed_at_unix_ms
             ) VALUES (?1, ?2, ?3, 20)",
            params![
                set_digest.as_str(),
                partial.sprint_id,
                partial.snapshot_digest.as_str()
            ],
        );
        assert!(
            seal.is_err(),
            "exact member sources cannot turn a required-task subset into a complete set"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One adversarial case crosses every exact criterion-source identity and membership edge.
    fn v32_criterion_members_reject_missing_and_crossed_exact_sources() {
        let (_database, mut ledger, _, _) =
            create_current_ledger("criterion-member-source", "sprint-criterion-member", 3);
        let exact_set = criterion_set("sprint-criterion-member", 'c', 1, 21);
        ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-criterion-member",
                "criterion-member-source-request",
                task_set("sprint-criterion-member", 'c', None, 20),
                exact_set.clone(),
                30,
            ))
            .expect("seed exact immutable criterion receipts through the fixture-only path");

        let mut staged = exact_set.clone();
        staged.recorded_at_unix_ms = 22;
        let staged_digest = staged
            .canonical_digest()
            .expect("digest staged criterion set");
        ledger
            .connection
            .execute(
                "INSERT INTO current_criterion_evidence_sets_v32 (
                    set_digest, sprint_id, snapshot_digest, member_count,
                    recorded_at_unix_ms, set_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    staged_digest.as_str(),
                    staged.sprint_id,
                    staged.snapshot_digest.as_str(),
                    i64::try_from(staged.members.len()).expect("fixture member count fits SQLite"),
                    i64::try_from(staged.recorded_at_unix_ms)
                        .expect("fixture timestamp fits SQLite"),
                    staged
                        .canonical_bytes()
                        .expect("encode staged criterion set"),
                ],
            )
            .expect("stage canonical inert criterion set envelope");

        let missing = ledger.connection.execute(
            "INSERT INTO current_criterion_evidence_members_v32 (
                set_digest, sprint_id, member_ordinal, criterion_id,
                evidence_receipt_id, evidence_kind, snapshot_digest
             ) VALUES (?1, ?2, 0, 'automated', 'missing-receipt', 'Verified', ?3)",
            params![
                staged_digest.as_str(),
                staged.sprint_id,
                staged.snapshot_digest.as_str()
            ],
        );
        assert!(
            format!("{missing:?}").contains(
                "current criterion-evidence member requires one exact immutable source receipt"
            ),
            "a label-only missing criterion source must fail at member insertion"
        );

        let crossed = ledger.connection.execute(
            "INSERT INTO current_criterion_evidence_members_v32 (
                set_digest, sprint_id, member_ordinal, criterion_id,
                evidence_receipt_id, evidence_kind, snapshot_digest
             ) VALUES (?1, ?2, 0, 'human', ?3, 'Verified', ?4)",
            params![
                staged_digest.as_str(),
                staged.sprint_id,
                exact_set.members[0].evidence_receipt_id,
                staged.snapshot_digest.as_str(),
            ],
        );
        assert!(
            format!("{crossed:?}").contains(
                "current criterion-evidence member requires one exact immutable source receipt"
            ),
            "a real receipt crossed onto another criterion must fail the exact join"
        );

        let mut partial = exact_set;
        partial.members.truncate(1);
        partial.recorded_at_unix_ms = 23;
        let partial_digest = partial
            .canonical_digest()
            .expect("digest source-backed partial criterion set");
        ledger
            .connection
            .execute(
                "INSERT INTO current_criterion_evidence_sets_v32 (
                    set_digest, sprint_id, snapshot_digest, member_count,
                    recorded_at_unix_ms, set_json
                 ) VALUES (?1, ?2, ?3, 1, 23, ?4)",
                params![
                    partial_digest.as_str(),
                    partial.sprint_id,
                    partial.snapshot_digest.as_str(),
                    partial
                        .canonical_bytes()
                        .expect("encode partial criterion set"),
                ],
            )
            .expect("stage source-backed partial criterion envelope");
        let member = &partial.members[0];
        ledger
            .connection
            .execute(
                "INSERT INTO current_criterion_evidence_members_v32 (
                    set_digest, sprint_id, member_ordinal, criterion_id,
                    evidence_receipt_id, evidence_kind, snapshot_digest
                 ) VALUES (?1, ?2, 0, ?3, ?4, 'Verified', ?5)",
                params![
                    partial_digest.as_str(),
                    partial.sprint_id,
                    member.criterion_id,
                    member.evidence_receipt_id,
                    member.snapshot_digest.as_str(),
                ],
            )
            .expect("exact source permits staging one inert member");
        let partial_seal = ledger.connection.execute(
            "INSERT INTO current_criterion_evidence_set_seals_v32 (
                set_digest, sprint_id, snapshot_digest, sealed_at_unix_ms
             ) VALUES (?1, ?2, ?3, 23)",
            params![
                partial_digest.as_str(),
                partial.sprint_id,
                partial.snapshot_digest.as_str()
            ],
        );
        assert!(
            partial_seal.is_err(),
            "an exact source-backed subset must not become a complete criterion set"
        );
    }

    #[test]
    fn v32_initial_admission_rejects_any_dormant_repair_member() {
        let (_database, mut ledger, _, _) =
            create_current_ledger("dormant-initial", "sprint-dormant-initial", 3);
        let result = ledger.admit_current_final_verification_attempt_v32(&admission_request(
            "sprint-dormant-initial",
            "admit-dormant",
            task_set("sprint-dormant-initial", 'd', Some((1, 'd')), 70),
            criterion_set("sprint-dormant-initial", 'd', 1, 71),
            80,
        ));
        assert!(matches!(result, Err(LedgerError::ReferenceMismatch { .. })));
        let attempt_count: i64 = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_attempts_v32",
                [],
                |row| row.get(0),
            )
            .expect("count attempts");
        assert_eq!(attempt_count, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One end-to-end negative sequence proves each repair prerequisite before the passing successor.
    fn v32_known_failure_requires_activation_changed_taskdone_and_all_fresh_evidence() {
        let (database, mut ledger, _, _) = create_current_ledger("repair", "sprint-repair", 3);
        let initial_tasks = task_set("sprint-repair", 'c', None, 20);
        let initial_criteria = criterion_set("sprint-repair", 'c', 1, 21);
        let stale_human_receipt_id = initial_criteria.members[1].evidence_receipt_id.clone();
        let first = ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-repair",
                "admit-1",
                initial_tasks.clone(),
                initial_criteria.clone(),
                30,
            ))
            .expect("admit initial verifier");
        let failure = ledger
            .close_current_final_verification_attempt_v32(&clean_capture(
                &first.authority,
                "closure-failed-1",
                CurrentFinalVerificationTerminationV1::Exited { code: 7 },
                40,
            ))
            .expect("close known failure");
        assert!(matches!(
            failure.outcome,
            CurrentFinalVerificationOutcomeKindV1::NonzeroExit { code: 7 }
        ));

        let unactivated = ledger.admit_current_final_verification_attempt_v32(&admission_request(
            "sprint-repair",
            "admit-without-repair",
            initial_tasks,
            initial_criteria,
            50,
        ));
        assert!(matches!(
            unactivated,
            Err(LedgerError::ReferenceMismatch { .. })
        ));

        let activation = ledger
            .activate_current_final_verification_repair_v32(&failure.outcome_id, 60)
            .expect("activate first repair slot");
        assert_eq!(activation.slot_ordinal, 1);
        let changed_tasks = task_set("sprint-repair", 'd', Some((1, 'd')), 70);
        let repair_task_done_proof_id = changed_tasks
            .members
            .last()
            .expect("repair set appends one task")
            .task_done_proof_id
            .clone();
        let mut stale_criteria = criterion_set("sprint-repair", 'd', 2, 71);
        stale_criteria.members[1].evidence_receipt_id = stale_human_receipt_id;
        let stale = ledger.complete_current_final_verification_repair_v32(
            &CurrentFinalVerificationRepairCompletionRequestV1 {
                request_id: "repair-stale".into(),
                activation_id: activation.activation_id.clone(),
                repair_task_done_proof_id: repair_task_done_proof_id.clone(),
                integration_receipt_id: "integration-repair-1".into(),
                input_snapshot: digest('c'),
                result_snapshot: digest('d'),
                change_set_id: "change-repair-1".into(),
                operation_count: 1,
                task_done_set: changed_tasks.clone(),
                criterion_evidence_set: stale_criteria,
                completed_at_unix_ms: 80,
            },
        );
        assert!(matches!(stale, Err(LedgerError::ReferenceMismatch { .. })));

        let fresh_criteria = criterion_set("sprint-repair", 'd', 2, 71);
        let mut crossed_prefix = changed_tasks.clone();
        crossed_prefix.members[0].task_done_proof_id = "rewritten-ordinary-proof".into();
        let crossed = ledger.complete_current_final_verification_repair_v32(
            &CurrentFinalVerificationRepairCompletionRequestV1 {
                request_id: "repair-crossed-prefix".into(),
                activation_id: activation.activation_id.clone(),
                repair_task_done_proof_id: repair_task_done_proof_id.clone(),
                integration_receipt_id: "integration-repair-1".into(),
                input_snapshot: digest('c'),
                result_snapshot: digest('d'),
                change_set_id: "change-repair-crossed".into(),
                operation_count: 1,
                task_done_set: crossed_prefix,
                criterion_evidence_set: fresh_criteria.clone(),
                completed_at_unix_ms: 80,
            },
        );
        assert!(matches!(
            crossed,
            Err(LedgerError::ReferenceMismatch { .. })
        ));
        let repair = ledger
            .complete_current_final_verification_repair_v32(
                &CurrentFinalVerificationRepairCompletionRequestV1 {
                    request_id: "repair-fresh".into(),
                    activation_id: activation.activation_id,
                    repair_task_done_proof_id,
                    integration_receipt_id: "integration-repair-1".into(),
                    input_snapshot: digest('c'),
                    result_snapshot: digest('d'),
                    change_set_id: "change-repair-1".into(),
                    operation_count: 1,
                    task_done_set: changed_tasks.clone(),
                    criterion_evidence_set: fresh_criteria.clone(),
                    completed_at_unix_ms: 80,
                },
            )
            .expect("complete exact repair");
        let second = ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-repair",
                "admit-2",
                changed_tasks,
                fresh_criteria,
                90,
            ))
            .expect("admit changed-snapshot verifier");
        assert_eq!(second.authority.attempt_ordinal, 2);
        assert!(matches!(
            second.authority.predecessor,
            FinalVerificationAttemptPredecessorV1::ChangedSnapshotAfterRepair {
                ref repair_admission_id,
                ..
            } if repair_admission_id == &repair.activation_id
        ));
        let passed = ledger
            .close_current_final_verification_attempt_v32(&clean_capture(
                &second.authority,
                "closure-passed-2",
                CurrentFinalVerificationTerminationV1::Exited { code: 0 },
                100,
            ))
            .expect("close passing verifier");
        assert_eq!(
            passed.outcome,
            CurrentFinalVerificationOutcomeKindV1::Verified
        );

        drop(ledger);
        let reopened = EventLedger::open(&database.path).expect("reopen repaired ledger");
        assert_eq!(
            reopened
                .load_current_final_verification_attempt_v32(&second.authority.attempt_id)
                .expect("read back second attempt")
                .outcome,
            Some(passed)
        );
        assert!(
            reopened
                .load_current_sprint_terminal_outcome_v32("sprint-repair")
                .expect("read terminal state")
                .is_none()
        );
    }
