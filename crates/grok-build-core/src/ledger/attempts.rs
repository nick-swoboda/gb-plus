//! Task-attempt lifecycle and effect-dispatch admission.

use super::{
    AgentEvent, AgentEventKind, ApplicationArtifactAssembly, BUSY_TIMEOUT, CONTRACT_VERSION,
    ClaimedObservationWriteFailure, CommandDomainCleanupProof, CommandOutputCaptureAcquiredV1,
    CommandOutputCaptureIntentAdmission, CommandOutputCaptureIntentV1,
    CommandOutputCaptureTerminalAnchorV1, CommandOutputCleanScanPublicationReceiptV1,
    CompiledExecutionPolicy, Connection, Digest, Duration, EffectIntent, EffectKind,
    EffectObservation, EventLedger, File, FlockOperation, FreshApplicationDispatchPermit,
    FreshFinalVerificationDispatchPermit, FreshLiveStateCaptureDispatchPermit,
    FreshRunnerEffectDispatchPermit, FreshTaskFormalCheckDispatchPermit,
    FreshTaskIntegrationDispatchPermit, FreshTaskRunningEffectDispatchPermit, Instant,
    LaunchCleanupExclusion, LedgerError, LedgerStateFilesystemIdentities, LiveStateCaptureBranch,
    MAX_EFFECT_REQUEST_BYTES, MAX_RUNNER_TRANSPORT_REQUEST_BYTES, Mode, OFlags, OpenFlags,
    OptionalExtension, Path, PersistedEffect, PersistedRunnerEffectDispatchClaim,
    RunnerEffectObservationAuthority, RunnerEffectRequestAuthority, RunnerEffectTransportPermit,
    RunnerSessionPurpose, SprintApplicationAdmission, SprintApplicationDispatchAdmission,
    SprintApplicationPreparation, SprintFinalVerificationAdmission,
    SprintFinalVerificationDispatchAdmission, SprintLiveStateCaptureAdmission,
    SprintLiveStateCaptureDispatchAdmission, SprintLiveStateCapturePlan,
    SprintLiveStateCapturePlanCut, SprintSpec, SprintState, TaskAttempt,
    TaskAttemptCandidateBoundary, TaskAttemptDisposition, TaskAttemptDispositionMetadata,
    TaskAttemptFormalCheck, TaskAttemptFormalCheckAdmission, TaskAttemptHistory,
    TaskAttemptIntegrationAdmission, TaskAttemptKnownCleanupOutcome, TaskAttemptRunningBoundary,
    TaskAttemptVerificationBoundary, TaskFormalCheckDispatchAdmission, TaskGraph,
    TaskGraphProvenance, TaskIntegrationDispatchAdmission, TaskIntegrationEvidence,
    TaskIntegrationRequest, TaskIntegrationValidationMode, TaskState, TransactionBehavior,
    VerificationEffectEvidence, WorkerLease, WorkerLeaseNeverLaunchedRelease, WorkspaceSnapshot,
    application_artifact_authority, canonical_database_path, canonical_finish_evidence,
    command_domain_cleanup, command_output_capture_authority, current_sprint_phase_state,
    current_task_state, decode_canonical_request, derive_applied_live_state_capture_plan_from,
    derive_sprint_application_preparation, derive_sprint_final_verification_snapshot,
    derive_verified_no_op_live_state_capture_plan_from, effect_requires_claimed_phase_terminal,
    encode, ensure_artifact_absent, ensure_new_sprint, ensure_sprint_not_terminal,
    ensure_sprint_running_for_task_work, event_exists, flock, fs, insert_agent_event,
    insert_application_artifact_assembly, insert_claimed_effect_observation,
    insert_direct_graph_provenance, insert_effect_evidence_payload, insert_effect_intent,
    insert_effect_observation, insert_effect_request_payload, insert_finish_effect_kind,
    insert_finish_receipt_id, insert_provider_graph_provenance,
    insert_runner_effect_dispatch_claim, insert_runner_effect_dispatch_claim_authority,
    insert_sprint_application_admission, insert_sprint_definition,
    insert_sprint_final_verification_admission, insert_sprint_live_state_capture_admission,
    insert_sprint_planning_state, insert_sprint_task_graph,
    insert_task_attempt_runner_effect_intent, insert_task_integration_receipt,
    insert_verification_effect_evidence, insert_verification_receipt, insert_workspace_snapshot,
    io, latest_sprint_phase_event, launch_cleanup_lock_path, ledger_directory_identity,
    ledger_regular_file_identity, load_application_artifact_assembly_from, load_effect_from,
    load_effect_runner_binding, load_event_by_id, load_events,
    load_runner_effect_dispatch_running_boundary, load_runner_launch_intent_from,
    load_runner_session_policy_from, load_sprint_application_admission_from,
    load_sprint_definition, load_sprint_final_verification_admission_envelope_from,
    load_sprint_final_verification_admission_from, load_sprint_inputs,
    load_sprint_live_state_capture_admission_from, load_sprint_live_state_capture_plan_from,
    load_task_attempt_history_from, load_task_integration_evidence_from,
    load_validated_task_attempt_running_boundary, load_verification_effect_evidence_from,
    load_workspace_snapshot_from, next_event_ledger_instance_id, next_sequence, open, params,
    path_scopes_conflict, prepare_database_file, reference_mismatch, register_schema_functions,
    reject_legacy_finish_gap_work, reject_legacy_unproven_work, reject_unresolved_effects_except,
    reject_unresolved_mutation_work, require_current_runner_effect_dispatch_authority,
    require_current_schema, require_final_verification_acceptance_authority,
    require_live_state_capture_attempt_gate, require_recursive_triggers,
    require_successful_effect_kind, run_migrations, runner_effect_dispatch_claim_id,
    runner_launch_cleanup_admission, secure_database_files, sensitive_output_rejection,
    set_user_only_permissions, sprint_exists, sprint_final_verification_phase_source,
    sqlite_integer, task_attempt_authority, thread, validate_attempt_phase_event,
    validate_causation, validate_claimed_final_verification_application_gate,
    validate_claimed_runner_effect_dispatch_authority, validate_draft_base_snapshot,
    validate_effect_for_sprint_phase, validate_effect_proposal_event_shape,
    validate_effect_session_binding, validate_event_for_sprint_phase,
    validate_existing_database_path, validate_formal_admission_intent,
    validate_formal_check_against_admission, validate_fresh_runner_effect_dispatch_authority,
    validate_integration_admission_intent, validate_integration_result_against_admission,
    validate_new_effect_observation, validate_new_event, validate_provider_graph_binding,
    validate_regular_database_file, validate_runner_effect_dispatch_claim_binding,
    validate_runner_effect_observation_authority, validate_sprint_application_admission_intent,
    validate_sprint_final_verification_admission_intent, validate_sprint_phase_transition,
    validate_supplied_effect_payload, validate_task_integration_artifact_binding,
    validate_task_integration_receipt, validate_task_integration_validation_binding,
    validate_task_state_transition, validate_verification_effect_evidence,
    validate_verification_evidence_write_contract, verify_database_integrity, verify_exact_schema,
    verify_user_only_permissions, worker_lease_authority,
};

impl EventLedger {
    /// Opens or creates a ledger at an absolute filesystem path.
    ///
    /// The database uses `WAL` journaling, full synchronization, foreign keys,
    /// schema migrations, and user-only Unix file permissions.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the path is unsafe, `SQLite` cannot be
    /// configured, a migration fails, or the database integrity check fails.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let database_path = canonical_database_path(path.as_ref())?;
        prepare_database_file(&database_path)?;

        let mut connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        register_schema_functions(&connection)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;\
             PRAGMA recursive_triggers = ON;\
             PRAGMA synchronous = FULL;\
             PRAGMA temp_store = MEMORY;\
             PRAGMA trusted_schema = OFF;",
        )?;
        require_recursive_triggers(&connection)?;

        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(LedgerError::WalUnavailable(journal_mode));
        }

        run_migrations(&mut connection)?;
        verify_exact_schema(&connection)?;
        task_attempt_authority::validate_v15_legacy_task_attempt_admission(&connection)?;
        verify_database_integrity(&connection)?;
        secure_database_files(&database_path)?;

        Ok(Self {
            connection,
            database_path,
            read_only: false,
            instance_id: next_event_ledger_instance_id(),
        })
    }

    /// Opens an existing ledger without write, create, or migration authority.
    ///
    /// This is the recovery and inspection path. It verifies the exact schema
    /// version, `WAL` configuration, file permissions, and database integrity,
    /// then permits only load operations.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the file is missing or insecure, `SQLite`
    /// cannot open it read-only, its schema is incompatible, `WAL` is inactive,
    /// or its integrity check fails.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let database_path = canonical_database_path(path.as_ref())?;
        validate_existing_database_path(&database_path)?;
        verify_user_only_permissions(&database_path)?;

        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        register_schema_functions(&connection)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;\
             PRAGMA recursive_triggers = ON;\
             PRAGMA temp_store = MEMORY;\
             PRAGMA trusted_schema = OFF;",
        )?;
        require_recursive_triggers(&connection)?;
        let journal_mode: String =
            connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(LedgerError::WalUnavailable(journal_mode));
        }
        require_current_schema(&connection)?;
        verify_exact_schema(&connection)?;
        task_attempt_authority::validate_v15_legacy_task_attempt_admission(&connection)?;
        verify_database_integrity(&connection)?;

        Ok(Self {
            connection,
            database_path,
            read_only: true,
            instance_id: next_event_ledger_instance_id(),
        })
    }

    /// Returns whether this handle was opened without mutation authority.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Captures the exact existing database file and canonical parent
    /// directory that form this ledger's local state root.
    #[cfg(unix)]
    #[allow(
        dead_code,
        reason = "schema-v37 persists these identities before its dormant native-preparation callback"
    )]
    pub(super) fn current_state_filesystem_identities(
        &self,
    ) -> Result<LedgerStateFilesystemIdentities, LedgerError> {
        validate_existing_database_path(&self.database_path)?;
        verify_user_only_permissions(&self.database_path)?;
        let database_metadata = fs::symlink_metadata(&self.database_path)?;
        let database = ledger_regular_file_identity(&self.database_path, &database_metadata)?;

        let state_root_path =
            self.database_path
                .parent()
                .ok_or_else(|| LedgerError::InvalidDatabasePath {
                    path: self.database_path.clone(),
                    reason: "database path has no state-root parent".into(),
                })?;
        let canonical_state_root = fs::canonicalize(state_root_path)?;
        if canonical_state_root != state_root_path {
            return Err(LedgerError::InvalidDatabasePath {
                path: state_root_path.to_path_buf(),
                reason: "ledger state-root path is not canonical".into(),
            });
        }
        let state_root_metadata = fs::symlink_metadata(&canonical_state_root)?;
        let state_root = ledger_directory_identity(&canonical_state_root, &state_root_metadata)?;
        Ok(LedgerStateFilesystemIdentities {
            database,
            state_root,
        })
    }

    /// Reopens the database and state-root paths and requires their complete
    /// Unix identities to equal the previously retained values.
    #[cfg(unix)]
    #[allow(
        dead_code,
        reason = "schema-v37 invokes this immediately before its dormant native-preparation callback"
    )]
    pub(super) fn revalidate_state_filesystem_identities(
        &self,
        expected: &LedgerStateFilesystemIdentities,
    ) -> Result<(), LedgerError> {
        let observed = self.current_state_filesystem_identities()?;
        if &observed != expected {
            return Err(LedgerError::InvalidDatabasePath {
                path: self.database_path.clone(),
                reason: "ledger database or state-root identity changed while launch/cleanup exclusion was retained"
                    .into(),
            });
        }
        Ok(())
    }

    /// Acquires the cross-process launch/cleanup exclusion on the exact
    /// secured companion inode. It is separate from `SQLite`'s own lock file
    /// and byte-range locks; every ordinary launch-preparation and cleanup
    /// entry point must take this application-level lock.
    #[cfg(unix)]
    pub(super) fn acquire_launch_cleanup_exclusion(
        &self,
    ) -> Result<LaunchCleanupExclusion, LedgerError> {
        validate_existing_database_path(&self.database_path)?;
        verify_user_only_permissions(&self.database_path)?;
        let lock_path = launch_cleanup_lock_path(&self.database_path);
        let descriptor = open(
            &lock_path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io::Error::from)?;
        let file = File::from(descriptor);
        let descriptor_metadata = file.metadata()?;
        validate_regular_database_file(&lock_path, &descriptor_metadata)?;
        set_user_only_permissions(&lock_path)?;
        let deadline = Instant::now() + BUSY_TIMEOUT;
        loop {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(error) => {
                    let error = io::Error::from(error);
                    if error.kind() != io::ErrorKind::WouldBlock {
                        return Err(LedgerError::Io(error));
                    }
                    if Instant::now() >= deadline {
                        return Err(LedgerError::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "timed out after {} ms acquiring launch/cleanup exclusion for {}",
                                BUSY_TIMEOUT.as_millis(),
                                lock_path.display()
                            ),
                        )));
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }
        }

        // Reopen-by-path substitution between validation and lock acquisition
        // must fail closed. The retained descriptor is the lock identity.
        let path_metadata = fs::symlink_metadata(&lock_path)?;
        validate_regular_database_file(&lock_path, &path_metadata)?;
        verify_user_only_permissions(&lock_path)?;
        let descriptor_identity = ledger_regular_file_identity(&lock_path, &descriptor_metadata)?;
        let path_identity = ledger_regular_file_identity(&lock_path, &path_metadata)?;
        if descriptor_identity != path_identity {
            return Err(LedgerError::InvalidDatabasePath {
                path: lock_path,
                reason: "launch/cleanup lock path changed while acquiring exclusion".into(),
            });
        }
        let exclusion = LaunchCleanupExclusion {
            file,
            identity: descriptor_identity,
        };
        exclusion.revalidate_retained_path_identity()?;
        Ok(exclusion)
    }

    #[cfg(not(unix))]
    pub(super) fn acquire_launch_cleanup_exclusion(
        &self,
    ) -> Result<LaunchCleanupExclusion, LedgerError> {
        Err(LedgerError::InvalidDatabasePath {
            path: self.database_path.clone(),
            reason: "live runner launch/cleanup exclusion is supported only on macOS and Linux"
                .into(),
        })
    }

    /// Atomically creates a draft sprint with its exact authenticated base
    /// snapshot and no task graph.
    ///
    /// This is the restart-safe provider-planning entry point. The snapshot
    /// must exactly match both `spec.base_snapshot` and the sprint grant, and
    /// must not postdate draft creation. No effect can be recorded for the
    /// draft unless this transaction commits in full.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when either contract is invalid, the snapshot
    /// identity, grant, or timestamp mismatches, the sprint already exists, or
    /// the atomic durable write fails.
    pub fn create_draft_sprint(
        &mut self,
        spec: &SprintSpec,
        base_snapshot: &WorkspaceSnapshot,
        created_at_unix_ms: u64,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        spec.validate()?;
        base_snapshot.validate()?;
        validate_draft_base_snapshot(spec, base_snapshot, created_at_unix_ms)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_new_sprint(&transaction, &spec.sprint_id)?;
        insert_sprint_definition(&transaction, spec, created_at_unix_ms)?;
        insert_sprint_planning_state(&transaction, spec)?;
        insert_workspace_snapshot(&transaction, &spec.sprint_id, base_snapshot)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Rejects graph attachment without explicit provider-effect provenance.
    ///
    /// This compatibility signature remains source-compatible, but schema v6
    /// never permits it to attach a draft graph. Use
    /// [`Self::attach_task_graph_from_effect`] for production planning.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the sprint is absent or already planned,
    /// and otherwise returns [`LedgerError::PlanningProvenanceRequired`].
    pub fn attach_task_graph(
        &mut self,
        sprint_id: &str,
        _graph: &TaskGraph,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        let (_, existing_graph, _, _) = load_sprint_definition(&self.connection, sprint_id)?;
        if existing_graph.is_some() {
            return Err(LedgerError::ArtifactAlreadyExists {
                entity: "task graph",
                id: sprint_id.to_owned(),
            });
        }
        Err(LedgerError::PlanningProvenanceRequired(
            sprint_id.to_owned(),
        ))
    }

    /// Atomically binds and attaches a graph to exact successful planning
    /// effect evidence.
    ///
    /// The planning effect must be a sprint-scoped `ProviderRequest` for this
    /// sprint and base snapshot, with a successful observation. Its exact
    /// request and evidence preimages are rehashed on read. Evidence must be
    /// the canonical JSON encoding of the strict core [`crate::ProviderResponse`],
    /// whose `PlanningComplete` graph must be semantically equal to `graph`;
    /// canonical re-encoding of that embedded graph must exactly equal the
    /// bytes persisted in the graph record. Provenance and graph share one
    /// transaction, and one effect identifier can bind at most one graph.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent or already-planned sprint, missing
    /// or non-successful effect evidence, wrong effect scope or sprint,
    /// noncanonical/mismatched response bytes, invalid graph, or storage
    /// failure.
    pub fn attach_task_graph_from_effect(
        &mut self,
        sprint_id: &str,
        planning_effect_id: &str,
        graph: &TaskGraph,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, existing_graph, created_at_unix_ms, provenance) =
            load_sprint_definition(&transaction, sprint_id)?;
        if existing_graph.is_some() {
            return Err(LedgerError::ArtifactAlreadyExists {
                entity: "task graph",
                id: sprint_id.to_owned(),
            });
        }
        if provenance != TaskGraphProvenance::NotAttached {
            return Err(LedgerError::Corrupt {
                entity: "task graph provenance",
                detail: "draft sprint has provenance before graph attachment".into(),
            });
        }
        ensure_sprint_not_terminal(&transaction, sprint_id)?;
        graph.validate_for_sprint(&spec)?;
        let base_snapshot =
            load_workspace_snapshot_from(&transaction, sprint_id, &spec.base_snapshot)?;
        validate_draft_base_snapshot(&spec, &base_snapshot, created_at_unix_ms)?;
        let effect = load_effect_from(&transaction, planning_effect_id)?;
        let (observation_id, response_digest) =
            validate_provider_graph_binding(&spec, sprint_id, graph, &effect)?;
        insert_provider_graph_provenance(
            &transaction,
            sprint_id,
            planning_effect_id,
            &observation_id,
            &response_digest,
        )?;
        insert_sprint_task_graph(&transaction, sprint_id, &spec, graph)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Atomically creates an already-planned sprint for compatibility.
    ///
    /// This helper creates the same v6 definition and immutable graph records
    /// in one transaction, so there is no pre-graph interval in which a
    /// provider request could start. Its graph is explicitly marked as direct
    /// trusted input, not provider provenance. New provider-planning flows
    /// should use [`Self::create_draft_sprint`] followed by
    /// [`Self::attach_task_graph_from_effect`].
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when either contract is invalid, the timestamp
    /// is zero or outside `SQLite`'s integer range, serialization fails, or the
    /// sprint identifier already exists.
    pub fn create_sprint(
        &mut self,
        spec: &SprintSpec,
        graph: &TaskGraph,
        created_at_unix_ms: u64,
    ) -> Result<(), LedgerError> {
        self.require_writable()?;
        spec.validate()?;
        graph.validate_for_sprint(spec)?;
        if created_at_unix_ms == 0 {
            return Err(LedgerError::InvalidTimestamp("created_at_unix_ms"));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_new_sprint(&transaction, &spec.sprint_id)?;
        insert_sprint_definition(&transaction, spec, created_at_unix_ms)?;
        insert_sprint_planning_state(&transaction, spec)?;
        insert_direct_graph_provenance(&transaction, &spec.sprint_id)?;
        insert_sprint_task_graph(&transaction, &spec.sprint_id, spec, graph)?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Returns the next sequence that may be appended to a sprint.
    ///
    /// This value is advisory under concurrency. [`Self::append_event`] still
    /// checks the sequence inside an immediate transaction.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::SprintNotFound`] for an unknown sprint or a
    /// database error when the sequence cannot be read.
    pub fn next_sequence(&self, sprint_id: &str) -> Result<u64, LedgerError> {
        if !sprint_exists(&self.connection, sprint_id)? {
            return Err(LedgerError::SprintNotFound(sprint_id.to_owned()));
        }
        next_sequence(&self.connection, sprint_id)
    }

    /// Returns the first unused durable sprint-scoped worker-lease epoch.
    ///
    /// This value is advisory until passed to [`Self::acquire_worker_lease`],
    /// which rechecks it under an immediate transaction.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an unknown or legacy-unproven sprint,
    /// corrupt lease history, or epoch overflow.
    pub fn next_worker_lease_epoch(&self, sprint_id: &str) -> Result<u64, LedgerError> {
        if !sprint_exists(&self.connection, sprint_id)? {
            return Err(LedgerError::SprintNotFound(sprint_id.to_owned()));
        }
        worker_lease_authority::next_epoch(&self.connection, sprint_id)
    }

    /// Legacy worker-lease-only acquisition is unavailable under schema v15.
    ///
    /// One lease acquisition is now inseparable from its exact durable
    /// [`TaskAttempt`]. Call [`Self::acquire_task_attempt`] instead.
    ///
    /// # Errors
    ///
    /// Always returns a fail-closed reference mismatch without writing.
    pub fn acquire_worker_lease(
        &mut self,
        _lease: &WorkerLease,
        _event: &AgentEvent,
    ) -> Result<WorkerLease, LedgerError> {
        self.require_writable()?;
        Err(reference_mismatch(
            "worker lease acquisition",
            "schema v15 requires atomic acquire_task_attempt authority",
        ))
    }

    /// Atomically opens one exact task attempt and appends its matching
    /// `Ready -> Leased` task event.
    ///
    /// The immutable task graph supplies the exact scope set. The transaction
    /// serializes epoch allocation, worker/task cardinality, conservative scope
    /// exclusion, and the event transition before returning authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a malformed, stale, conflicting,
    /// cross-sprint, legacy, non-next, or non-`Ready` acquisition. No lease or
    /// event is retained on any pre-commit failure.
    #[allow(clippy::too_many_lines)] // One transaction closes every lease/event authority race.
    pub fn acquire_task_attempt(
        &mut self,
        lease: &WorkerLease,
        event: &AgentEvent,
    ) -> Result<TaskAttempt, LedgerError> {
        self.require_writable()?;
        lease.validate()?;
        event.validate()?;
        let transition_matches = matches!(
            &event.payload,
            AgentEventKind::TaskStateChanged { from, to }
                if from == "Ready" && to == "Leased"
        );
        if event.sprint_id != lease.sprint_id
            || event.task_id.as_deref() != Some(lease.task_id.as_str())
            || event.worker_id.as_deref() != Some(lease.worker_id.as_str())
            || event.occurred_at_unix_ms != lease.acquired_at_unix_ms
            || !transition_matches
        {
            return Err(reference_mismatch(
                "worker lease acquisition",
                "event must prove the exact sprint/task/worker Ready-to-Leased transition at acquisition time",
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, graph, _, provenance) = load_sprint_definition(&transaction, &lease.sprint_id)?;
        reject_legacy_unproven_work(&lease.sprint_id, &provenance)?;
        reject_unresolved_mutation_work(&transaction, &lease.sprint_id)?;
        reject_legacy_finish_gap_work(&transaction, &lease.sprint_id)?;
        worker_lease_authority::reject_legacy_sprint(&transaction, &lease.sprint_id)?;
        task_attempt_authority::reject_legacy_history(&transaction, &lease.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &lease.sprint_id)?;
        ensure_sprint_running_for_task_work(
            &transaction,
            &lease.sprint_id,
            "worker lease acquisition",
        )?;
        let graph =
            graph.ok_or_else(|| LedgerError::SprintGraphNotAttached(lease.sprint_id.clone()))?;
        let task = graph.task(&lease.task_id).ok_or_else(|| {
            reference_mismatch(
                "worker lease acquisition",
                "lease task is absent from the graph",
            )
        })?;
        if task.path_scopes != lease.path_scopes {
            return Err(reference_mismatch(
                "worker lease acquisition",
                "lease scopes must exactly equal the immutable graph task scopes",
            ));
        }
        let expected_epoch = worker_lease_authority::next_epoch(&transaction, &lease.sprint_id)?;
        if lease.lease_epoch != expected_epoch {
            return Err(reference_mismatch(
                "worker lease acquisition",
                format!(
                    "expected first unused epoch {expected_epoch}, got {}",
                    lease.lease_epoch
                ),
            ));
        }
        let active = worker_lease_authority::load_active(&transaction, &lease.sprint_id)?;
        let workspace_blocking =
            worker_lease_authority::load_workspace_blocking(&transaction, &lease.sprint_id)?;
        if active.len() >= usize::from(spec.max_workers) {
            return Err(reference_mismatch(
                "worker lease acquisition",
                "active lease count has reached the sprint worker ceiling",
            ));
        }
        if active.iter().chain(&workspace_blocking).any(|held| {
            held.path_scopes.iter().any(|held_scope| {
                lease
                    .path_scopes
                    .iter()
                    .any(|proposed| path_scopes_conflict(held_scope, proposed))
            })
        }) {
            return Err(reference_mismatch(
                "worker lease acquisition",
                "lease scopes conflict with an active worker lease",
            ));
        }
        let acquisition_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM worker_lease_acquisitions
             WHERE sprint_id = ?1 AND task_id = ?2",
            params![lease.sprint_id, lease.task_id],
            |row| row.get(0),
        )?;
        let acquisition_count = usize::try_from(acquisition_count)
            .map_err(|_| LedgerError::IntegerOutOfRange("task_attempt.acquisition_count"))?;
        if acquisition_count >= usize::from(spec.budget.max_attempts_per_task) {
            return Err(reference_mismatch(
                "task attempt acquisition",
                "immutable per-task attempt budget is exhausted",
            ));
        }
        let attempt_ordinal =
            task_attempt_authority::next_ordinal(&transaction, &lease.sprint_id, &lease.task_id)?;
        if usize::try_from(attempt_ordinal)
            .ok()
            .and_then(|ordinal| ordinal.checked_sub(1))
            != Some(acquisition_count)
        {
            return Err(LedgerError::Corrupt {
                entity: "task attempt history",
                detail: "attempt ordinal and immutable acquisition count disagree".into(),
            });
        }
        let attempt = TaskAttempt::new(lease.clone(), attempt_ordinal, event.event_id.clone())?;
        let current_task_state = load_events(&transaction, &lease.sprint_id)?
            .into_iter()
            .filter(|stored| stored.task_id.as_deref() == Some(lease.task_id.as_str()))
            .filter_map(|stored| match stored.payload {
                AgentEventKind::TaskStateChanged { to, .. } => Some(to),
                _ => None,
            })
            .next_back();
        if current_task_state.as_deref() != Some("Ready") {
            return Err(reference_mismatch(
                "worker lease acquisition",
                "durable task state is not Ready",
            ));
        }
        validate_task_state_transition(&transaction, &graph, event)?;
        validate_new_event(&transaction, event)?;
        worker_lease_authority::insert_acquisition(&transaction, lease, event)?;
        task_attempt_authority::insert(&transaction, &attempt)?;
        insert_agent_event(&transaction, event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt acquisition",
                recovery_id: attempt.attempt_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt acquisition",
            &attempt.attempt_id,
            |ledger| {
                let stored = task_attempt_authority::load(&ledger.connection, &attempt.attempt_id)?;
                if stored != attempt {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt",
                        detail: "post-commit readback differs from the acquired attempt".into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Loads one exact current or schema-v14-backfilled task attempt.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the attempt is missing, noncanonical, or
    /// disagrees with its exact lease and opening-event authority.
    pub fn load_task_attempt(&self, attempt_id: &str) -> Result<TaskAttempt, LedgerError> {
        task_attempt_authority::load(&self.connection, attempt_id)
    }

    /// Atomically binds an acquired attempt to its exact admitted task-worker
    /// launch and initialized session while entering `Running`.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a stale phase, inactive/crossed attempt,
    /// launch, session, lease, worker, timestamp, or transition event.
    pub fn start_task_attempt(
        &mut self,
        boundary: &TaskAttemptRunningBoundary,
        event: &AgentEvent,
    ) -> Result<TaskAttemptRunningBoundary, LedgerError> {
        self.require_writable()?;
        boundary.validate()?;
        event.validate()?;
        let attempt = &boundary.attempt;
        let lease = &attempt.worker_lease;
        let matches = matches!(
            &event.payload,
            AgentEventKind::TaskStateChanged { from, to }
                if from == "Leased" && to == "Running"
        );
        if event.sprint_id != lease.sprint_id
            || event.task_id.as_deref() != Some(lease.task_id.as_str())
            || event.worker_id.as_deref() != Some(lease.worker_id.as_str())
            || boundary.transition_event_id != event.event_id
            || boundary.started_at_unix_ms != event.occurred_at_unix_ms
            || !matches
        {
            return Err(reference_mismatch(
                "task attempt Running boundary",
                "event must exactly match the attempt Leased-to-Running transition",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        task_attempt_authority::require_exact(&transaction, attempt)?;
        let existing_boundary_id = transaction
            .query_row(
                "SELECT boundary_id
                 FROM task_attempt_running_boundaries
                 WHERE attempt_id = ?1 OR boundary_id = ?2",
                params![attempt.attempt_id, boundary.boundary_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_boundary_id) = existing_boundary_id {
            let stored =
                task_attempt_authority::load_running_boundary(&transaction, &existing_boundary_id)?;
            let stored_event = load_event_by_id(&transaction, &stored.transition_event_id)?;
            if stored == *boundary && stored_event == *event {
                transaction.commit()?;
                return Ok(stored);
            }
            return Err(reference_mismatch(
                "task attempt Running boundary",
                "attempt or boundary identity is already bound to different authority",
            ));
        }
        if current_task_state(&transaction, &lease.sprint_id, &lease.task_id)? != TaskState::Leased
        {
            return Err(reference_mismatch(
                "task attempt Running boundary",
                "durable task state is not Leased",
            ));
        }
        validate_new_event(&transaction, event)?;
        task_attempt_authority::insert_running_boundary(&transaction, boundary)?;
        insert_agent_event(&transaction, event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt Running boundary",
                recovery_id: boundary.boundary_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt Running boundary",
            &boundary.boundary_id,
            |ledger| {
                let stored = load_validated_task_attempt_running_boundary(
                    &ledger.connection,
                    &boundary.boundary_id,
                )?;
                if stored != *boundary {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt Running boundary",
                        detail: "post-commit readback differs from admitted authority".into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Loads one exact immutable `Leased -> Running` boundary.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the boundary is missing, noncanonical, or
    /// disagrees with its attempt, launch, session, event, or indexed fields.
    pub fn load_task_attempt_running_boundary(
        &self,
        boundary_id: &str,
    ) -> Result<TaskAttemptRunningBoundary, LedgerError> {
        load_validated_task_attempt_running_boundary(&self.connection, boundary_id)
    }

    /// Atomically seals one exact Running attempt and enters `Verifying`.
    ///
    /// The boundary retains the complete ordered set of all earlier
    /// non-cleanup effects and their known terminal observations. The state
    /// event, boundary, and ordered links commit as one unit.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a stale phase, nonterminal/unknown earlier
    /// effect, crossed attempt/launch/session/change set/snapshot/event, or a
    /// conflicting replay.
    pub fn transition_task_attempt_to_verifying(
        &mut self,
        boundary: &TaskAttemptVerificationBoundary,
        event: &AgentEvent,
    ) -> Result<TaskAttemptVerificationBoundary, LedgerError> {
        self.require_writable()?;
        boundary.validate()?;
        event.validate()?;
        validate_attempt_phase_event(
            &boundary.attempt,
            &boundary.transition_event_id,
            boundary.sealed_at_unix_ms,
            TaskState::Running,
            TaskState::Verifying,
            event,
            "task attempt verification boundary",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        task_attempt_authority::require_exact(&transaction, &boundary.attempt)?;
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT boundary_id FROM task_attempt_verification_boundaries
                 WHERE boundary_id = ?1 OR attempt_id = ?2
                    OR transition_event_id = ?3",
                params![
                    boundary.boundary_id,
                    boundary.attempt.attempt_id,
                    boundary.transition_event_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored =
                task_attempt_authority::load_verification_boundary(&transaction, &existing_id)?;
            let stored_event = load_event_by_id(&transaction, &stored.transition_event_id)?;
            if stored == *boundary && stored_event == *event {
                transaction.commit()?;
                return Ok(stored);
            }
            return Err(reference_mismatch(
                "task attempt verification boundary",
                "boundary, attempt, or transition identity is already bound differently",
            ));
        }
        if current_task_state(
            &transaction,
            &boundary.attempt.worker_lease.sprint_id,
            &boundary.attempt.worker_lease.task_id,
        )? != TaskState::Running
        {
            return Err(reference_mismatch(
                "task attempt verification boundary",
                "durable task state is not Running",
            ));
        }
        validate_new_event(&transaction, event)?;
        task_attempt_authority::insert_verification_boundary(&transaction, boundary)?;
        insert_agent_event(&transaction, event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt verification boundary",
                recovery_id: boundary.boundary_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt verification boundary",
            &boundary.boundary_id,
            |ledger| {
                let stored =
                    ledger.load_task_attempt_verification_boundary(&boundary.boundary_id)?;
                if stored != *boundary {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt verification boundary",
                        detail: "post-commit readback differs from admitted authority".into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Loads one exact immutable `Running -> Verifying` boundary.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when canonical bytes, indexed fields, ordered
    /// terminal-effect links, or the exact transition event disagree.
    pub fn load_task_attempt_verification_boundary(
        &self,
        boundary_id: &str,
    ) -> Result<TaskAttemptVerificationBoundary, LedgerError> {
        let boundary =
            task_attempt_authority::load_verification_boundary(&self.connection, boundary_id)?;
        let event = load_event_by_id(&self.connection, &boundary.transition_event_id)?;
        validate_attempt_phase_event(
            &boundary.attempt,
            &boundary.transition_event_id,
            boundary.sealed_at_unix_ms,
            TaskState::Running,
            TaskState::Verifying,
            &event,
            "task attempt verification boundary",
        )
        .map_err(|error| LedgerError::Corrupt {
            entity: "task attempt verification boundary",
            detail: error.to_string(),
        })?;
        Ok(boundary)
    }

    /// Derives an Applied-branch live-state capture plan from the exact current
    /// durable high-water cut and complete prior runner-cleanup set.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when any supplied identity is absent or crossed,
    /// the cut is not the current latest event, or the existing runner set is
    /// not completely cleaned.
    pub fn derive_applied_live_state_capture_plan(
        &self,
        cut: SprintLiveStateCapturePlanCut,
        compiled_policy: &CompiledExecutionPolicy,
        sprint_id: &str,
        final_verification_receipt_id: &str,
        application_receipt_id: &str,
        rollback_reference_id: &str,
    ) -> Result<SprintLiveStateCapturePlan, LedgerError> {
        derive_applied_live_state_capture_plan_from(
            &self.connection,
            cut,
            compiled_policy,
            sprint_id,
            final_verification_receipt_id,
            application_receipt_id,
            rollback_reference_id,
        )
    }

    /// Derives a VerifiedNoOp-branch live-state capture plan from the exact
    /// explicit-empty `TaskDone` source and current durable high-water cut.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the integration receipt is not the sole
    /// exact empty `TaskDone` winner, the final verification is crossed, or
    /// prior runner cleanup is incomplete.
    pub fn derive_verified_no_op_live_state_capture_plan(
        &self,
        cut: SprintLiveStateCapturePlanCut,
        compiled_policy: &CompiledExecutionPolicy,
        sprint_id: &str,
        final_verification_receipt_id: &str,
        task_integration_receipt_id: &str,
    ) -> Result<SprintLiveStateCapturePlan, LedgerError> {
        derive_verified_no_op_live_state_capture_plan_from(
            &self.connection,
            cut,
            compiled_policy,
            sprint_id,
            final_verification_receipt_id,
            task_integration_receipt_id,
        )
    }

    /// Loads one exact immutable schema-v23 capture plan.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent, noncanonical, crossed, or
    /// source-inconsistent plan.
    pub fn load_sprint_live_state_capture_plan(
        &self,
        plan_id: &str,
    ) -> Result<SprintLiveStateCapturePlan, LedgerError> {
        load_sprint_live_state_capture_plan_from(&self.connection, plan_id)
    }

    /// Atomically pre-admits one descriptor-relative live-state capture and
    /// returns dispatch authority only for a fresh exact post-commit readback.
    ///
    /// Exact replay returns [`SprintLiveStateCaptureDispatchAdmission::Existing`]
    /// without recreating a permit. The plan, semantic launch/session,
    /// still-open cleanup obligation, canonical request, effect subtype,
    /// proposal event, binding, and intent are validated in one immediate
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a crossed plan/request/lifecycle, stale
    /// source branch, unresolved prior work, noncanonical event or bytes, or
    /// any duplicate identity bound differently.
    #[allow(clippy::too_many_lines)]
    pub fn admit_sprint_live_state_capture_for_dispatch(
        &mut self,
        admission: &SprintLiveStateCaptureAdmission,
        intent: &EffectIntent,
        proposed_event: &AgentEvent,
    ) -> Result<SprintLiveStateCaptureDispatchAdmission, LedgerError> {
        self.require_writable()?;
        admission.validate()?;
        intent.validate()?;
        proposed_event.validate()?;
        let request_bytes = encode("sprint live-state capture request", &admission.request)?;
        validate_supplied_effect_payload(
            "sprint live-state capture request",
            &intent.effect_id,
            &request_bytes,
            &intent.request_digest,
            MAX_EFFECT_REQUEST_BYTES,
        )?;
        if intent.contract_version != admission.contract_version
            || intent.kind != EffectKind::CaptureWorkspaceState
            || intent.effect_id != admission.effect_id
            || intent.sprint_id != admission.plan.sprint_id
            || intent.task_id.is_some()
            || intent.worker_id.is_some()
            || intent.worker_lease.is_some()
            || intent.input_snapshot != admission.plan.expected_snapshot
            || intent.policy_hash != admission.plan.policy_hash
            || intent.request_digest != admission.request.request_digest()?
            || intent.created_at_unix_ms != admission.admitted_at_unix_ms
        {
            return Err(reference_mismatch(
                "sprint live-state capture admission",
                "capture intent differs from the exact admitted request, plan, policy, or time",
            ));
        }
        validate_effect_proposal_event_shape(intent, proposed_event)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT admission_id FROM sprint_live_state_capture_admissions
                 WHERE admission_id = ?1 OR plan_id = ?2 OR effect_id = ?3",
                params![
                    admission.admission_id,
                    admission.plan.plan_id,
                    admission.effect_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored = load_sprint_live_state_capture_admission_from(&transaction, &existing_id)?;
            let effect = load_effect_from(&transaction, &stored.effect_id)?;
            if stored == *admission
                && effect.intent == *intent
                && effect.request_bytes == request_bytes
                && effect.proposed_event == *proposed_event
            {
                transaction.commit()?;
                return Ok(SprintLiveStateCaptureDispatchAdmission::Existing {
                    admission: stored,
                    effect,
                });
            }
            return Err(reference_mismatch(
                "sprint live-state capture admission",
                "admission, plan, or effect identity is already bound differently",
            ));
        }
        require_live_state_capture_attempt_gate(&transaction, &admission.plan.sprint_id, None)?;
        let stored_plan =
            load_sprint_live_state_capture_plan_from(&transaction, &admission.plan.plan_id)?;
        if stored_plan != admission.plan {
            return Err(reference_mismatch(
                "sprint live-state capture admission",
                "admission plan differs from exact durable rederivation",
            ));
        }
        let (spec, graph, sprint_created_at, provenance) =
            load_sprint_definition(&transaction, &admission.plan.sprint_id)?;
        reject_legacy_unproven_work(&admission.plan.sprint_id, &provenance)?;
        reject_unresolved_mutation_work(&transaction, &admission.plan.sprint_id)?;
        reject_legacy_finish_gap_work(&transaction, &admission.plan.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &admission.plan.sprint_id)?;
        if graph.is_none() || admission.admitted_at_unix_ms < sprint_created_at {
            return Err(reference_mismatch(
                "sprint live-state capture admission",
                "capture requires an attached graph and cannot predate its sprint",
            ));
        }
        validate_effect_for_sprint_phase(&spec, graph.as_ref(), intent)?;
        let snapshot = load_workspace_snapshot_from(
            &transaction,
            &admission.plan.sprint_id,
            &admission.plan.expected_snapshot,
        )?;
        if snapshot.created_at_unix_ms > admission.admitted_at_unix_ms {
            return Err(reference_mismatch(
                "sprint live-state capture admission",
                "capture admission predates its expected snapshot",
            ));
        }
        let (launch, _) = load_runner_launch_intent_from(
            &transaction,
            &admission.plan.sprint_id,
            &admission.runner_launch_id,
        )?;
        let (session, _) = load_runner_session_policy_from(
            &transaction,
            &admission.plan.sprint_id,
            &admission.runner_session_id,
        )?;
        let cleanup = runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &admission.plan.sprint_id,
            &admission.runner_launch_id,
        )?;
        runner_launch_cleanup_admission::require_preparation_allows_session_work(
            &transaction,
            &admission.plan.sprint_id,
            &admission.runner_launch_id,
        )?;
        let latest = load_events(&transaction, &admission.plan.sprint_id)?
            .pop()
            .ok_or_else(|| {
                reference_mismatch(
                    "sprint live-state capture admission",
                    "capture requires its retained cleanup proposal event",
                )
            })?;
        let required_phase = match admission.plan.branch {
            LiveStateCaptureBranch::Applied { .. } => SprintState::Applying,
            LiveStateCaptureBranch::VerifiedNoOp { .. } => SprintState::FinalVerification,
            LiveStateCaptureBranch::KnownPreApplicationTerminal { .. } => unreachable!(),
        };
        if launch.purpose != RunnerSessionPurpose::LiveStateVerifier
            || session.purpose != RunnerSessionPurpose::LiveStateVerifier
            || launch.session_id != session.session_id
            || launch.launch_id != session.launch_id
            || launch.launch_id != admission.runner_launch_id
            || session.session_id != admission.runner_session_id
            || launch.policy_hash != admission.plan.policy_hash
            || session.policy_hash != admission.plan.policy_hash
            || launch.grant_hash != admission.plan.grant_hash
            || session.grant_hash != admission.plan.grant_hash
            || current_sprint_phase_state(&transaction, &admission.plan.sprint_id)?
                != required_phase
            || latest.event_id != cleanup.cleanup_effect.proposed_event.event_id
            || latest.sequence != admission.plan.source_event_sequence + 1
            || intent.causation_event_id.as_deref() != Some(latest.event_id.as_str())
            || admission.admitted_at_unix_ms < session.registered_at_unix_ms
        {
            return Err(reference_mismatch(
                "sprint live-state capture admission",
                "plan, phase, cleanup proposal, launch, session, or intent causation is crossed",
            ));
        }
        let unresolved_other = transaction.query_row(
            "SELECT EXISTS (
                 SELECT 1
                 FROM effect_intents unresolved
                 LEFT JOIN effect_observations terminal
                   ON terminal.effect_id = unresolved.effect_id
                 WHERE unresolved.sprint_id = ?1
                   AND unresolved.effect_id != ?2
                   AND (terminal.effect_id IS NULL OR terminal.outcome = 'Unknown')
             )",
            params![
                admission.plan.sprint_id,
                cleanup.cleanup_effect.intent.effect_id
            ],
            |row| row.get::<_, bool>(0),
        )?;
        if unresolved_other {
            return Err(reference_mismatch(
                "sprint live-state capture admission",
                "only the new verifier cleanup obligation may remain unresolved",
            ));
        }
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM effect_intents WHERE effect_id = ?1",
            "effect intent",
            &intent.effect_id,
        )?;
        if let Some(existing_effect_id) = transaction
            .query_row(
                "SELECT effect_id FROM effect_intents
                 WHERE sprint_id = ?1 AND idempotency_key = ?2",
                params![intent.sprint_id, intent.idempotency_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect idempotency key",
                id: format!(
                    "{}:{} (effect {existing_effect_id})",
                    intent.sprint_id, intent.idempotency_key
                ),
            });
        }
        validate_new_event(&transaction, proposed_event)?;
        insert_sprint_live_state_capture_admission(&transaction, admission)?;
        transaction.execute(
            "INSERT INTO live_state_capture_effect_kinds (
                effect_id, sprint_id, admission_id, semantic_kind, contract_version
             ) VALUES (?1, ?2, ?3, 'CaptureWorkspaceState', ?4)",
            params![
                intent.effect_id,
                intent.sprint_id,
                admission.admission_id,
                i64::from(intent.contract_version),
            ],
        )?;
        transaction.execute(
            "INSERT INTO effect_session_bindings (
                effect_id, sprint_id, launch_id, session_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                intent.effect_id,
                intent.sprint_id,
                launch.launch_id,
                session.session_id,
                i64::from(intent.contract_version),
            ],
        )?;
        insert_agent_event(&transaction, proposed_event)?;
        insert_effect_request_payload(&transaction, intent, &request_bytes)?;
        insert_effect_intent(&transaction, intent, &proposed_event.event_id)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "sprint live-state capture admission",
                recovery_id: admission.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "sprint live-state capture admission",
            &admission.effect_id,
            |ledger| {
                let stored = load_sprint_live_state_capture_admission_from(
                    &ledger.connection,
                    &admission.admission_id,
                )?;
                let effect = load_effect_from(&ledger.connection, &admission.effect_id)?;
                let binding = load_effect_runner_binding(&ledger.connection, &effect.intent)?;
                let stored_session = binding.session.ok_or_else(|| LedgerError::Corrupt {
                    entity: "sprint live-state capture admission",
                    detail: "fresh capture effect lacks initialized semantic session".into(),
                })?;
                if stored != *admission
                    || effect.intent != *intent
                    || effect.request_bytes != request_bytes
                    || effect.proposed_event != *proposed_event
                    || effect.dispatch_claim.is_some()
                    || effect.observation.is_some()
                    || binding.launch != launch
                    || stored_session != session
                {
                    return Err(LedgerError::Corrupt {
                        entity: "sprint live-state capture admission",
                        detail: "fresh post-commit readback differs from exact capture authority"
                            .into(),
                    });
                }
                Ok(SprintLiveStateCaptureDispatchAdmission::Fresh {
                    admission: stored.clone(),
                    effect: effect.clone(),
                    permit: FreshLiveStateCaptureDispatchPermit {
                        effect,
                        launch: binding.launch,
                        session: stored_session,
                        admission: Box::new(stored),
                        ledger_instance_id: ledger.instance_id,
                    },
                })
            },
        )
    }

    /// Loads one exact immutable live-state capture admission.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent, crossed, or noncanonical admission.
    pub fn load_sprint_live_state_capture_admission(
        &self,
        admission_id: &str,
    ) -> Result<SprintLiveStateCaptureAdmission, LedgerError> {
        load_sprint_live_state_capture_admission_from(&self.connection, admission_id)
    }

    /// Atomically enters sprint `FinalVerification` and pre-admits its exact
    /// repository-wide command effect.
    ///
    /// The final snapshot is recomputed from the complete `TaskDone` integration
    /// chain. The phase event, normalized admission, final-verifier binding,
    /// canonical command request, proposal, and effect intent commit together.
    /// Only a fresh post-commit exact readback returns a move-only dispatch
    /// permit; exact replay and reopen return `Existing` without reminting.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for incomplete task closure, a noncontiguous
    /// integration chain, stale/crossed phase event, snapshot, command, effect,
    /// launch/session, policy, timestamp, replay, or storage authority.
    #[allow(clippy::too_many_lines)]
    pub fn admit_sprint_final_verification_for_dispatch(
        &mut self,
        admission: &SprintFinalVerificationAdmission,
        phase_event: &AgentEvent,
        intent: &EffectIntent,
        proposed_event: &AgentEvent,
    ) -> Result<SprintFinalVerificationDispatchAdmission, LedgerError> {
        self.admit_sprint_final_verification_for_dispatch_inner(
            admission,
            phase_event,
            intent,
            proposed_event,
            None,
        )
    }

    /// Schema-v27 final-verification admission that commits the exact capture
    /// intent with the phase, verifier binding, and `RunCommand` effect.
    ///
    /// # Errors
    ///
    /// Returns final-verification admission errors plus capture-source,
    /// private-state, replay, and durable-readback mismatches.
    pub fn admit_sprint_final_verification_with_output_capture_for_dispatch(
        &mut self,
        admission: &SprintFinalVerificationAdmission,
        phase_event: &AgentEvent,
        intent: &EffectIntent,
        proposed_event: &AgentEvent,
        output_capture_intent: &CommandOutputCaptureIntentV1,
    ) -> Result<SprintFinalVerificationDispatchAdmission, LedgerError> {
        self.admit_sprint_final_verification_for_dispatch_inner(
            admission,
            phase_event,
            intent,
            proposed_event,
            Some(output_capture_intent),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn admit_sprint_final_verification_for_dispatch_inner(
        &mut self,
        admission: &SprintFinalVerificationAdmission,
        phase_event: &AgentEvent,
        intent: &EffectIntent,
        proposed_event: &AgentEvent,
        output_capture_intent: Option<&CommandOutputCaptureIntentV1>,
    ) -> Result<SprintFinalVerificationDispatchAdmission, LedgerError> {
        self.require_writable()?;
        admission.validate()?;
        phase_event.validate()?;
        intent.validate()?;
        proposed_event.validate()?;
        let command_bytes = encode("final-verification command", &admission.command)?;
        validate_supplied_effect_payload(
            "final-verification command",
            &intent.effect_id,
            &command_bytes,
            &intent.request_digest,
            MAX_EFFECT_REQUEST_BYTES,
        )?;
        validate_sprint_final_verification_admission_intent(admission, phase_event, intent)?;
        validate_effect_proposal_event_shape(intent, proposed_event)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT admission_id FROM sprint_final_verification_admissions
                 WHERE admission_id = ?1 OR effect_id = ?2
                    OR sprint_phase_event_id = ?3",
                params![
                    admission.admission_id,
                    admission.effect_id,
                    admission.sprint_phase_event_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored = load_sprint_final_verification_admission_from(&transaction, &existing_id)?;
            let stored_phase = load_event_by_id(&transaction, &stored.sprint_phase_event_id)?;
            let effect = load_effect_from(&transaction, &stored.effect_id)?;
            if stored == *admission
                && stored_phase == *phase_event
                && effect.intent == *intent
                && effect.request_bytes == command_bytes
                && effect.proposed_event == *proposed_event
            {
                if let Some(expected_capture) = output_capture_intent {
                    let capture = command_output_capture_authority::load_from_effect(
                        &transaction,
                        &effect.intent.effect_id,
                    )?
                    .ok_or_else(|| {
                        reference_mismatch(
                            "sprint final-verification capture admission",
                            "existing final-verification effect predates v27 capture authority",
                        )
                    })?;
                    if capture.intent != *expected_capture {
                        return Err(reference_mismatch(
                            "sprint final-verification capture admission",
                            "existing capture is bound differently",
                        ));
                    }
                }
                transaction.commit()?;
                return Ok(SprintFinalVerificationDispatchAdmission::Existing {
                    admission: stored,
                    effect,
                });
            }
            return Err(reference_mismatch(
                "sprint final-verification admission",
                "admission, phase event, or effect identity is already bound differently",
            ));
        }

        let (spec, graph, sprint_created_at_unix_ms, provenance) =
            load_sprint_definition(&transaction, &admission.sprint_id)?;
        reject_legacy_unproven_work(&admission.sprint_id, &provenance)?;
        reject_unresolved_mutation_work(&transaction, &admission.sprint_id)?;
        reject_legacy_finish_gap_work(&transaction, &admission.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &admission.sprint_id)?;
        if graph.is_none() || sprint_created_at_unix_ms > admission.admitted_at_unix_ms {
            return Err(reference_mismatch(
                "sprint final-verification admission",
                "final verification requires an attached graph and cannot predate its sprint",
            ));
        }
        validate_effect_for_sprint_phase(&spec, graph.as_ref(), intent)?;
        let derived_snapshot =
            derive_sprint_final_verification_snapshot(&transaction, &admission.sprint_id)?;
        if derived_snapshot != admission.final_snapshot {
            return Err(reference_mismatch(
                "sprint final-verification admission",
                "caller snapshot differs from the complete TaskDone integration chain",
            ));
        }
        let snapshot = load_workspace_snapshot_from(
            &transaction,
            &admission.sprint_id,
            &admission.final_snapshot,
        )?;
        if snapshot.created_at_unix_ms > admission.admitted_at_unix_ms {
            return Err(reference_mismatch(
                "sprint final-verification admission",
                "admission predates its exact final snapshot",
            ));
        }
        validate_sprint_phase_transition(&transaction, phase_event)?;
        validate_new_event(&transaction, phase_event)?;
        let phase_source =
            sprint_final_verification_phase_source(phase_event).ok_or_else(|| {
                reference_mismatch(
                    "sprint final-verification admission",
                    "phase source changed after admission intent validation",
                )
            })?;
        require_final_verification_acceptance_authority(
            &transaction,
            phase_source,
            &admission.sprint_id,
            &admission.final_snapshot,
            admission.admitted_at_unix_ms,
        )?;
        let session =
            validate_effect_session_binding(&transaction, intent, &admission.runner_session_id)?;
        let (launch, _) = load_runner_launch_intent_from(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        if session.purpose != RunnerSessionPurpose::FinalVerifier
            || launch.purpose != RunnerSessionPurpose::FinalVerifier
            || session.launch_id != admission.runner_launch_id
            || launch.session_id != admission.runner_session_id
            || session.policy_hash != intent.policy_hash
            || launch.policy_hash != intent.policy_hash
        {
            return Err(reference_mismatch(
                "sprint final-verification admission",
                "effect is not bound to the exact admitted FinalVerifier launch and session",
            ));
        }
        runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        runner_launch_cleanup_admission::require_preparation_allows_session_work(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM effect_intents WHERE effect_id = ?1",
            "effect intent",
            &intent.effect_id,
        )?;
        if let Some(existing_effect_id) = transaction
            .query_row(
                "SELECT effect_id FROM effect_intents
                 WHERE sprint_id = ?1 AND idempotency_key = ?2",
                params![intent.sprint_id, intent.idempotency_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect idempotency key",
                id: format!(
                    "{}:{} (effect {existing_effect_id})",
                    intent.sprint_id, intent.idempotency_key
                ),
            });
        }

        insert_agent_event(&transaction, phase_event)?;
        insert_sprint_final_verification_admission(&transaction, admission, &command_bytes)?;
        validate_new_event(&transaction, proposed_event)?;
        transaction.execute(
            "INSERT INTO effect_session_bindings (
                effect_id, sprint_id, launch_id, session_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                intent.effect_id,
                intent.sprint_id,
                launch.launch_id,
                session.session_id,
                i64::from(intent.contract_version),
            ],
        )?;
        let capture_schema = command_output_capture_authority::schema_is_installed(&transaction)?;
        match (output_capture_intent, capture_schema) {
            (None, true) => {
                return Err(reference_mismatch(
                    "sprint final-verification capture admission",
                    "new final-verification commands require caller-preallocated v27 capture authority",
                ));
            }
            (Some(_), false) => {
                return Err(reference_mismatch(
                    "sprint final-verification capture admission",
                    "capture authority requires the installed v27 schema",
                ));
            }
            (Some(output_capture_intent), true) => {
                output_capture_intent.validate()?;
                if output_capture_intent.source.sprint_id != intent.sprint_id
                    || output_capture_intent.source.effect_id != intent.effect_id
                    || output_capture_intent.source.runner_launch_id != launch.launch_id
                    || output_capture_intent.source.runner_session_id != session.session_id
                    || output_capture_intent.source.request_digest != intent.request_digest
                    || output_capture_intent.private_state_digest != launch.private_state_digest
                    || output_capture_intent.private_state_digest != session.private_state_digest
                    || output_capture_intent.created_at_unix_ms != intent.created_at_unix_ms
                {
                    return Err(reference_mismatch(
                        "sprint final-verification capture admission",
                        "capture differs from exact command, request, verifier, private state, or timestamp",
                    ));
                }
                command_output_capture_authority::insert_intent(
                    &transaction,
                    output_capture_intent,
                )?;
            }
            (None, false) => {}
        }
        insert_agent_event(&transaction, proposed_event)?;
        insert_effect_request_payload(&transaction, intent, &command_bytes)?;
        insert_finish_effect_kind(&transaction, intent)?;
        insert_effect_intent(&transaction, intent, &proposed_event.event_id)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "sprint final-verification admission",
                recovery_id: admission.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "sprint final-verification admission",
            &admission.effect_id,
            |ledger| {
                let stored =
                    ledger.load_sprint_final_verification_admission(&admission.admission_id)?;
                let stored_phase =
                    load_event_by_id(&ledger.connection, &stored.sprint_phase_event_id)?;
                let effect = load_effect_from(&ledger.connection, &stored.effect_id)?;
                let binding = load_effect_runner_binding(&ledger.connection, &effect.intent)?;
                let stored_session = binding.session.ok_or_else(|| LedgerError::Corrupt {
                    entity: "fresh sprint final-verification dispatch permit",
                    detail: "effect lacks initialized final-verifier session".into(),
                })?;
                if stored != *admission
                    || stored_phase != *phase_event
                    || effect.intent != *intent
                    || effect.request_bytes != command_bytes
                    || effect.proposed_event != *proposed_event
                    || effect.dispatch_claim.is_some()
                    || effect.observation.is_some()
                    || binding.launch != launch
                    || stored_session != session
                    || latest_sprint_phase_event(&ledger.connection, &admission.sprint_id)?.as_ref()
                        != Some(phase_event)
                {
                    return Err(LedgerError::Corrupt {
                        entity: "fresh sprint final-verification dispatch permit",
                        detail: "post-commit readback differs from the exact fresh phase authority"
                            .into(),
                    });
                }
                let capture = command_output_capture_authority::load_from_effect(
                    &ledger.connection,
                    &effect.intent.effect_id,
                )?;
                match (output_capture_intent, capture.as_ref()) {
                    (Some(expected), Some(capture))
                        if capture.intent == *expected
                            && capture.acquired.is_none()
                            && capture.terminal.is_none() => {}
                    (None, None) => {}
                    _ => {
                        return Err(LedgerError::Corrupt {
                            entity: "fresh sprint final-verification dispatch permit",
                            detail:
                                "fresh final-verification capture differs from its schema authority"
                                    .into(),
                        });
                    }
                }
                let sensitive_output_detection_policy =
                    sensitive_output_rejection::load_policy_for_effect(
                        &ledger.connection,
                        &effect.intent.effect_id,
                    )?;
                Ok(SprintFinalVerificationDispatchAdmission::Fresh {
                    admission: stored.clone(),
                    effect: effect.clone(),
                    permit: FreshFinalVerificationDispatchPermit {
                        effect,
                        launch: binding.launch,
                        session: stored_session,
                        admission: stored,
                        output_capture_intent: output_capture_intent.cloned(),
                        sensitive_output_detection_policy,
                        ledger_instance_id: ledger.instance_id,
                    },
                })
            },
        )
    }

    /// Loads one exact normalized sprint final-verification admission.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent, noncanonical, crossed, or
    /// phase-lineage-invalid admission.
    pub fn load_sprint_final_verification_admission(
        &self,
        admission_id: &str,
    ) -> Result<SprintFinalVerificationAdmission, LedgerError> {
        load_sprint_final_verification_admission_from(&self.connection, admission_id)
    }

    /// Computes the gate-one application artifact exclusively from durable
    /// `TaskDone` winners and exact typed integration evidence.
    ///
    /// This is read-only. An empty sole change set is classified as
    /// `VerifiedNoOpRequired`, and multiple winners are explicitly unsupported;
    /// neither case can create an application request or effect.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for absent/crossed final-verification evidence,
    /// incomplete cleanup, noncontiguous `TaskDone` authority, or corrupt typed
    /// integration provenance.
    pub fn assess_sprint_application_preparation(
        &self,
        sprint_id: &str,
        final_verification_receipt_id: &str,
        assembly_id: &str,
        assembled_at_unix_ms: u64,
    ) -> Result<SprintApplicationPreparation, LedgerError> {
        let gate = validate_claimed_final_verification_application_gate(
            &self.connection,
            sprint_id,
            final_verification_receipt_id,
        )?;
        gate.validate_cut(None, assembled_at_unix_ms)?;
        derive_sprint_application_preparation(
            &self.connection,
            sprint_id,
            final_verification_receipt_id,
            assembly_id,
            assembled_at_unix_ms,
        )
    }

    /// Atomically advances `FinalVerification -> Applying` and pre-admits the
    /// exact gate-one artifact-bound application effect.
    ///
    /// The assembly is derived internally from exactly one `TaskDone` winner.
    /// The passing claimed final verification, its final-verifier runner and
    /// command cleanup, the trusted-applier launch/session/policy/grant, the
    /// phase event, normalized assembly/source/admission rows, canonical
    /// request, proposal, and effect intent commit together. Exact replay is
    /// readback-only and returns no execution permit.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a no-op or multi-source assembly, stale phase,
    /// unresolved work, active lease, crossed final receipt, launch, session,
    /// policy, grant, request, effect, event, timestamp, or storage authority.
    #[allow(clippy::too_many_lines)]
    pub fn admit_sprint_application_for_dispatch(
        &mut self,
        admission: &SprintApplicationAdmission,
        phase_event: &AgentEvent,
        intent: &EffectIntent,
        proposed_event: &AgentEvent,
    ) -> Result<SprintApplicationDispatchAdmission, LedgerError> {
        self.require_writable()?;
        admission.validate()?;
        phase_event.validate()?;
        intent.validate()?;
        proposed_event.validate()?;
        let request_bytes = encode("application request", &admission.request)?;
        validate_supplied_effect_payload(
            "application request",
            &intent.effect_id,
            &request_bytes,
            &intent.request_digest,
            MAX_EFFECT_REQUEST_BYTES,
        )?;
        validate_sprint_application_admission_intent(admission, phase_event, intent)?;
        validate_effect_proposal_event_shape(intent, proposed_event)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT admission_id FROM sprint_application_admissions
                 WHERE admission_id = ?1 OR effect_id = ?2
                    OR sprint_phase_event_id = ?3 OR artifact_assembly_id = ?4",
                params![
                    admission.admission_id,
                    admission.effect_id,
                    admission.sprint_phase_event_id,
                    admission.artifact_assembly_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored = load_sprint_application_admission_from(&transaction, &existing_id)?;
            let assembly = load_application_artifact_assembly_from(
                &transaction,
                &stored.artifact_assembly_id,
            )?;
            let stored_phase = load_event_by_id(&transaction, &stored.sprint_phase_event_id)?;
            let effect = load_effect_from(&transaction, &stored.effect_id)?;
            if stored == *admission
                && stored_phase == *phase_event
                && effect.intent == *intent
                && effect.request_bytes == request_bytes
                && effect.proposed_event == *proposed_event
            {
                transaction.commit()?;
                return Ok(SprintApplicationDispatchAdmission::Existing {
                    admission: stored,
                    assembly,
                    effect,
                });
            }
            return Err(reference_mismatch(
                "sprint application admission",
                "admission, assembly, phase event, or effect identity is already bound differently",
            ));
        }

        let (spec, graph, sprint_created_at_unix_ms, provenance) =
            load_sprint_definition(&transaction, &admission.sprint_id)?;
        reject_legacy_unproven_work(&admission.sprint_id, &provenance)?;
        reject_unresolved_mutation_work(&transaction, &admission.sprint_id)?;
        reject_legacy_finish_gap_work(&transaction, &admission.sprint_id)?;
        ensure_sprint_not_terminal(&transaction, &admission.sprint_id)?;
        if graph.is_none() || sprint_created_at_unix_ms > admission.admitted_at_unix_ms {
            return Err(reference_mismatch(
                "sprint application admission",
                "application requires an attached graph and cannot predate its sprint",
            ));
        }
        validate_effect_for_sprint_phase(&spec, graph.as_ref(), intent)?;
        let final_gate = validate_claimed_final_verification_application_gate(
            &transaction,
            &admission.sprint_id,
            &admission.final_verification_receipt_id,
        )?;
        final_gate.validate_cut(Some(phase_event), admission.admitted_at_unix_ms)?;
        let assembly = match derive_sprint_application_preparation(
            &transaction,
            &admission.sprint_id,
            &admission.final_verification_receipt_id,
            &admission.artifact_assembly_id,
            admission.admitted_at_unix_ms,
        )? {
            SprintApplicationPreparation::Ready(assembly) => assembly,
            SprintApplicationPreparation::VerifiedNoOpRequired { .. } => {
                return Err(reference_mismatch(
                    "sprint application admission",
                    "empty TaskDone change set requires VerifiedNoOp and cannot admit application",
                ));
            }
            SprintApplicationPreparation::MultipleIntegratedSourcesUnsupported {
                integrated_source_count,
            } => {
                return Err(reference_mismatch(
                    "sprint application admission",
                    format!(
                        "gate-one application supports exactly one integrated source, found {integrated_source_count}"
                    ),
                ));
            }
        };
        if admission.request.change_set != assembly.change_set
            || admission.request.artifact != assembly.artifact
        {
            return Err(reference_mismatch(
                "sprint application admission",
                "caller request differs from the internally derived exact artifact assembly",
            ));
        }
        validate_sprint_phase_transition(&transaction, phase_event)?;
        validate_new_event(&transaction, phase_event)?;
        let session =
            validate_effect_session_binding(&transaction, intent, &admission.runner_session_id)?;
        let (launch, _) = load_runner_launch_intent_from(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        if session.purpose != RunnerSessionPurpose::Applier
            || launch.purpose != RunnerSessionPurpose::Applier
            || session.launch_id != admission.runner_launch_id
            || launch.session_id != admission.runner_session_id
            || session.policy_hash != intent.policy_hash
            || launch.policy_hash != intent.policy_hash
            || session.grant_hash != spec.workspace_grant.grant_hash
            || launch.grant_hash != spec.workspace_grant.grant_hash
            || session.policy_version != spec.workspace_grant.policy_version
            || launch.policy_version != spec.workspace_grant.policy_version
            || session.registered_at_unix_ms > admission.admitted_at_unix_ms
            || launch.created_at_unix_ms > admission.admitted_at_unix_ms
        {
            return Err(reference_mismatch(
                "sprint application admission",
                "effect is not bound to the exact admitted Applier launch, session, policy, and grant",
            ));
        }
        let cleanup = runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        runner_launch_cleanup_admission::require_preparation_allows_session_work(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        reject_unresolved_effects_except(
            &transaction,
            &admission.sprint_id,
            &cleanup.cleanup_effect.intent.effect_id,
        )?;
        worker_lease_authority::require_no_active(&transaction, &admission.sprint_id)?;
        ensure_artifact_absent(
            &transaction,
            "SELECT 1 FROM effect_intents WHERE effect_id = ?1",
            "effect intent",
            &intent.effect_id,
        )?;
        if let Some(existing_effect_id) = transaction
            .query_row(
                "SELECT effect_id FROM effect_intents
                 WHERE sprint_id = ?1 AND idempotency_key = ?2",
                params![intent.sprint_id, intent.idempotency_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(LedgerError::ArtifactAlreadyExists {
                entity: "effect idempotency key",
                id: format!(
                    "{}:{} (effect {existing_effect_id})",
                    intent.sprint_id, intent.idempotency_key
                ),
            });
        }

        insert_agent_event(&transaction, phase_event)?;
        insert_application_artifact_assembly(&transaction, &assembly)?;
        insert_sprint_application_admission(&transaction, admission)?;
        application_artifact_authority::insert_application_request_artifact_authority(
            &transaction,
            intent,
            &admission.request,
            &request_bytes,
        )?;
        validate_new_event(&transaction, proposed_event)?;
        transaction.execute(
            "INSERT INTO effect_session_bindings (
                effect_id, sprint_id, launch_id, session_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                intent.effect_id,
                intent.sprint_id,
                launch.launch_id,
                session.session_id,
                i64::from(intent.contract_version),
            ],
        )?;
        insert_agent_event(&transaction, proposed_event)?;
        insert_effect_request_payload(&transaction, intent, &request_bytes)?;
        insert_finish_effect_kind(&transaction, intent)?;
        insert_effect_intent(&transaction, intent, &proposed_event.event_id)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "sprint application admission",
                recovery_id: admission.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "sprint application admission",
            &admission.effect_id,
            |ledger| {
                let stored = ledger.load_sprint_application_admission(&admission.admission_id)?;
                let stored_assembly =
                    ledger.load_application_artifact_assembly(&stored.artifact_assembly_id)?;
                let stored_phase =
                    load_event_by_id(&ledger.connection, &stored.sprint_phase_event_id)?;
                let effect = load_effect_from(&ledger.connection, &stored.effect_id)?;
                let binding = load_effect_runner_binding(&ledger.connection, &effect.intent)?;
                let stored_session = binding.session.ok_or_else(|| LedgerError::Corrupt {
                    entity: "fresh sprint application dispatch permit",
                    detail: "effect lacks initialized Applier session".into(),
                })?;
                if stored != *admission
                    || stored_assembly != assembly
                    || stored_phase != *phase_event
                    || effect.intent != *intent
                    || effect.request_bytes != request_bytes
                    || effect.proposed_event != *proposed_event
                    || effect.dispatch_claim.is_some()
                    || effect.observation.is_some()
                    || binding.launch != launch
                    || stored_session != session
                    || latest_sprint_phase_event(&ledger.connection, &admission.sprint_id)?.as_ref()
                        != Some(phase_event)
                {
                    return Err(LedgerError::Corrupt {
                        entity: "fresh sprint application dispatch permit",
                        detail:
                            "post-commit readback differs from exact fresh application authority"
                                .into(),
                    });
                }
                Ok(SprintApplicationDispatchAdmission::Fresh {
                    admission: stored.clone(),
                    assembly: stored_assembly,
                    effect: effect.clone(),
                    permit: FreshApplicationDispatchPermit {
                        effect,
                        launch: binding.launch,
                        session: stored_session,
                        admission: stored,
                        ledger_instance_id: ledger.instance_id,
                    },
                })
            },
        )
    }

    /// Loads one exact immutable sprint application admission.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent, noncanonical, or crossed row.
    pub fn load_sprint_application_admission(
        &self,
        admission_id: &str,
    ) -> Result<SprintApplicationAdmission, LedgerError> {
        load_sprint_application_admission_from(&self.connection, admission_id)
    }

    /// Loads one exact immutable gate-one artifact assembly and ordered source.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent, noncanonical, or crossed row.
    pub fn load_application_artifact_assembly(
        &self,
        assembly_id: &str,
    ) -> Result<ApplicationArtifactAssembly, LedgerError> {
        load_application_artifact_assembly_from(&self.connection, assembly_id)
    }

    /// Atomically pre-admits the next serialized automated formal check and
    /// its exact runner-bound `RunCommand` intent.
    ///
    /// The admission is inserted before the intent inside the same immediate
    /// transaction. No effect can become executable without the exact
    /// criterion command, attempt, session, and sealed snapshot authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a non-next or non-automated criterion,
    /// unfinished prior check, crossed effect/session/snapshot, noncanonical
    /// request, stale phase, or conflicting replay.
    #[allow(clippy::too_many_lines)] // admission, exact replay, and post-commit authority readback are one boundary.
    pub fn admit_task_attempt_formal_check_for_dispatch(
        &mut self,
        admission: &TaskAttemptFormalCheckAdmission,
        intent: &EffectIntent,
        proposed_event: &AgentEvent,
    ) -> Result<TaskFormalCheckDispatchAdmission, LedgerError> {
        self.admit_task_attempt_formal_check_for_dispatch_inner(
            admission,
            intent,
            proposed_event,
            None,
        )
    }

    /// Schema-v27 formal-check admission that commits the caller-preallocated
    /// output capture intent in the same transaction as the check and command.
    ///
    /// # Errors
    ///
    /// Returns the formal-check admission errors plus a mismatch for crossed
    /// capture source or private-state authority.
    pub fn admit_task_attempt_formal_check_with_output_capture_for_dispatch(
        &mut self,
        admission: &TaskAttemptFormalCheckAdmission,
        intent: &EffectIntent,
        proposed_event: &AgentEvent,
        output_capture_intent: &CommandOutputCaptureIntentV1,
    ) -> Result<TaskFormalCheckDispatchAdmission, LedgerError> {
        self.admit_task_attempt_formal_check_for_dispatch_inner(
            admission,
            intent,
            proposed_event,
            Some(output_capture_intent),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn admit_task_attempt_formal_check_for_dispatch_inner(
        &mut self,
        admission: &TaskAttemptFormalCheckAdmission,
        intent: &EffectIntent,
        proposed_event: &AgentEvent,
        output_capture_intent: Option<&CommandOutputCaptureIntentV1>,
    ) -> Result<TaskFormalCheckDispatchAdmission, LedgerError> {
        self.require_writable()?;
        admission.validate()?;
        intent.validate()?;
        proposed_event.validate()?;
        let request_bytes = encode("formal-check command", &admission.command)?;
        validate_supplied_effect_payload(
            "formal-check command",
            &intent.effect_id,
            &request_bytes,
            &intent.request_digest,
            MAX_EFFECT_REQUEST_BYTES,
        )?;
        validate_effect_proposal_event_shape(intent, proposed_event)?;
        validate_formal_admission_intent(admission, intent)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        task_attempt_authority::require_exact(&transaction, &admission.attempt)?;
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT admission_id FROM task_attempt_formal_check_admissions
                 WHERE admission_id = ?1 OR effect_id = ?2
                    OR (attempt_id = ?3 AND criterion_id = ?4)
                    OR (attempt_id = ?3 AND criterion_ordinal = ?5)",
                params![
                    admission.admission_id,
                    admission.effect_id,
                    admission.attempt.attempt_id,
                    admission.criterion_id,
                    i64::from(admission.criterion_ordinal),
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored =
                task_attempt_authority::load_formal_check_admission(&transaction, &existing_id)?;
            let effect = load_effect_from(&transaction, &stored.effect_id)?;
            if stored == *admission
                && effect.intent == *intent
                && effect.request_bytes == request_bytes
                && effect.proposed_event == *proposed_event
            {
                if let Some(expected_capture) = output_capture_intent {
                    let capture = command_output_capture_authority::load_from_effect(
                        &transaction,
                        &effect.intent.effect_id,
                    )?
                    .ok_or_else(|| {
                        reference_mismatch(
                            "task attempt formal-check capture admission",
                            "existing formal-check effect predates v27 capture authority",
                        )
                    })?;
                    if capture.intent != *expected_capture {
                        return Err(reference_mismatch(
                            "task attempt formal-check capture admission",
                            "existing formal-check capture is bound differently",
                        ));
                    }
                }
                transaction.commit()?;
                return Ok(TaskFormalCheckDispatchAdmission::Existing {
                    admission: stored,
                    effect,
                });
            }
            return Err(reference_mismatch(
                "task attempt formal-check admission",
                "admission, criterion, or effect identity is already bound differently",
            ));
        }
        task_attempt_authority::insert_formal_check_admission(&transaction, admission)?;
        insert_task_attempt_runner_effect_intent(
            &transaction,
            intent,
            &request_bytes,
            proposed_event,
            &admission.runner_session_id,
            output_capture_intent,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt formal-check admission",
                recovery_id: admission.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt formal-check admission",
            &admission.effect_id,
            |ledger| {
                let stored =
                    ledger.load_task_attempt_formal_check_admission(&admission.admission_id)?;
                if stored != *admission {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt formal-check admission",
                        detail: "post-commit readback differs from admitted authority".into(),
                    });
                }
                let effect = load_effect_from(&ledger.connection, &admission.effect_id)?;
                let binding = load_effect_runner_binding(&ledger.connection, &effect.intent)?;
                let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
                    entity: "fresh formal-check dispatch permit",
                    detail: "admitted formal-check effect lacks an initialized session".into(),
                })?;
                if effect.observation.is_some()
                    || effect.dispatch_claim.is_some()
                    || session.session_id != admission.runner_session_id
                {
                    return Err(LedgerError::Corrupt {
                        entity: "fresh formal-check dispatch permit",
                        detail:
                            "post-commit readback is not the exact pristine formal-check authority"
                                .into(),
                    });
                }
                if let Some(expected_capture) = output_capture_intent {
                    let capture = command_output_capture_authority::load_from_effect(
                        &ledger.connection,
                        &effect.intent.effect_id,
                    )?
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "fresh formal-check dispatch permit",
                        detail: "fresh formal-check command lacks its capture intent".into(),
                    })?;
                    if capture.intent != *expected_capture
                        || capture.acquired.is_some()
                        || capture.terminal.is_some()
                    {
                        return Err(LedgerError::Corrupt {
                            entity: "fresh formal-check dispatch permit",
                            detail:
                                "fresh formal-check capture readback differs or is not pristine"
                                    .into(),
                        });
                    }
                }
                let sensitive_output_detection_policy =
                    sensitive_output_rejection::load_policy_for_effect(
                        &ledger.connection,
                        &effect.intent.effect_id,
                    )?;
                Ok(TaskFormalCheckDispatchAdmission::Fresh {
                    admission: stored.clone(),
                    effect: effect.clone(),
                    permit: FreshTaskFormalCheckDispatchPermit {
                        effect,
                        launch: binding.launch,
                        session,
                        admission: stored,
                        output_capture_intent: output_capture_intent.cloned(),
                        sensitive_output_detection_policy,
                        ledger_instance_id: ledger.instance_id,
                    },
                })
            },
        )
    }

    /// Compatibility admission path. It intentionally discards fresh dispatch
    /// authority, so callers requiring runner execution must use
    /// [`Self::admit_task_attempt_formal_check_for_dispatch`].
    ///
    /// # Errors
    ///
    /// Returns the same validation, storage, or conflicting-replay error as
    /// the authority-preserving admission path.
    pub fn admit_task_attempt_formal_check(
        &mut self,
        admission: &TaskAttemptFormalCheckAdmission,
        intent: &EffectIntent,
        proposed_event: &AgentEvent,
    ) -> Result<TaskAttemptFormalCheckAdmission, LedgerError> {
        match self.admit_task_attempt_formal_check_for_dispatch(
            admission,
            intent,
            proposed_event,
        )? {
            TaskFormalCheckDispatchAdmission::Fresh {
                admission, permit, ..
            } => {
                drop(permit);
                Ok(admission)
            }
            TaskFormalCheckDispatchAdmission::Existing { admission, .. } => Ok(admission),
        }
    }

    /// Loads one exact formal-check admission and its still-correlated effect.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the canonical admission or its exact
    /// command request, runner binding, proposal event, or intent disagrees.
    pub fn load_task_attempt_formal_check_admission(
        &self,
        admission_id: &str,
    ) -> Result<TaskAttemptFormalCheckAdmission, LedgerError> {
        let admission =
            task_attempt_authority::load_formal_check_admission(&self.connection, admission_id)?;
        let effect = load_effect_from(&self.connection, &admission.effect_id)?;
        validate_formal_admission_intent(&admission, &effect.intent).map_err(|error| {
            LedgerError::Corrupt {
                entity: "task attempt formal-check admission",
                detail: error.to_string(),
            }
        })?;
        if effect.request_bytes != encode("formal-check command", &admission.command)? {
            return Err(LedgerError::Corrupt {
                entity: "task attempt formal-check admission",
                detail: "effect request differs from the exact criterion command".into(),
            });
        }
        let binding = load_effect_runner_binding(&self.connection, &effect.intent)?;
        if binding
            .session
            .as_ref()
            .map(|session| session.session_id.as_str())
            != Some(admission.runner_session_id.as_str())
        {
            return Err(LedgerError::Corrupt {
                entity: "task attempt formal-check admission",
                detail: "effect is bound to a different runner session".into(),
            });
        }
        Ok(admission)
    }

    /// Atomically records one terminal formal-check observation and its exact
    /// criterion-specific typed check.
    ///
    /// The verification receipt, full execution evidence, effect observation,
    /// terminal event, and formal check commit together. A failing command
    /// verification remains a known terminal check and fences later work.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for any crossed admission, attempt, effect,
    /// observation, receipt, session, snapshot, timestamp, or conflicting replay.
    #[allow(clippy::too_many_lines)] // Receipt, observation, formal result, replay, and readback form one atomic boundary.
    pub fn complete_task_attempt_formal_check(
        &mut self,
        check: &TaskAttemptFormalCheck,
        observation: &EffectObservation,
        terminal_event: &AgentEvent,
        evidence: &VerificationEffectEvidence,
    ) -> Result<TaskAttemptFormalCheck, LedgerError> {
        self.require_writable()?;
        check.validate()?;
        observation.validate()?;
        terminal_event.validate()?;
        validate_verification_evidence_write_contract(&self.connection, evidence)?;
        require_successful_effect_kind(observation, EffectKind::RunCommand)?;
        let evidence_bytes = canonical_finish_evidence(
            "verification effect evidence",
            &observation.effect_id,
            evidence,
            observation.outcome.evidence_digest(),
        )?;
        if check.effect_id != observation.effect_id
            || check.observation_id != observation.observation_id
            || check.verification_receipt != evidence.verification
            || evidence.effect_id != check.effect_id
            || evidence.observation_id != check.observation_id
            || evidence.runner_session_id != check.runner_session_id
        {
            return Err(reference_mismatch(
                "task attempt formal check",
                "check must embed the exact effect-bound verification evidence",
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        task_attempt_authority::require_exact(&transaction, &check.attempt)?;
        let admission_id = transaction
            .query_row(
                "SELECT admission_id FROM task_attempt_formal_check_admissions
                 WHERE effect_id = ?1",
                [&check.effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::ArtifactNotFound {
                entity: "task attempt formal-check admission",
                id: check.effect_id.clone(),
            })?;
        let admission =
            task_attempt_authority::load_formal_check_admission(&transaction, &admission_id)?;
        validate_formal_check_against_admission(check, &admission)?;
        let admitted_effect = load_effect_from(&transaction, &admission.effect_id)?;
        if admitted_effect.dispatch_claim.is_some()
            || effect_requires_claimed_phase_terminal(&transaction, &admission.effect_id)?
        {
            return Err(reference_mismatch(
                "task attempt formal check",
                "current admissions require complete_claimed_task_attempt_formal_check with move-only claimed authority",
            ));
        }
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT formal_check_id FROM task_attempt_formal_checks
                 WHERE formal_check_id = ?1 OR admission_id = ?2
                    OR effect_id = ?3 OR observation_id = ?4
                    OR verification_receipt_id = ?5",
                params![
                    check.formal_check_id,
                    admission_id,
                    check.effect_id,
                    check.observation_id,
                    check.verification_receipt.receipt_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored = task_attempt_authority::load_formal_check(&transaction, &existing_id)?;
            let effect = load_effect_from(&transaction, &stored.effect_id)?;
            let stored_evidence = load_verification_effect_evidence_from(
                &transaction,
                &stored.verification_receipt.receipt_id,
            )?;
            if stored == *check
                && effect.observation.as_ref() == Some(observation)
                && effect.evidence_bytes.as_deref() == Some(evidence_bytes.as_slice())
                && effect.terminal_event.as_ref() == Some(terminal_event)
                && stored_evidence == *evidence
            {
                transaction.commit()?;
                return Ok(stored);
            }
            return Err(reference_mismatch(
                "task attempt formal check",
                "check, observation, or receipt identity is already bound differently",
            ));
        }
        let persisted = validate_new_effect_observation(&transaction, observation, terminal_event)?;
        let session =
            validate_verification_effect_evidence(&transaction, &persisted, observation, evidence)?;
        insert_verification_receipt(&transaction, &evidence.verification)?;
        transaction.execute(
            "INSERT INTO verification_session_bindings (
                verification_receipt_id, sprint_id, session_id, contract_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                evidence.verification.receipt_id,
                evidence.verification.sprint_id,
                session.session_id,
                i64::from(CONTRACT_VERSION),
            ],
        )?;
        insert_verification_effect_evidence(&transaction, evidence, &evidence_bytes)?;
        insert_agent_event(&transaction, terminal_event)?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_effect_observation(&transaction, observation, &terminal_event.event_id)?;
        task_attempt_authority::insert_formal_check(&transaction, &admission_id, check)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt formal check",
                recovery_id: check.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt formal check",
            &check.effect_id,
            |ledger| {
                let stored = ledger.load_task_attempt_formal_check(&check.formal_check_id)?;
                if stored != *check {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt formal check",
                        detail: "post-commit readback differs from completed check".into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Atomically records a claimed formal-check observation and its exact
    /// criterion-specific typed check.
    ///
    /// The supplied move-only authority must be the exact `TaskFormalCheck`
    /// authority produced after validating this effect's committed transport
    /// request. Every typed receipt, retained output byte, terminal event, and
    /// observation commits in one transaction, and the observation carries the
    /// immutable dispatch-claim identity.
    ///
    /// Retry custody follows the commit-attempt boundary exactly: a failure
    /// proven to occur before [`rusqlite::Transaction::commit`] returns the
    /// original authority, while commit, hardening, and readback failures never
    /// recreate it and require durable reconciliation.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimedObservationWriteFailure`] for any crossed authority,
    /// admission, attempt, effect, observation, receipt, session, snapshot,
    /// phase, timestamp, storage, or readback failure.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn complete_claimed_task_attempt_formal_check(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        check: &TaskAttemptFormalCheck,
        observation: &EffectObservation,
        terminal_event: &AgentEvent,
        evidence: &VerificationEffectEvidence,
    ) -> Result<TaskAttemptFormalCheck, ClaimedObservationWriteFailure> {
        self.complete_claimed_task_attempt_formal_check_inner(
            authority,
            check,
            observation,
            terminal_event,
            evidence,
            None,
        )
    }

    /// Schema-v27 claimed formal-check terminal that atomically joins complete
    /// verification artifacts, the capture terminal, and independent native
    /// command-domain cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimedObservationWriteFailure`] with the same exact
    /// precommit/uncertain-commit custody rules as the compatibility method.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_claimed_task_attempt_formal_check_with_output_capture(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        check: &TaskAttemptFormalCheck,
        observation: &EffectObservation,
        terminal_event: &AgentEvent,
        evidence: &VerificationEffectEvidence,
        output_capture_terminal: &CommandOutputCaptureTerminalAnchorV1,
        clean_scan_receipt: &CommandOutputCleanScanPublicationReceiptV1,
        command_cleanup: &CommandDomainCleanupProof,
    ) -> Result<TaskAttemptFormalCheck, ClaimedObservationWriteFailure> {
        self.complete_claimed_task_attempt_formal_check_inner(
            authority,
            check,
            observation,
            terminal_event,
            evidence,
            Some((output_capture_terminal, clean_scan_receipt, command_cleanup)),
        )
    }
}
impl EventLedger {
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn complete_claimed_task_attempt_formal_check_inner(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        check: &TaskAttemptFormalCheck,
        observation: &EffectObservation,
        terminal_event: &AgentEvent,
        evidence: &VerificationEffectEvidence,
        output_capture_terminal: Option<(
            &CommandOutputCaptureTerminalAnchorV1,
            &CommandOutputCleanScanPublicationReceiptV1,
            &CommandDomainCleanupProof,
        )>,
    ) -> Result<TaskAttemptFormalCheck, ClaimedObservationWriteFailure> {
        let evidence_bytes = match (|| -> Result<Vec<u8>, LedgerError> {
            self.require_writable()?;
            if authority.ledger_instance_id != self.instance_id {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "authority belongs to another open EventLedger instance",
                ));
            }
            check.validate()?;
            observation.validate()?;
            terminal_event.validate()?;
            validate_verification_evidence_write_contract(&self.connection, evidence)?;
            require_successful_effect_kind(observation, EffectKind::RunCommand)?;
            if let Some((terminal, clean_scan, cleanup)) = output_capture_terminal {
                terminal.validate()?;
                clean_scan.validate()?;
                cleanup.validate()?;
                if terminal.effect_id != observation.effect_id
                    || terminal.observation_id != observation.observation_id
                    || terminal.dispatch_claim_id.as_deref()
                        != Some(authority.claim.dispatch_claim_id.as_str())
                    || terminal.artifact_reference.as_ref() != evidence.output_artifacts.as_ref()
                    || evidence.verification.termination != Some(clean_scan.termination)
                    || cleanup.effect_id != observation.effect_id
                    || cleanup.observation_id.as_deref()
                        != Some(observation.observation_id.as_str())
                    || cleanup.launch_id != authority.launch.launch_id
                    || cleanup.session_id != authority.session.session_id
                {
                    return Err(reference_mismatch(
                        "claimed task formal-check output capture",
                        "terminal, output artifacts, or cleanup differs from exact claimed verification",
                    ));
                }
            }
            let evidence_bytes = canonical_finish_evidence(
                "verification effect evidence",
                &observation.effect_id,
                evidence,
                observation.outcome.evidence_digest(),
            )?;
            if check.effect_id != observation.effect_id
                || check.observation_id != observation.observation_id
                || check.verification_receipt != evidence.verification
                || evidence.effect_id != check.effect_id
                || evidence.observation_id != check.observation_id
                || evidence.runner_launch_id != authority.launch.launch_id
                || evidence.runner_session_id != authority.session.session_id
                || evidence.runner_session_id != check.runner_session_id
            {
                return Err(reference_mismatch(
                    "claimed task attempt formal check",
                    "check and evidence must name the exact claimed formal-check effect, launch, session, and observation",
                ));
            }
            Ok(evidence_bytes)
        })() {
            Ok(evidence_bytes) => evidence_bytes,
            Err(error) => {
                return Err(ClaimedObservationWriteFailure::definitely_precommit(
                    error, authority,
                ));
            }
        };

        let transaction = match self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(error) => {
                return Err(ClaimedObservationWriteFailure::definitely_precommit(
                    error.into(),
                    authority,
                ));
            }
        };
        let precommit = (|| -> Result<(), LedgerError> {
            task_attempt_authority::require_exact(&transaction, &check.attempt)?;
            let admission_id = transaction
                .query_row(
                    "SELECT admission_id FROM task_attempt_formal_check_admissions
                     WHERE effect_id = ?1",
                    [&check.effect_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| LedgerError::ArtifactNotFound {
                    entity: "task attempt formal-check admission",
                    id: check.effect_id.clone(),
                })?;
            let admission =
                task_attempt_authority::load_formal_check_admission(&transaction, &admission_id)?;
            let authorized_admission =
                authority.formal_check_admission.as_ref().ok_or_else(|| {
                    reference_mismatch(
                        "claimed task attempt formal check",
                        "observation authority is not TaskFormalCheck authority",
                    )
                })?;
            if authority.integration_admission.is_some()
                || authority.running_boundary.is_some()
                || &admission != authorized_admission
            {
                return Err(reference_mismatch(
                    "claimed task attempt formal check",
                    "stored admission differs from the exact move-only formal-check authority",
                ));
            }
            validate_formal_check_against_admission(check, &admission)?;
            if transaction
                .query_row(
                    "SELECT 1 FROM task_attempt_formal_checks
                     WHERE formal_check_id = ?1 OR admission_id = ?2
                        OR effect_id = ?3 OR observation_id = ?4
                        OR verification_receipt_id = ?5",
                    params![
                        check.formal_check_id,
                        admission_id,
                        check.effect_id,
                        check.observation_id,
                        check.verification_receipt.receipt_id,
                    ],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                return Err(LedgerError::ArtifactAlreadyExists {
                    entity: "task attempt formal check",
                    id: check.formal_check_id.clone(),
                });
            }
            let persisted =
                validate_new_effect_observation(&transaction, observation, terminal_event)?;
            validate_runner_effect_observation_authority(
                &transaction,
                &authority.effect,
                &authority.claim,
                &authority.launch,
                &authority.session,
                authority.running_boundary.as_ref(),
                authority.formal_check_admission.as_ref(),
                authority.integration_admission.as_ref(),
                authority.final_verification_admission.as_ref(),
                authority.application_admission.as_deref(),
                authority.live_state_capture_admission.as_deref(),
                &persisted,
            )?;
            let session = validate_verification_effect_evidence(
                &transaction,
                &persisted,
                observation,
                evidence,
            )?;
            if session != authority.session {
                return Err(reference_mismatch(
                    "claimed task attempt formal check",
                    "verification evidence resolved a different runner session",
                ));
            }
            let capture = command_output_capture_authority::load_from_effect(
                &transaction,
                &observation.effect_id,
            )?;
            match (capture.as_ref(), output_capture_terminal) {
                (Some(_), None) => {
                    return Err(reference_mismatch(
                        "claimed task formal-check output capture",
                        "v27 formal-check terminal requires exact capture and cleanup authority",
                    ));
                }
                (None, Some(_)) => {
                    return Err(reference_mismatch(
                        "claimed task formal-check output capture",
                        "capture terminal cannot be attached to a historical effect",
                    ));
                }
                (Some(capture), Some((terminal, clean_scan, cleanup))) => {
                    let acquired = capture.acquired.as_ref().ok_or_else(|| {
                        reference_mismatch(
                            "claimed task formal-check output capture",
                            "current clean publication lacks its exact acquisition",
                        )
                    })?;
                    command_output_capture_authority::validate_claim_acquisition(
                        &transaction,
                        &authority.claim,
                    )?;
                    if capture.terminal.is_some() {
                        return Err(reference_mismatch(
                            "claimed task formal-check output capture",
                            "capture is already terminal",
                        ));
                    }
                    command_output_capture_authority::insert_direct_terminal_validation(
                        &transaction,
                        terminal,
                        &cleanup.proof_id,
                    )?;
                    sensitive_output_rejection::insert_clean_scan_publication(
                        &transaction,
                        clean_scan,
                        &capture.intent,
                        acquired,
                        terminal,
                        cleanup,
                    )?;
                    command_output_capture_authority::insert_terminal(
                        &transaction,
                        terminal,
                        observation,
                    )?;
                }
                (None, None) => {}
            }
            insert_verification_receipt(&transaction, &evidence.verification)?;
            transaction.execute(
                "INSERT INTO verification_session_bindings (
                    verification_receipt_id, sprint_id, session_id, contract_version
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    evidence.verification.receipt_id,
                    evidence.verification.sprint_id,
                    session.session_id,
                    i64::from(CONTRACT_VERSION),
                ],
            )?;
            insert_verification_effect_evidence(&transaction, evidence, &evidence_bytes)?;
            insert_agent_event(&transaction, terminal_event)?;
            insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &terminal_event.event_id,
                &authority.claim.dispatch_claim_id,
            )?;
            if let Some((_, _, cleanup)) = output_capture_terminal {
                command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
                    &transaction,
                    cleanup,
                )?;
            }
            task_attempt_authority::insert_formal_check(&transaction, &admission_id, check)
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

        let claim_id = authority.claim.dispatch_claim_id.clone();
        drop(authority);
        if let Err(error) = transaction.commit() {
            return Err(ClaimedObservationWriteFailure::commit_attempted(
                LedgerError::PostCommitStateUncertain {
                    operation: "claimed task attempt formal check",
                    recovery_id: check.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        self.read_back_authority_after_commit(
            "claimed task attempt formal check",
            &check.effect_id,
            |ledger| {
                let stored = ledger.load_task_attempt_formal_check(&check.formal_check_id)?;
                let stored_evidence =
                    ledger.load_verification_effect_evidence(&evidence.verification.receipt_id)?;
                let effect = ledger.load_effect(&check.effect_id)?;
                if stored != *check
                    || stored_evidence != *evidence
                    || effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || effect.terminal_event.as_ref() != Some(terminal_event)
                    || effect
                        .dispatch_claim
                        .as_ref()
                        .map(|claim| claim.dispatch_claim_id.as_str())
                        != Some(claim_id.as_str())
                {
                    return Err(LedgerError::Corrupt {
                        entity: "claimed task attempt formal check",
                        detail: "post-commit readback differs from the exact claimed formal check"
                            .into(),
                    });
                }
                if let Some((terminal, clean_scan, cleanup)) = output_capture_terminal {
                    let capture = command_output_capture_authority::load_from_effect(
                        &ledger.connection,
                        &observation.effect_id,
                    )?
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "claimed task formal-check output capture",
                        detail: "terminal capture is absent on readback".into(),
                    })?;
                    let stored_cleanup =
                        ledger.load_command_domain_cleanup_proof(&observation.effect_id)?;
                    let stored_clean_scan = ledger
                        .load_command_output_clean_scan_publication_receipt_for_effect(
                            &observation.effect_id,
                        )?;
                    if capture.terminal.as_ref() != Some(terminal)
                        || stored_clean_scan != *clean_scan
                        || stored_cleanup.proof != *cleanup
                    {
                        return Err(LedgerError::Corrupt {
                            entity: "claimed task formal-check output capture",
                            detail: "terminal capture or cleanup differs on readback".into(),
                        });
                    }
                }
                Ok(stored)
            },
        )
        .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Loads one exact completed formal check and its effect-bound evidence.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the canonical check, admission, effect,
    /// observation, verification receipt, or runner evidence disagrees.
    pub fn load_task_attempt_formal_check(
        &self,
        formal_check_id: &str,
    ) -> Result<TaskAttemptFormalCheck, LedgerError> {
        let check = task_attempt_authority::load_formal_check(&self.connection, formal_check_id)?;
        let evidence = load_verification_effect_evidence_from(
            &self.connection,
            &check.verification_receipt.receipt_id,
        )?;
        if evidence.verification != check.verification_receipt
            || evidence.effect_id != check.effect_id
            || evidence.observation_id != check.observation_id
            || evidence.runner_session_id != check.runner_session_id
        {
            return Err(LedgerError::Corrupt {
                entity: "task attempt formal check",
                detail: "effect-bound verification evidence differs from the check".into(),
            });
        }
        Ok(check)
    }

    /// Atomically closes formal verification and enters `Candidate`.
    ///
    /// The boundary's ordered formal-check and verification-receipt vectors
    /// must be a complete bijection over the task's automated criteria. Both
    /// vectors may be empty when the task declares only human criteria.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an incomplete, failed, duplicated, crossed,
    /// or out-of-order check set, stale phase, wrong event, or conflicting replay.
    pub fn transition_task_attempt_to_candidate(
        &mut self,
        boundary: &TaskAttemptCandidateBoundary,
        event: &AgentEvent,
    ) -> Result<TaskAttemptCandidateBoundary, LedgerError> {
        self.require_writable()?;
        boundary.validate()?;
        event.validate()?;
        validate_attempt_phase_event(
            &boundary.attempt,
            &boundary.transition_event_id,
            boundary.admitted_at_unix_ms,
            TaskState::Verifying,
            TaskState::Candidate,
            event,
            "task attempt candidate boundary",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        task_attempt_authority::require_exact(&transaction, &boundary.attempt)?;
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT boundary_id FROM task_attempt_candidate_boundaries
                 WHERE boundary_id = ?1 OR attempt_id = ?2
                    OR verification_boundary_id = ?3 OR transition_event_id = ?4",
                params![
                    boundary.boundary_id,
                    boundary.attempt.attempt_id,
                    boundary.verification_boundary_id,
                    boundary.transition_event_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored =
                task_attempt_authority::load_candidate_boundary(&transaction, &existing_id)?;
            let stored_event = load_event_by_id(&transaction, &stored.transition_event_id)?;
            if stored == *boundary && stored_event == *event {
                transaction.commit()?;
                return Ok(stored);
            }
            return Err(reference_mismatch(
                "task attempt candidate boundary",
                "boundary, attempt, verification, or transition identity is already bound differently",
            ));
        }
        if current_task_state(
            &transaction,
            &boundary.attempt.worker_lease.sprint_id,
            &boundary.attempt.worker_lease.task_id,
        )? != TaskState::Verifying
        {
            return Err(reference_mismatch(
                "task attempt candidate boundary",
                "durable task state is not Verifying",
            ));
        }
        validate_new_event(&transaction, event)?;
        task_attempt_authority::insert_candidate_boundary(&transaction, boundary)?;
        insert_agent_event(&transaction, event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt candidate boundary",
                recovery_id: boundary.boundary_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt candidate boundary",
            &boundary.boundary_id,
            |ledger| {
                let stored = ledger.load_task_attempt_candidate_boundary(&boundary.boundary_id)?;
                if stored != *boundary {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt candidate boundary",
                        detail: "post-commit readback differs from admitted authority".into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Loads one exact immutable `Verifying -> Candidate` boundary.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when canonical bytes, exact verification phase,
    /// formal-check bijection, or transition event disagree.
    pub fn load_task_attempt_candidate_boundary(
        &self,
        boundary_id: &str,
    ) -> Result<TaskAttemptCandidateBoundary, LedgerError> {
        let boundary =
            task_attempt_authority::load_candidate_boundary(&self.connection, boundary_id)?;
        let event = load_event_by_id(&self.connection, &boundary.transition_event_id)?;
        validate_attempt_phase_event(
            &boundary.attempt,
            &boundary.transition_event_id,
            boundary.admitted_at_unix_ms,
            TaskState::Verifying,
            TaskState::Candidate,
            &event,
            "task attempt candidate boundary",
        )
        .map_err(|error| LedgerError::Corrupt {
            entity: "task attempt candidate boundary",
            detail: error.to_string(),
        })?;
        Ok(boundary)
    }

    /// Atomically pre-admits one exact candidate integration effect.
    ///
    /// The typed admission is durable before the runner-bound
    /// `IntegrateChangeSet` intent. The canonical request must carry the exact
    /// candidate change set and declared input/result snapshots.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a stale Candidate phase, crossed
    /// attempt/candidate/launch/session/snapshot/request/effect, or conflicting replay.
    #[allow(clippy::too_many_lines)] // admission, exact replay, and post-commit authority readback are one boundary.
    pub fn admit_task_attempt_integration_for_dispatch(
        &mut self,
        admission: &TaskAttemptIntegrationAdmission,
        intent: &EffectIntent,
        request: &TaskIntegrationRequest,
        proposed_event: &AgentEvent,
    ) -> Result<TaskIntegrationDispatchAdmission, LedgerError> {
        self.require_writable()?;
        admission.validate()?;
        intent.validate()?;
        request.validate()?;
        proposed_event.validate()?;
        let request_bytes = encode("task integration request", request)?;
        validate_supplied_effect_payload(
            "task integration request",
            &intent.effect_id,
            &request_bytes,
            &intent.request_digest,
            MAX_EFFECT_REQUEST_BYTES,
        )?;
        validate_effect_proposal_event_shape(intent, proposed_event)?;
        validate_integration_admission_intent(admission, intent, request)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        task_attempt_authority::require_exact(&transaction, &admission.candidate_boundary.attempt)?;
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT admission_id FROM task_attempt_integration_admissions
                 WHERE admission_id = ?1 OR attempt_id = ?2
                    OR candidate_boundary_id = ?3 OR effect_id = ?4",
                params![
                    admission.admission_id,
                    admission.candidate_boundary.attempt.attempt_id,
                    admission.candidate_boundary.boundary_id,
                    admission.effect_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored =
                task_attempt_authority::load_integration_admission(&transaction, &existing_id)?;
            let stored_request = task_attempt_authority::load_integration_admission_request(
                &transaction,
                &existing_id,
            )?;
            let effect = load_effect_from(&transaction, &stored.effect_id)?;
            if stored == *admission
                && stored_request == request_bytes
                && effect.intent == *intent
                && effect.request_bytes == request_bytes
                && effect.proposed_event == *proposed_event
            {
                transaction.commit()?;
                return Ok(TaskIntegrationDispatchAdmission::Existing {
                    admission: stored,
                    effect,
                });
            }
            return Err(reference_mismatch(
                "task attempt integration admission",
                "admission, candidate, attempt, or effect identity is already bound differently",
            ));
        }
        task_attempt_authority::insert_integration_admission(
            &transaction,
            admission,
            &request_bytes,
        )?;
        insert_task_attempt_runner_effect_intent(
            &transaction,
            intent,
            &request_bytes,
            proposed_event,
            &admission.runner_session_id,
            None,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt integration admission",
                recovery_id: admission.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt integration admission",
            &admission.effect_id,
            |ledger| {
                let stored =
                    ledger.load_task_attempt_integration_admission(&admission.admission_id)?;
                if stored != *admission {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt integration admission",
                        detail: "post-commit readback differs from admitted authority".into(),
                    });
                }
                let effect = load_effect_from(&ledger.connection, &admission.effect_id)?;
                let binding = load_effect_runner_binding(&ledger.connection, &effect.intent)?;
                let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
                    entity: "fresh integration dispatch permit",
                    detail: "admitted integration effect lacks an initialized session".into(),
                })?;
                if effect.observation.is_some()
                    || effect.dispatch_claim.is_some()
                    || binding.launch.launch_id != admission.runner_launch_id
                    || session.session_id != admission.runner_session_id
                {
                    return Err(LedgerError::Corrupt {
                        entity: "fresh integration dispatch permit",
                        detail:
                            "post-commit readback is not the exact pristine integration authority"
                                .into(),
                    });
                }
                Ok(TaskIntegrationDispatchAdmission::Fresh {
                    admission: stored.clone(),
                    effect: effect.clone(),
                    permit: FreshTaskIntegrationDispatchPermit {
                        effect,
                        launch: binding.launch,
                        session,
                        admission: stored,
                        ledger_instance_id: ledger.instance_id,
                    },
                })
            },
        )
    }

    /// Compatibility admission path. It intentionally discards fresh dispatch
    /// authority; runner execution must use
    /// [`Self::admit_task_attempt_integration_for_dispatch`].
    ///
    /// # Errors
    ///
    /// Returns the same validation, storage, or conflicting-replay error as
    /// the authority-preserving admission path.
    pub fn admit_task_attempt_integration(
        &mut self,
        admission: &TaskAttemptIntegrationAdmission,
        intent: &EffectIntent,
        request: &TaskIntegrationRequest,
        proposed_event: &AgentEvent,
    ) -> Result<TaskAttemptIntegrationAdmission, LedgerError> {
        match self.admit_task_attempt_integration_for_dispatch(
            admission,
            intent,
            request,
            proposed_event,
        )? {
            TaskIntegrationDispatchAdmission::Fresh {
                admission, permit, ..
            } => {
                drop(permit);
                Ok(admission)
            }
            TaskIntegrationDispatchAdmission::Existing { admission, .. } => Ok(admission),
        }
    }

    /// Loads one exact integration admission and its runner-bound effect.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when canonical admission bytes or the candidate,
    /// request, effect, runner binding, or proposal event relationship differs.
    pub fn load_task_attempt_integration_admission(
        &self,
        admission_id: &str,
    ) -> Result<TaskAttemptIntegrationAdmission, LedgerError> {
        let admission =
            task_attempt_authority::load_integration_admission(&self.connection, admission_id)?;
        let effect = load_effect_from(&self.connection, &admission.effect_id)?;
        let stored_request = task_attempt_authority::load_integration_admission_request(
            &self.connection,
            admission_id,
        )?;
        if stored_request != effect.request_bytes {
            return Err(LedgerError::Corrupt {
                entity: "task attempt integration admission",
                detail: "stored admission request differs from its effect request".into(),
            });
        }
        let request: TaskIntegrationRequest =
            decode_canonical_request("task integration request", &stored_request)?;
        validate_integration_admission_intent(&admission, &effect.intent, &request).map_err(
            |error| LedgerError::Corrupt {
                entity: "task attempt integration admission",
                detail: error.to_string(),
            },
        )?;
        let binding = load_effect_runner_binding(&self.connection, &effect.intent)?;
        if binding.launch.launch_id != admission.runner_launch_id
            || binding
                .session
                .as_ref()
                .map(|session| session.session_id.as_str())
                != Some(admission.runner_session_id.as_str())
        {
            return Err(LedgerError::Corrupt {
                entity: "task attempt integration admission",
                detail: "effect is bound to a different launch or runner session".into(),
            });
        }
        Ok(admission)
    }

    /// Records independent append-only source authority for a known launched
    /// cleanup outcome before any native cleanup/disposition transaction.
    ///
    /// This API admits only worker-exit, candidate-rejection, permanent,
    /// blocked, and operator-cancellation sources. Launch refusal and formal
    /// verification failure already have their own preparation/check
    /// authority and are deliberately rejected here. Exact replay succeeds;
    /// crossed reuse conflicts. A post-commit canonical readback is mandatory.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for unsupported/self-justifying cause shapes,
    /// crossed attempt/source evidence, stale or released authority,
    /// noncanonical storage, or readback failure.
    pub fn record_task_attempt_cleanup_outcome_authority(
        &mut self,
        attempt: &TaskAttempt,
        outcome: &TaskAttemptKnownCleanupOutcome,
        recorded_at_unix_ms: u64,
    ) -> Result<TaskAttemptKnownCleanupOutcome, LedgerError> {
        self.require_writable()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, _, _, provenance) =
            load_sprint_definition(&transaction, &attempt.worker_lease.sprint_id)?;
        reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
        match task_attempt_authority::record_external_cleanup_outcome_authority(
            &transaction,
            attempt,
            outcome,
            recorded_at_unix_ms,
            false,
        ) {
            Ok(()) => {
                transaction.commit()?;
                return Ok(outcome.clone());
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {}
            Err(error) => return Err(error),
        }
        worker_lease_authority::require_exact(&transaction, &attempt.worker_lease, true)?;
        task_attempt_authority::record_external_cleanup_outcome_authority(
            &transaction,
            attempt,
            outcome,
            recorded_at_unix_ms,
            true,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt cleanup outcome authority",
                recovery_id: attempt.attempt_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt cleanup outcome authority",
            &attempt.attempt_id,
            |ledger| {
                task_attempt_authority::record_external_cleanup_outcome_authority(
                    &ledger.connection,
                    attempt,
                    outcome,
                    recorded_at_unix_ms,
                    false,
                )?;
                Ok(outcome.clone())
            },
        )
    }

    /// Atomically records one successful integration effect, exact receipt,
    /// and `Integrated` task-attempt disposition.
    ///
    /// The successful observation and typed integration receipt are inserted
    /// first, followed by the exact disposition and `Candidate -> Integrated`
    /// event in the same immediate transaction. A deferred coverage row makes
    /// standalone current integration receipts impossible at commit.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for any non-Integrated disposition, crossed
    /// candidate/admission/effect/observation/receipt/session/snapshot/event,
    /// stale phase, or conflicting replay.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn integrate_task_attempt(
        &mut self,
        disposition: &TaskAttemptDisposition,
        observation: &EffectObservation,
        effect_terminal_event: &AgentEvent,
        evidence: &TaskIntegrationEvidence,
        transition_event: &AgentEvent,
    ) -> Result<TaskAttemptDisposition, LedgerError> {
        self.require_writable()?;
        observation.validate()?;
        effect_terminal_event.validate()?;
        transition_event.validate()?;
        evidence.validate()?;
        require_successful_effect_kind(observation, EffectKind::IntegrateChangeSet)?;
        let TaskAttemptDisposition::Integrated(integrated) = disposition else {
            return Err(reference_mismatch(
                "task attempt integration disposition",
                "integration API accepts only the Integrated disposition variant",
            ));
        };
        let evidence_bytes = canonical_finish_evidence(
            "task integration evidence",
            &observation.effect_id,
            evidence,
            observation.outcome.evidence_digest(),
        )?;
        if integrated.candidate_boundary.attempt != integrated.metadata.attempt
            || integrated.integration_receipt != evidence.receipt
            || integrated.evidence.canonical_bytes != evidence_bytes
            || integrated.evidence.digest != Digest::sha256(&evidence_bytes)
            || integrated.evidence.kind != crate::TaskAttemptEvidenceKind::Integrated
            || observation.effect_id != evidence.receipt.effect_id
            || observation.observation_id != evidence.receipt.observation_id
        {
            return Err(reference_mismatch(
                "task attempt integration disposition",
                "disposition must retain the exact candidate and canonical integration evidence",
            ));
        }
        validate_attempt_phase_event(
            &integrated.metadata.attempt,
            &integrated.metadata.state_transition_event_id,
            integrated.metadata.disposed_at_unix_ms,
            TaskState::Candidate,
            TaskState::Integrated,
            transition_event,
            "task attempt integration disposition",
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, graph, _, provenance) = load_sprint_definition(
            &transaction,
            &integrated.metadata.attempt.worker_lease.sprint_id,
        )?;
        reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
        let graph =
            graph.ok_or_else(|| LedgerError::SprintGraphNotAttached(spec.sprint_id.clone()))?;
        disposition.validate_for_budget(spec.budget.max_attempts_per_task)?;
        task_attempt_authority::require_exact(&transaction, &integrated.metadata.attempt)?;
        let admitted_effect = load_effect_from(&transaction, &observation.effect_id)?;
        if admitted_effect.dispatch_claim.is_some()
            || effect_requires_claimed_phase_terminal(&transaction, &observation.effect_id)?
        {
            return Err(reference_mismatch(
                "task attempt integration disposition",
                "current admissions require integrate_claimed_task_attempt with move-only claimed authority",
            ));
        }
        if let Some(existing_id) = transaction
            .query_row(
                "SELECT disposition_id FROM task_attempt_dispositions
                 WHERE disposition_id = ?1 OR attempt_id = ?2
                    OR integration_receipt_id = ?3 OR transition_event_id = ?4",
                params![
                    integrated.metadata.disposition_id,
                    integrated.metadata.attempt.attempt_id,
                    integrated.integration_receipt.receipt_id,
                    integrated.metadata.state_transition_event_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let stored = task_attempt_authority::load_disposition(
                &transaction,
                &existing_id,
                spec.budget.max_attempts_per_task,
            )?;
            let effect = load_effect_from(&transaction, &observation.effect_id)?;
            let stored_evidence = load_task_integration_evidence_from(
                &transaction,
                &integrated.integration_receipt.receipt_id,
            )?;
            let stored_transition =
                load_event_by_id(&transaction, &integrated.metadata.state_transition_event_id)?;
            if stored == *disposition
                && effect.observation.as_ref() == Some(observation)
                && effect.evidence_bytes.as_deref() == Some(evidence_bytes.as_slice())
                && effect.terminal_event.as_ref() == Some(effect_terminal_event)
                && stored_evidence == *evidence
                && stored_transition == *transition_event
            {
                transaction.commit()?;
                return Ok(stored);
            }
            return Err(reference_mismatch(
                "task attempt integration disposition",
                "attempt, receipt, observation, or transition is already bound differently",
            ));
        }
        if current_task_state(
            &transaction,
            &spec.sprint_id,
            &integrated.metadata.attempt.worker_lease.task_id,
        )? != TaskState::Candidate
        {
            return Err(reference_mismatch(
                "task attempt integration disposition",
                "durable task state is not Candidate",
            ));
        }
        let admission_id = transaction
            .query_row(
                "SELECT admission_id FROM task_attempt_integration_admissions
                 WHERE attempt_id = ?1 AND candidate_boundary_id = ?2
                   AND effect_id = ?3",
                params![
                    integrated.metadata.attempt.attempt_id,
                    integrated.candidate_boundary.boundary_id,
                    observation.effect_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| LedgerError::ArtifactNotFound {
                entity: "task attempt integration admission",
                id: observation.effect_id.clone(),
            })?;
        let admission =
            task_attempt_authority::load_integration_admission(&transaction, &admission_id)?;
        validate_integration_result_against_admission(integrated, evidence, &admission)?;
        let persisted =
            validate_new_effect_observation(&transaction, observation, effect_terminal_event)?;
        validate_task_integration_artifact_binding(&persisted, evidence)?;
        validate_task_integration_receipt(
            &transaction,
            &persisted,
            observation,
            &evidence.receipt,
            true,
        )?;
        validate_task_integration_validation_binding(
            &transaction,
            &persisted,
            observation,
            evidence,
        )?;
        validate_task_state_transition(&transaction, &graph, transition_event)?;

        task_attempt_authority::insert_integrated_result_coverage(
            &transaction,
            &integrated.metadata.disposition_id,
            &evidence.receipt.receipt_id,
            &admission_id,
            &integrated.metadata.attempt.attempt_id,
        )?;
        insert_finish_receipt_id(
            &transaction,
            &evidence.receipt.receipt_id,
            &evidence.receipt.sprint_id,
            "TaskIntegration",
        )?;
        insert_task_integration_receipt(&transaction, &evidence.receipt)?;
        insert_agent_event(&transaction, effect_terminal_event)?;
        validate_new_event(&transaction, transition_event)?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_effect_observation(&transaction, observation, &effect_terminal_event.event_id)?;
        task_attempt_authority::insert_disposition(&transaction, disposition)?;
        insert_agent_event(&transaction, transition_event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "task attempt integration disposition",
                recovery_id: observation.effect_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "task attempt integration disposition",
            &observation.effect_id,
            |ledger| {
                let stored =
                    ledger.load_task_attempt_disposition(&integrated.metadata.disposition_id)?;
                if stored != *disposition
                    || ledger.load_task_integration_evidence(&evidence.receipt.receipt_id)?
                        != *evidence
                {
                    return Err(LedgerError::Corrupt {
                        entity: "task attempt integration disposition",
                        detail: "post-commit readback differs from integrated authority".into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Atomically records one claimed task-integration effect and its exact
    /// `Integrated` task-attempt disposition.
    ///
    /// This is the only successful terminal path for a dispatch claim carrying
    /// `TaskIntegration` authority. It requires direct `WorkerPublication`
    /// evidence from the exact claimed worker session, persists the immutable
    /// claim ID on the observation, and commits the receipt, artifact evidence,
    /// disposition, and `Candidate -> Integrated` event as one unit.
    ///
    /// The original move-only authority is returned only when failure is proven
    /// to occur before [`rusqlite::Transaction::commit`] is invoked. Once the
    /// commit-attempt boundary is reached, custody is destroyed and every error
    /// is reconciliation-only.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimedObservationWriteFailure`] for a crossed authority,
    /// non-direct validation provenance, non-Integrated disposition, stale
    /// phase, mismatched admission/effect/receipt/artifact/event, storage
    /// failure, or uncertain post-commit readback.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn integrate_claimed_task_attempt(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        disposition: &TaskAttemptDisposition,
        observation: &EffectObservation,
        effect_terminal_event: &AgentEvent,
        evidence: &TaskIntegrationEvidence,
        transition_event: &AgentEvent,
    ) -> Result<TaskAttemptDisposition, ClaimedObservationWriteFailure> {
        let evidence_bytes = match (|| -> Result<Vec<u8>, LedgerError> {
            self.require_writable()?;
            if authority.ledger_instance_id != self.instance_id {
                return Err(reference_mismatch(
                    "runner effect observation authority",
                    "authority belongs to another open EventLedger instance",
                ));
            }
            observation.validate()?;
            effect_terminal_event.validate()?;
            transition_event.validate()?;
            evidence.validate()?;
            require_successful_effect_kind(observation, EffectKind::IntegrateChangeSet)?;
            if evidence.validation.mode != TaskIntegrationValidationMode::WorkerPublication {
                return Err(reference_mismatch(
                    "claimed task attempt integration",
                    "direct claimed integration requires WorkerPublication evidence",
                ));
            }
            let TaskAttemptDisposition::Integrated(integrated) = disposition else {
                return Err(reference_mismatch(
                    "claimed task attempt integration",
                    "claimed integration accepts only the Integrated disposition variant",
                ));
            };
            let evidence_bytes = canonical_finish_evidence(
                "task integration evidence",
                &observation.effect_id,
                evidence,
                observation.outcome.evidence_digest(),
            )?;
            if integrated.candidate_boundary.attempt != integrated.metadata.attempt
                || integrated.integration_receipt != evidence.receipt
                || integrated.evidence.canonical_bytes != evidence_bytes
                || integrated.evidence.digest != Digest::sha256(&evidence_bytes)
                || integrated.evidence.kind != crate::TaskAttemptEvidenceKind::Integrated
                || observation.effect_id != evidence.receipt.effect_id
                || observation.observation_id != evidence.receipt.observation_id
                || evidence.validation.runner_launch_id != authority.launch.launch_id
                || evidence.validation.runner_session_id != authority.session.session_id
            {
                return Err(reference_mismatch(
                    "claimed task attempt integration",
                    "disposition and direct evidence must retain the exact claimed candidate, effect, worker session, and artifact",
                ));
            }
            validate_attempt_phase_event(
                &integrated.metadata.attempt,
                &integrated.metadata.state_transition_event_id,
                integrated.metadata.disposed_at_unix_ms,
                TaskState::Candidate,
                TaskState::Integrated,
                transition_event,
                "claimed task attempt integration",
            )?;
            Ok(evidence_bytes)
        })() {
            Ok(evidence_bytes) => evidence_bytes,
            Err(error) => {
                return Err(ClaimedObservationWriteFailure::definitely_precommit(
                    error, authority,
                ));
            }
        };

        let transaction = match self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(error) => {
                return Err(ClaimedObservationWriteFailure::definitely_precommit(
                    error.into(),
                    authority,
                ));
            }
        };
        let precommit = (|| -> Result<(), LedgerError> {
            let TaskAttemptDisposition::Integrated(integrated) = disposition else {
                unreachable!("validated Integrated disposition changed while borrowed")
            };
            let (spec, graph, _, provenance) = load_sprint_definition(
                &transaction,
                &integrated.metadata.attempt.worker_lease.sprint_id,
            )?;
            reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
            let graph =
                graph.ok_or_else(|| LedgerError::SprintGraphNotAttached(spec.sprint_id.clone()))?;
            disposition.validate_for_budget(spec.budget.max_attempts_per_task)?;
            task_attempt_authority::require_exact(&transaction, &integrated.metadata.attempt)?;
            if current_task_state(
                &transaction,
                &spec.sprint_id,
                &integrated.metadata.attempt.worker_lease.task_id,
            )? != TaskState::Candidate
            {
                return Err(reference_mismatch(
                    "claimed task attempt integration",
                    "durable task state is not Candidate",
                ));
            }
            let admission_id = transaction
                .query_row(
                    "SELECT admission_id FROM task_attempt_integration_admissions
                     WHERE attempt_id = ?1 AND candidate_boundary_id = ?2
                       AND effect_id = ?3",
                    params![
                        integrated.metadata.attempt.attempt_id,
                        integrated.candidate_boundary.boundary_id,
                        observation.effect_id,
                    ],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| LedgerError::ArtifactNotFound {
                    entity: "task attempt integration admission",
                    id: observation.effect_id.clone(),
                })?;
            let admission =
                task_attempt_authority::load_integration_admission(&transaction, &admission_id)?;
            let authorized_admission =
                authority.integration_admission.as_ref().ok_or_else(|| {
                    reference_mismatch(
                        "claimed task attempt integration",
                        "observation authority is not TaskIntegration authority",
                    )
                })?;
            if authority.formal_check_admission.is_some()
                || authority.running_boundary.is_some()
                || &admission != authorized_admission
            {
                return Err(reference_mismatch(
                    "claimed task attempt integration",
                    "stored admission differs from the exact move-only integration authority",
                ));
            }
            validate_integration_result_against_admission(integrated, evidence, &admission)?;
            if transaction
                .query_row(
                    "SELECT 1 FROM task_attempt_dispositions
                     WHERE disposition_id = ?1 OR attempt_id = ?2
                        OR integration_receipt_id = ?3 OR transition_event_id = ?4",
                    params![
                        integrated.metadata.disposition_id,
                        integrated.metadata.attempt.attempt_id,
                        integrated.integration_receipt.receipt_id,
                        integrated.metadata.state_transition_event_id,
                    ],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                return Err(LedgerError::ArtifactAlreadyExists {
                    entity: "task attempt integration disposition",
                    id: integrated.metadata.disposition_id.clone(),
                });
            }
            let persisted =
                validate_new_effect_observation(&transaction, observation, effect_terminal_event)?;
            validate_runner_effect_observation_authority(
                &transaction,
                &authority.effect,
                &authority.claim,
                &authority.launch,
                &authority.session,
                authority.running_boundary.as_ref(),
                authority.formal_check_admission.as_ref(),
                authority.integration_admission.as_ref(),
                authority.final_verification_admission.as_ref(),
                authority.application_admission.as_deref(),
                authority.live_state_capture_admission.as_deref(),
                &persisted,
            )?;
            validate_task_integration_artifact_binding(&persisted, evidence)?;
            validate_task_integration_receipt(
                &transaction,
                &persisted,
                observation,
                &evidence.receipt,
                true,
            )?;
            validate_task_integration_validation_binding(
                &transaction,
                &persisted,
                observation,
                evidence,
            )?;
            validate_task_state_transition(&transaction, &graph, transition_event)?;

            task_attempt_authority::insert_integrated_result_coverage(
                &transaction,
                &integrated.metadata.disposition_id,
                &evidence.receipt.receipt_id,
                &admission_id,
                &integrated.metadata.attempt.attempt_id,
            )?;
            insert_finish_receipt_id(
                &transaction,
                &evidence.receipt.receipt_id,
                &evidence.receipt.sprint_id,
                "TaskIntegration",
            )?;
            insert_task_integration_receipt(&transaction, &evidence.receipt)?;
            insert_agent_event(&transaction, effect_terminal_event)?;
            validate_new_event(&transaction, transition_event)?;
            insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &effect_terminal_event.event_id,
                &authority.claim.dispatch_claim_id,
            )?;
            task_attempt_authority::insert_disposition(&transaction, disposition)?;
            insert_agent_event(&transaction, transition_event)?;
            Ok(())
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }

        let claim_id = authority.claim.dispatch_claim_id.clone();
        drop(authority);
        if let Err(error) = transaction.commit() {
            return Err(ClaimedObservationWriteFailure::commit_attempted(
                LedgerError::PostCommitStateUncertain {
                    operation: "claimed task attempt integration disposition",
                    recovery_id: observation.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        let TaskAttemptDisposition::Integrated(integrated) = disposition else {
            unreachable!("validated Integrated disposition changed while borrowed")
        };
        self.read_back_authority_after_commit(
            "claimed task attempt integration disposition",
            &observation.effect_id,
            |ledger| {
                let stored =
                    ledger.load_task_attempt_disposition(&integrated.metadata.disposition_id)?;
                let stored_evidence =
                    ledger.load_task_integration_evidence(&evidence.receipt.receipt_id)?;
                let effect = ledger.load_effect(&observation.effect_id)?;
                if stored != *disposition
                    || stored_evidence != *evidence
                    || effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || effect.terminal_event.as_ref() != Some(effect_terminal_event)
                    || effect
                        .dispatch_claim
                        .as_ref()
                        .map(|claim| claim.dispatch_claim_id.as_str())
                        != Some(claim_id.as_str())
                {
                    return Err(LedgerError::Corrupt {
                        entity: "claimed task attempt integration disposition",
                        detail: "post-commit readback differs from exact claimed integration"
                            .into(),
                    });
                }
                Ok(stored)
            },
        )
        .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Atomically closes an exact current attempt that never admitted any
    /// launch authority, computing retry versus exhaustion from the immutable
    /// sprint budget.
    ///
    /// The transaction inserts the no-launch release, computed disposition,
    /// and exact task transition as one crash-binary unit. Callers cannot
    /// select `Retryable` versus `AttemptsExhausted`.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for crossed identity, stale state, any launch,
    /// session, effect, preparation, native authority, wrong transition, or a
    /// conflicting replay.
    #[allow(clippy::too_many_lines)] // Exact replay and the computed release/disposition/event commit stay visibly contiguous.
    pub fn close_never_launched_task_attempt(
        &mut self,
        release: &WorkerLeaseNeverLaunchedRelease,
        metadata: &TaskAttemptDispositionMetadata,
        event: &AgentEvent,
    ) -> Result<TaskAttemptDisposition, LedgerError> {
        self.require_writable()?;
        release.validate()?;
        event.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (spec, graph, _, provenance) =
            load_sprint_definition(&transaction, &release.attempt.worker_lease.sprint_id)?;
        reject_legacy_unproven_work(&spec.sprint_id, &provenance)?;
        let graph =
            graph.ok_or_else(|| LedgerError::SprintGraphNotAttached(spec.sprint_id.clone()))?;
        task_attempt_authority::require_exact(&transaction, &release.attempt)?;
        let disposition = task_attempt_authority::computed_never_launched_disposition(
            metadata.clone(),
            release.clone(),
            spec.budget.max_attempts_per_task,
        )?;
        let existing_disposition_id = transaction
            .query_row(
                "SELECT disposition_id
                 FROM task_attempt_dispositions
                 WHERE attempt_id = ?1",
                [&release.attempt.attempt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_disposition_id) = existing_disposition_id {
            let existing_release_id = transaction
                .query_row(
                    "SELECT release_id
                     FROM worker_lease_never_launched_releases
                     WHERE attempt_id = ?1",
                    [&release.attempt.attempt_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let stored = task_attempt_authority::load_disposition(
                &transaction,
                &existing_disposition_id,
                spec.budget.max_attempts_per_task,
            )?;
            let stored_release = existing_release_id
                .as_deref()
                .map(|release_id| {
                    task_attempt_authority::load_never_launched_release(&transaction, release_id)
                })
                .transpose()?;
            let stored_event =
                load_event_by_id(&transaction, &stored.metadata().state_transition_event_id)?;
            if existing_disposition_id == metadata.disposition_id
                && stored == disposition
                && stored_release.as_ref() == Some(release)
                && stored_event == *event
            {
                transaction.commit()?;
                return Ok(stored);
            }
            return Err(reference_mismatch(
                "never-launched disposition",
                "attempt is already closed by a different release, disposition, or event",
            ));
        }
        let from_state = current_task_state(
            &transaction,
            &spec.sprint_id,
            &release.attempt.worker_lease.task_id,
        )?;
        if from_state != metadata.from_state
            || metadata.attempt != release.attempt
            || metadata.state_transition_event_id != event.event_id
            || metadata.disposed_at_unix_ms != event.occurred_at_unix_ms
        {
            return Err(reference_mismatch(
                "never-launched disposition",
                "metadata must match the exact current attempt state and transition event",
            ));
        }
        let lease = &release.attempt.worker_lease;
        let expected_to = match &disposition {
            TaskAttemptDisposition::Retryable(_) => "Ready",
            TaskAttemptDisposition::AttemptsExhausted(_) => "Failed",
            _ => unreachable!("computed no-launch disposition is closed"),
        };
        let transition_matches = matches!(
            &event.payload,
            AgentEventKind::TaskStateChanged { from, to }
                if from == &format!("{:?}", metadata.from_state) && to == expected_to
        );
        if event.sprint_id != lease.sprint_id
            || event.task_id.as_deref() != Some(lease.task_id.as_str())
            || event.worker_id.as_deref() != Some(lease.worker_id.as_str())
            || !transition_matches
            || graph.task(&lease.task_id).is_none()
        {
            return Err(reference_mismatch(
                "never-launched disposition",
                "event must be the exact computed task transition for this attempt",
            ));
        }
        validate_new_event(&transaction, event)?;
        task_attempt_authority::insert_never_launched_release(
            &transaction,
            release,
            &metadata.disposition_id,
        )?;
        task_attempt_authority::insert_disposition(&transaction, &disposition)?;
        insert_agent_event(&transaction, event)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "never-launched disposition",
                recovery_id: release.attempt.attempt_id.clone(),
                detail: error.to_string(),
            })?;
        self.read_back_authority_after_commit(
            "never-launched disposition",
            &release.attempt.attempt_id,
            |ledger| {
                let stored = task_attempt_authority::load_disposition(
                    &ledger.connection,
                    &metadata.disposition_id,
                    spec.budget.max_attempts_per_task,
                )?;
                if stored != disposition {
                    return Err(LedgerError::Corrupt {
                        entity: "never-launched disposition",
                        detail: "post-commit readback differs from computed disposition".into(),
                    });
                }
                Ok(stored)
            },
        )
    }

    /// Loads one exact typed task-attempt disposition.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent, noncanonical, crossed, or
    /// over-budget disposition.
    pub fn load_task_attempt_disposition(
        &self,
        disposition_id: &str,
    ) -> Result<TaskAttemptDisposition, LedgerError> {
        let attempt_id: String = self.connection.query_row(
            "SELECT attempt_id FROM task_attempt_dispositions WHERE disposition_id = ?1",
            [disposition_id],
            |row| row.get(0),
        )?;
        let attempt = task_attempt_authority::load(&self.connection, &attempt_id)?;
        let (spec, _, _) = load_sprint_inputs(&self.connection, &attempt.worker_lease.sprint_id)?;
        task_attempt_authority::load_disposition(
            &self.connection,
            disposition_id,
            spec.budget.max_attempts_per_task,
        )
    }

    /// Loads the exact ordered schema-v15/legacy attempt history for one graph
    /// task. This is the sole scheduler and recovery projection; callers do
    /// not assemble loose attempt, phase, disposition, or lease vectors.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an unknown graph task, noncanonical nested
    /// authority, ordinal/budget mismatch, impossible phase shape, or crossed
    /// active/released lease state.
    pub fn load_task_attempt_history(
        &self,
        sprint_id: &str,
        task_id: &str,
    ) -> Result<TaskAttemptHistory, LedgerError> {
        load_task_attempt_history_from(&self.connection, sprint_id, task_id)
    }

    /// Loads one canonical lease acquisition, including released history.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the lease is absent, its durable envelope
    /// or indexed identity is corrupt, or storage cannot be read.
    pub fn load_worker_lease(&self, lease_id: &str) -> Result<WorkerLease, LedgerError> {
        worker_lease_authority::load(&self.connection, lease_id, false)
    }

    /// Loads the exact active leases in ascending epoch order.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when any active lease is corrupt or storage
    /// cannot be read.
    pub fn load_active_worker_leases(
        &self,
        sprint_id: &str,
    ) -> Result<Vec<WorkerLease>, LedgerError> {
        worker_lease_authority::load_active(&self.connection, sprint_id)
    }

    /// Loads active leases owned by other sprints on this sprint's exact
    /// authenticated canonical workspace.
    ///
    /// Feed this deterministic readback into
    /// [`crate::SchedulerInput::workspace_blocking_leases`] so pure planning
    /// and atomic SQL acquisition apply the same cross-sprint scope fence.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the sprint is unknown or legacy-unproven,
    /// any blocking lease is corrupt, or storage cannot be read.
    pub fn load_workspace_blocking_worker_leases(
        &self,
        sprint_id: &str,
    ) -> Result<Vec<WorkerLease>, LedgerError> {
        worker_lease_authority::load_workspace_blocking(&self.connection, sprint_id)
    }

    /// Atomically appends one validated event at the next sprint sequence.
    ///
    /// Existing rows cannot be updated or deleted because the migrated schema
    /// enforces append-only triggers in addition to this API boundary.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] for an invalid event, unknown sprint, duplicate
    /// event identifier, missing or cross-sprint causation, non-monotonic
    /// sequence, serialization failure, or `SQLite` failure.
    pub fn append_event(&mut self, event: &AgentEvent) -> Result<(), LedgerError> {
        self.require_writable()?;
        event.validate()?;
        if matches!(
            &event.payload,
            AgentEventKind::ToolProposed { .. }
                | AgentEventKind::ToolFinished { .. }
                | AgentEventKind::SprintTerminalRecorded { .. }
        ) {
            return Err(reference_mismatch(
                "agent event",
                "effect and terminal lifecycle events must be committed by their atomic ledger APIs",
            ));
        }
        if matches!(
            &event.payload,
            AgentEventKind::TaskStateChanged { from, to }
                if from == "Ready" && to == "Leased"
        ) {
            return Err(reference_mismatch(
                "agent event",
                "Ready-to-Leased transitions require atomic worker-lease acquisition",
            ));
        }
        if matches!(
            &event.payload,
            AgentEventKind::TaskStateChanged { from, to }
                if (from == "Leased" && to == "Running")
                    || (from == "Running" && to == "Verifying")
                    || (from == "Verifying" && to == "Candidate")
                    || (from == "Candidate" && to == "Integrated")
                    || (matches!(from.as_str(), "Leased" | "Running" | "Verifying" | "Candidate")
                        && matches!(to.as_str(), "Ready" | "Blocked" | "Failed" | "Canceled" | "Unknown"))
        ) {
            return Err(reference_mismatch(
                "agent event",
                "attempt phase and disposition transitions require their specialized atomic v15 API",
            ));
        }
        if matches!(
            &event.payload,
            AgentEventKind::SprintStateChanged { to, .. } if to == "FinalVerification"
        ) {
            return Err(reference_mismatch(
                "agent event",
                "every transition into FinalVerification requires the atomic schema-v21 admission API",
            ));
        }
        let event_json = encode("agent event", event)?;
        let sequence = sqlite_integer("agent_event.sequence", event.sequence)?;
        let occurred_at =
            sqlite_integer("agent_event.occurred_at_unix_ms", event.occurred_at_unix_ms)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, graph, _, provenance) = load_sprint_definition(&transaction, &event.sprint_id)?;
        reject_legacy_unproven_work(&event.sprint_id, &provenance)?;
        reject_unresolved_mutation_work(&transaction, &event.sprint_id)?;
        reject_legacy_finish_gap_work(&transaction, &event.sprint_id)?;
        validate_event_for_sprint_phase(event, graph.as_ref())?;
        validate_sprint_phase_transition(&transaction, event)?;
        if let (Some(graph), AgentEventKind::TaskStateChanged { .. }) =
            (graph.as_ref(), &event.payload)
        {
            validate_task_state_transition(&transaction, graph, event)?;
        }
        ensure_sprint_not_terminal(&transaction, &event.sprint_id)?;
        if event_exists(&transaction, &event.event_id)? {
            return Err(LedgerError::EventAlreadyExists(event.event_id.clone()));
        }

        let expected = next_sequence(&transaction, &event.sprint_id)?;
        if event.sequence != expected {
            return Err(LedgerError::SequenceMismatch {
                sprint_id: event.sprint_id.clone(),
                expected,
                actual: event.sequence,
            });
        }
        validate_causation(&transaction, event)?;

        transaction.execute(
            "INSERT INTO agent_events (
                sprint_id, sequence, event_id, contract_version,
                occurred_at_unix_ms, event_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.sprint_id,
                sequence,
                event.event_id,
                i64::from(event.contract_version),
                occurred_at,
                event_json
            ],
        )?;
        transaction.commit()?;
        secure_database_files(&self.database_path)
    }

    /// Atomically commits a side-effect intent and its exact `ToolProposed`
    /// event before execution may begin.
    ///
    /// The input snapshot must already be durable for this sprint. The event's
    /// sprint, task, worker, causation, correlation, policy, timestamp,
    /// idempotency key, and canonical tool name must exactly match the intent.
    /// `request_bytes` must contain the non-empty canonical request preimage,
    /// must not exceed [`MAX_EFFECT_REQUEST_BYTES`], and must hash to
    /// `intent.request_digest`. The bytes, event, and intent share one
    /// transaction; no digest-only write path exists.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an invalid or mismatched contract, unknown
    /// sprint/task/snapshot, digest mismatch, payload-size violation, duplicate
    /// effect or sprint idempotency key, non-next event, terminal sprint, or
    /// durable-storage failure. Every pre-commit failure rolls back all rows. A
    /// [`LedgerError::PostCommitStateUncertain`] explicitly means the rows did
    /// commit and the caller must reload rather than execute or retry.
    pub fn record_effect_intent(
        &mut self,
        intent: &EffectIntent,
        request_bytes: &[u8],
        event: &AgentEvent,
    ) -> Result<PersistedEffect, LedgerError> {
        self.record_effect_intent_inner(intent, request_bytes, event, None, None, None)
    }

    /// Atomically commits a runner-owned effect intent with its exact immutable
    /// runner-session binding.
    ///
    /// This is the only intent path that can make a runner effect eligible for
    /// v9 completion. The session binding commits before execution in the same
    /// transaction and has no backfill API.
    ///
    /// # Errors
    ///
    /// Returns the ordinary intent errors plus a mismatch when the registered
    /// session role, logical worker, compiled policy, sprint, or registration
    /// time does not authorize this effect kind.
    pub fn record_runner_effect_intent(
        &mut self,
        intent: &EffectIntent,
        request_bytes: &[u8],
        event: &AgentEvent,
        session_id: &str,
    ) -> Result<PersistedEffect, LedgerError> {
        self.record_effect_intent_inner(intent, request_bytes, event, Some(session_id), None, None)
    }

    /// Atomically commits a fresh runner effect and returns its non-reloadable,
    /// one-use dispatch capability.
    ///
    /// This is the only API that can mint a
    /// [`FreshRunnerEffectDispatchPermit`]. The ordinary persisted effect and
    /// its exact session binding commit through the same transaction used by
    /// [`Self::record_runner_effect_intent`]. A permit is returned only after a
    /// second canonical readback exact-compares the fresh effect, immutable
    /// launch, initialized session, and task Running boundary (when present).
    /// Existing, duplicated, recovered, or post-commit-uncertain effects never
    /// yield a permit.
    ///
    /// # Errors
    ///
    /// Returns the ordinary runner-intent errors, or
    /// [`LedgerError::PostCommitStateUncertain`] when the fresh rows committed
    /// but the complete dispatch authority could not be hardened and read back
    /// exactly. Either error path returns no execution capability; callers must
    /// reconcile durable state and must not retry the effect.
    pub fn record_runner_effect_intent_for_dispatch(
        &mut self,
        intent: &EffectIntent,
        request_bytes: &[u8],
        event: &AgentEvent,
        session_id: &str,
    ) -> Result<(PersistedEffect, FreshRunnerEffectDispatchPermit), LedgerError> {
        if matches!(
            intent.kind,
            EffectKind::ProviderRequest | EffectKind::CleanupWorkerDomain
        ) {
            return Err(reference_mismatch(
                "fresh runner effect dispatch permit",
                "provider requests and cleanup obligations cannot receive ordinary runner dispatch authority",
            ));
        }
        let session = self.load_runner_session(&intent.sprint_id, session_id)?;
        if session.purpose != RunnerSessionPurpose::TaskWorker {
            return Err(reference_mismatch(
                "fresh runner effect dispatch permit",
                "generic dispatch admits only TaskRunning effects; finish-critical roles require their phase-specific v19 admission",
            ));
        }
        let committed = self.record_effect_intent_inner(
            intent,
            request_bytes,
            event,
            Some(session_id),
            None,
            None,
        )?;
        self.read_back_authority_after_commit(
            "runner effect dispatch authority",
            &intent.effect_id,
            |ledger| {
                let persisted = load_effect_from(&ledger.connection, &intent.effect_id)?;
                if persisted != committed
                    || persisted.intent != *intent
                    || persisted.request_bytes != request_bytes
                    || persisted.proposed_event != *event
                {
                    return Err(LedgerError::Corrupt {
                        entity: "fresh runner effect dispatch permit",
                        detail: "post-commit effect readback differs from the freshly inserted intent, request, or proposal".into(),
                    });
                }
                let binding = load_effect_runner_binding(&ledger.connection, &persisted.intent)?;
                let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
                    entity: "fresh runner effect dispatch permit",
                    detail: "ordinary runner effect is not bound to an initialized session".into(),
                })?;
                if session.session_id != session_id {
                    return Err(LedgerError::Corrupt {
                        entity: "fresh runner effect dispatch permit",
                        detail: "post-commit session binding differs from the requested session"
                            .into(),
                    });
                }
                let running_boundary = load_runner_effect_dispatch_running_boundary(
                    &ledger.connection,
                    &session,
                )?;
                validate_fresh_runner_effect_dispatch_authority(
                    &persisted,
                    &binding.launch,
                    &session,
                    running_boundary.as_ref(),
                    &persisted.intent,
                    &persisted.request_bytes,
                    &binding.launch,
                    &session,
                    running_boundary.as_ref(),
                )?;
                let permit = FreshTaskRunningEffectDispatchPermit {
                    effect: persisted.clone(),
                    launch: binding.launch,
                    session,
                    running_boundary,
                    output_capture_intent: None,
                    sensitive_output_detection_policy: None,
                    ledger_instance_id: ledger.instance_id,
                };
                Ok((
                    persisted,
                    FreshRunnerEffectDispatchPermit::TaskRunning(Box::new(permit)),
                ))
            },
        )
    }

    /// Atomically commits one caller-preallocated v27 capture intent with its
    /// exact fresh task-worker `RunCommand` effect.
    ///
    /// Exact replay returns durable state without a transport capability.
    /// Any acquisition, dispatch claim, observation, or terminal state is
    /// classified as reconciliation-only. Only the invocation that actually
    /// commits and exactly reads back the pristine rows receives a move-only
    /// permit.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for crossed source/private-state authority,
    /// conflicting replay, a non-command effect, storage failure, or uncertain
    /// commit/readback.
    #[allow(clippy::too_many_lines)]
    pub fn admit_runner_command_output_capture_intent_for_dispatch(
        &mut self,
        intent: &EffectIntent,
        request_bytes: &[u8],
        event: &AgentEvent,
        session_id: &str,
        output_capture_intent: &CommandOutputCaptureIntentV1,
    ) -> Result<CommandOutputCaptureIntentAdmission, LedgerError> {
        self.require_writable()?;
        if intent.kind != EffectKind::RunCommand {
            return Err(reference_mismatch(
                "command output capture admission",
                "v27 capture admission requires exactly one RunCommand effect",
            ));
        }
        output_capture_intent.validate()?;

        if let Some(existing_capture) =
            command_output_capture_authority::load_from_effect(&self.connection, &intent.effect_id)?
        {
            let effect = load_effect_from(&self.connection, &intent.effect_id)?;
            if existing_capture.intent != *output_capture_intent
                || effect.intent != *intent
                || effect.request_bytes != request_bytes
                || effect.proposed_event != *event
            {
                return Err(reference_mismatch(
                    "command output capture admission",
                    "existing effect or capture identity is bound differently",
                ));
            }
            if existing_capture.acquired.is_some()
                || existing_capture.terminal.is_some()
                || existing_capture.reconciliation_obligation_closure.is_some()
                || effect.dispatch_claim.is_some()
                || effect.observation.is_some()
            {
                return Ok(
                    CommandOutputCaptureIntentAdmission::ReconciliationRequired {
                        effect,
                        capture: existing_capture,
                    },
                );
            }
            return Ok(CommandOutputCaptureIntentAdmission::Existing {
                effect,
                capture: existing_capture,
            });
        }
        if self
            .connection
            .query_row(
                "SELECT 1 FROM effect_intents WHERE effect_id = ?1",
                [&intent.effect_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(reference_mismatch(
                "command output capture admission",
                "an existing or historical effect cannot be backfilled or remint v27 authority",
            ));
        }

        let session = self.load_runner_session(&intent.sprint_id, session_id)?;
        if session.purpose != RunnerSessionPurpose::TaskWorker {
            return Err(reference_mismatch(
                "command output capture admission",
                "generic capture admission is task-worker only; finish-critical commands use their phase-specific admission",
            ));
        }
        let committed = self.record_effect_intent_inner(
            intent,
            request_bytes,
            event,
            Some(session_id),
            None,
            Some(output_capture_intent),
        )?;
        self.read_back_authority_after_commit(
            "command output capture admission",
            &intent.effect_id,
            |ledger| {
                let persisted = load_effect_from(&ledger.connection, &intent.effect_id)?;
                let capture = command_output_capture_authority::load_from_effect(
                    &ledger.connection,
                    &intent.effect_id,
                )?
                .ok_or_else(|| LedgerError::Corrupt {
                    entity: "command output capture admission",
                    detail: "fresh effect lacks its atomically admitted capture intent".into(),
                })?;
                if persisted != committed
                    || persisted.intent != *intent
                    || persisted.request_bytes != request_bytes
                    || persisted.proposed_event != *event
                    || capture.intent != *output_capture_intent
                    || capture.acquired.is_some()
                    || capture.terminal.is_some()
                    || capture.reconciliation_obligation_closure.is_some()
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture admission",
                        detail: "post-commit readback differs from exact pristine effect/capture authority".into(),
                    });
                }
                let binding = load_effect_runner_binding(&ledger.connection, &persisted.intent)?;
                let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
                    entity: "command output capture admission",
                    detail: "fresh command lacks its initialized runner session".into(),
                })?;
                if session.session_id != session_id {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture admission",
                        detail: "fresh command session differs on exact readback".into(),
                    });
                }
                let sensitive_output_detection_policy =
                    sensitive_output_rejection::load_policy_for_effect(
                        &ledger.connection,
                        &persisted.intent.effect_id,
                    )?;
                let running_boundary = load_runner_effect_dispatch_running_boundary(
                    &ledger.connection,
                    &session,
                )?;
                validate_fresh_runner_effect_dispatch_authority(
                    &persisted,
                    &binding.launch,
                    &session,
                    running_boundary.as_ref(),
                    &persisted.intent,
                    &persisted.request_bytes,
                    &binding.launch,
                    &session,
                    running_boundary.as_ref(),
                )?;
                let permit = FreshTaskRunningEffectDispatchPermit {
                    effect: persisted.clone(),
                    launch: binding.launch,
                    session,
                    running_boundary,
                    output_capture_intent: Some(output_capture_intent.clone()),
                    sensitive_output_detection_policy,
                    ledger_instance_id: ledger.instance_id,
                };
                Ok(CommandOutputCaptureIntentAdmission::Fresh {
                    effect: persisted,
                    capture,
                    permit: FreshRunnerEffectDispatchPermit::TaskRunning(Box::new(permit)),
                })
            },
        )
    }

    /// Durably claims one freshly committed ordinary runner effect before its
    /// exact opaque transport request may be presented to the runner.
    ///
    /// The fresh permit is consumed before an immediate transaction reloads
    /// and exact-compares the pristine effect, immutable launch, initialized
    /// session, and task Running boundary. The transaction inserts one
    /// immutable claim and can win only if no terminal observation exists.
    /// A transport permit is returned only after commit, database-file
    /// hardening, and exact canonical readback. Any error returns no transport
    /// authority; a possibly committed claim is reconciliation-only.
    ///
    /// `opaque_transport_request_bytes` are bounded and authenticated but not
    /// interpreted by core. The owning adapter is responsible for canonical
    /// runner-wire construction and must later present the same bytes to
    /// [`RunnerEffectTransportPermit::validate_transport_request`].
    ///
    /// # Errors
    ///
    /// Returns a ledger error for empty/oversized transport bytes, a crossed,
    /// stale, terminal, or already-claimed effect, mismatched runner authority,
    /// storage failure, or post-commit uncertainty.
    #[allow(clippy::too_many_lines)] // One transaction revalidates every live authority before minting a capability.
    pub fn claim_runner_effect_dispatch(
        &mut self,
        permit: FreshRunnerEffectDispatchPermit,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        self.claim_runner_effect_dispatch_inner(permit, None, opaque_transport_request_bytes)
    }

    /// Atomically anchors one exact physical capture acquisition with the
    /// deterministic runner dispatch claim and returns transport custody only
    /// after exact durable readback.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a crossed/stale capability, mismatched
    /// acquisition, non-command permit, storage failure, or uncertain commit.
    pub fn claim_command_output_capture_dispatch(
        &mut self,
        permit: FreshRunnerEffectDispatchPermit,
        acquired: CommandOutputCaptureAcquiredV1,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        self.claim_runner_effect_dispatch_inner(
            permit,
            Some(acquired),
            opaque_transport_request_bytes,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn claim_runner_effect_dispatch_inner(
        &mut self,
        permit: FreshRunnerEffectDispatchPermit,
        output_capture_acquired: Option<CommandOutputCaptureAcquiredV1>,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        self.require_writable()?;
        let permit = match permit {
            FreshRunnerEffectDispatchPermit::TaskRunning(permit) => permit,
            FreshRunnerEffectDispatchPermit::TaskFormalCheck(permit) => {
                return self.claim_task_attempt_formal_check_dispatch_inner(
                    permit,
                    output_capture_acquired,
                    opaque_transport_request_bytes,
                );
            }
            FreshRunnerEffectDispatchPermit::TaskIntegration(permit) => {
                if output_capture_acquired.is_some() {
                    return Err(reference_mismatch(
                        "command output capture dispatch",
                        "integration effects cannot consume command capture acquisition",
                    ));
                }
                return self.claim_task_attempt_integration_dispatch(
                    permit,
                    opaque_transport_request_bytes,
                );
            }
            FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit) => {
                return self.claim_sprint_final_verification_dispatch_inner(
                    permit,
                    output_capture_acquired,
                    opaque_transport_request_bytes,
                );
            }
            FreshRunnerEffectDispatchPermit::SprintApplication(permit) => {
                if output_capture_acquired.is_some() {
                    return Err(reference_mismatch(
                        "command output capture dispatch",
                        "application effects cannot consume command capture acquisition",
                    ));
                }
                return self
                    .claim_sprint_application_dispatch(permit, opaque_transport_request_bytes);
            }
            FreshRunnerEffectDispatchPermit::SprintLiveStateCapture(permit) => {
                if output_capture_acquired.is_some() {
                    return Err(reference_mismatch(
                        "command output capture dispatch",
                        "live-state capture effects cannot consume command output acquisition",
                    ));
                }
                return self.claim_sprint_live_state_capture_dispatch(
                    permit,
                    opaque_transport_request_bytes,
                );
            }
            FreshRunnerEffectDispatchPermit::SprintRollback(_) => {
                return Err(reference_mismatch(
                    "runner effect dispatch claim",
                    "ordinary rollback authority remains fail-closed until its phase-specific admission is implemented",
                ));
            }
        };
        let FreshTaskRunningEffectDispatchPermit {
            effect: freshly_committed,
            launch: freshly_committed_launch,
            session: freshly_committed_session,
            running_boundary: freshly_committed_running,
            output_capture_intent,
            sensitive_output_detection_policy,
            ledger_instance_id,
        } = *permit;
        if ledger_instance_id != self.instance_id {
            return Err(reference_mismatch(
                "runner effect dispatch claim",
                "fresh permit belongs to another open EventLedger instance",
            ));
        }
        match (
            &output_capture_intent,
            &output_capture_acquired,
            &sensitive_output_detection_policy,
        ) {
            (Some(intent), Some(acquired), Some(policy)) => {
                acquired.validate_against(intent)?;
                policy.validate()?;
            }
            (Some(_), None, Some(_)) => {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "fresh RunCommand authority requires its exact acquired anchor",
                ));
            }
            (None, Some(_), None) => {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "capture acquisition cannot be attached to a non-capture permit",
                ));
            }
            (None, None, None) => {}
            _ => {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "fresh capture intent, acquisition, and persisted detector policy must be present together",
                ));
            }
        }
        if opaque_transport_request_bytes.is_empty()
            || opaque_transport_request_bytes.len() > MAX_RUNNER_TRANSPORT_REQUEST_BYTES
        {
            return Err(LedgerError::EffectPayloadSize {
                entity: "opaque runner transport request",
                effect_id: freshly_committed.intent.effect_id.clone(),
                actual_bytes: opaque_transport_request_bytes.len(),
                maximum_bytes: MAX_RUNNER_TRANSPORT_REQUEST_BYTES,
            });
        }
        validate_fresh_runner_effect_dispatch_authority(
            &freshly_committed,
            &freshly_committed_launch,
            &freshly_committed_session,
            freshly_committed_running.as_ref(),
            &freshly_committed.intent,
            &freshly_committed.request_bytes,
            &freshly_committed_launch,
            &freshly_committed_session,
            freshly_committed_running.as_ref(),
        )?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_effect_from(&transaction, &freshly_committed.intent.effect_id)?;
        let binding = load_effect_runner_binding(&transaction, &current.intent)?;
        let current_session = binding.session.ok_or_else(|| LedgerError::Corrupt {
            entity: "runner effect dispatch claim",
            detail: "ordinary claimed effect lacks an initialized runner session".into(),
        })?;
        let current_running =
            load_runner_effect_dispatch_running_boundary(&transaction, &current_session)?;
        let current_sensitive_output_detection_policy =
            sensitive_output_rejection::load_policy_for_effect(
                &transaction,
                &current.intent.effect_id,
            )?;
        if current != freshly_committed
            || binding.launch != freshly_committed_launch
            || current_session != freshly_committed_session
            || current_running != freshly_committed_running
            || current_sensitive_output_detection_policy != sensitive_output_detection_policy
        {
            return Err(reference_mismatch(
                "runner effect dispatch claim",
                "fresh permit no longer matches the exact current pristine effect authority",
            ));
        }
        validate_fresh_runner_effect_dispatch_authority(
            &current,
            &binding.launch,
            &current_session,
            current_running.as_ref(),
            &current.intent,
            &current.request_bytes,
            &binding.launch,
            &current_session,
            current_running.as_ref(),
        )?;
        require_current_runner_effect_dispatch_authority(
            &transaction,
            &current,
            &binding.launch,
            &current_session,
            current_running.as_ref(),
        )?;
        let running_boundary_id = current_running
            .as_ref()
            .ok_or_else(|| {
                reference_mismatch(
                    "runner effect dispatch claim",
                    "TaskRunning compatibility admission requires its exact current Running boundary",
                )
            })?
            .boundary_id
            .clone();
        let claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&current.intent.effect_id),
            effect_id: current.intent.effect_id.clone(),
            sprint_id: current.intent.sprint_id.clone(),
            launch_id: binding.launch.launch_id.clone(),
            session_id: current_session.session_id.clone(),
            running_boundary_id: Some(running_boundary_id.clone()),
            authority: RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id,
            },
            request_digest: current.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(opaque_transport_request_bytes),
            policy_hash: current.intent.policy_hash.clone(),
            input_snapshot: current.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        validate_runner_effect_dispatch_claim_binding(
            &claim,
            &current,
            &binding.launch,
            &current_session,
            current_running.as_ref(),
        )?;
        if let Some(acquired) = output_capture_acquired.as_ref() {
            let capture = command_output_capture_authority::load_from_effect(
                &transaction,
                &current.intent.effect_id,
            )?
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "command output capture dispatch",
                detail: "fresh command is missing its exact capture intent".into(),
            })?;
            if capture.intent != *output_capture_intent.as_ref().expect("paired above")
                || capture.acquired.is_some()
                || capture.terminal.is_some()
                || acquired.dispatch_claim_id != claim.dispatch_claim_id
            {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "capture intent, acquisition, or deterministic claim identity is crossed",
                ));
            }
            command_output_capture_authority::insert_acquired(
                &transaction,
                &capture.intent,
                acquired,
            )?;
        }
        insert_runner_effect_dispatch_claim_authority(&transaction, &claim)?;
        insert_runner_effect_dispatch_claim(&transaction, &claim)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "runner effect dispatch claim",
                recovery_id: claim.effect_id.clone(),
                detail: error.to_string(),
            })?;

        let claim_recovery_id = claim.effect_id.clone();
        self.read_back_authority_after_commit(
            "runner effect dispatch claim",
            &claim_recovery_id,
            |ledger| {
                let persisted = load_effect_from(&ledger.connection, &claim.effect_id)?;
                let readback_claim =
                    persisted
                        .dispatch_claim
                        .as_ref()
                        .ok_or_else(|| LedgerError::Corrupt {
                            entity: "runner effect dispatch claim",
                            detail: "committed claim is absent from effect readback".into(),
                        })?;
                let binding = load_effect_runner_binding(&ledger.connection, &persisted.intent)?;
                let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
                    entity: "runner effect dispatch claim",
                    detail: "claimed effect readback lacks its initialized session".into(),
                })?;
                let running =
                    load_runner_effect_dispatch_running_boundary(&ledger.connection, &session)?;
                if readback_claim != &claim
                    || binding.launch != freshly_committed_launch
                    || session != freshly_committed_session
                    || running != freshly_committed_running
                    || persisted.observation.is_some()
                {
                    return Err(LedgerError::Corrupt {
                        entity: "runner effect dispatch claim",
                        detail:
                            "post-commit readback differs from the exact claimed pristine authority"
                                .into(),
                    });
                }
                if let Some(expected_acquired) = output_capture_acquired.as_ref() {
                    let capture = command_output_capture_authority::load_from_effect(
                        &ledger.connection,
                        &claim.effect_id,
                    )?
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "command output capture dispatch",
                        detail: "claimed command lost its capture lifecycle".into(),
                    })?;
                    if capture.acquired.as_ref() != Some(expected_acquired)
                        || capture.terminal.is_some()
                    {
                        return Err(LedgerError::Corrupt {
                            entity: "command output capture dispatch",
                            detail: "post-commit acquired capture readback differs".into(),
                        });
                    }
                }
                let readback_sensitive_output_detection_policy =
                    sensitive_output_rejection::load_policy_for_effect(
                        &ledger.connection,
                        &claim.effect_id,
                    )?;
                if readback_sensitive_output_detection_policy != sensitive_output_detection_policy {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture dispatch",
                        detail: "post-commit detector-policy readback differs from fresh admission"
                            .into(),
                    });
                }
                validate_claimed_runner_effect_dispatch_authority(
                    &persisted,
                    readback_claim,
                    &binding.launch,
                    &session,
                    running.as_ref(),
                    &persisted.intent,
                    &persisted.request_bytes,
                    &binding.launch,
                    &session,
                    running.as_ref(),
                )?;
                Ok((
                    persisted.clone(),
                    RunnerEffectTransportPermit {
                        effect: persisted,
                        claim,
                        launch: binding.launch,
                        session,
                        running_boundary: running,
                        formal_check_admission: None,
                        integration_admission: None,
                        final_verification_admission: None,
                        application_admission: None,
                        live_state_capture_admission: None,
                        sensitive_output_detection_policy,
                        ledger_instance_id,
                    },
                ))
            },
        )
    }

    /// Claims one freshly admitted formal-check effect for runner transport.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed, stale, terminal, already-claimed, or
    /// noncanonical transport authority; the permit is consumed either way.
    pub fn claim_task_attempt_formal_check_dispatch(
        &mut self,
        permit: FreshTaskFormalCheckDispatchPermit,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        self.claim_task_attempt_formal_check_dispatch_inner(
            permit,
            None,
            opaque_transport_request_bytes,
        )
    }

    fn claim_task_attempt_formal_check_dispatch_inner(
        &mut self,
        permit: FreshTaskFormalCheckDispatchPermit,
        output_capture_acquired: Option<CommandOutputCaptureAcquiredV1>,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        let FreshTaskFormalCheckDispatchPermit {
            effect,
            launch,
            session,
            admission,
            output_capture_intent,
            sensitive_output_detection_policy,
            ledger_instance_id,
        } = permit;
        if ledger_instance_id != self.instance_id {
            return Err(reference_mismatch(
                "formal-check dispatch claim",
                "fresh permit belongs to another open EventLedger instance",
            ));
        }
        self.claim_task_phase_dispatch(
            effect,
            launch,
            session,
            RunnerEffectRequestAuthority::TaskFormalCheck {
                formal_check_admission_id: admission.admission_id.clone(),
            },
            Some(admission),
            None,
            output_capture_intent,
            output_capture_acquired,
            sensitive_output_detection_policy,
            opaque_transport_request_bytes,
        )
    }

    /// Claims one freshly admitted integration effect for runner transport.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed, stale, terminal, already-claimed, or
    /// noncanonical transport authority; the permit is consumed either way.
    pub fn claim_task_attempt_integration_dispatch(
        &mut self,
        permit: FreshTaskIntegrationDispatchPermit,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        let FreshTaskIntegrationDispatchPermit {
            effect,
            launch,
            session,
            admission,
            ledger_instance_id,
        } = permit;
        if ledger_instance_id != self.instance_id {
            return Err(reference_mismatch(
                "integration dispatch claim",
                "fresh permit belongs to another open EventLedger instance",
            ));
        }
        self.claim_task_phase_dispatch(
            effect,
            launch,
            session,
            RunnerEffectRequestAuthority::TaskIntegration {
                integration_admission_id: admission.admission_id.clone(),
            },
            None,
            Some(admission),
            None,
            None,
            None,
            opaque_transport_request_bytes,
        )
    }

    /// Claims one freshly admitted sprint final-verification command for
    /// runner transport.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed, stale, moved, terminal, already-claimed,
    /// or noncanonical phase authority. The permit is consumed either way.
    #[allow(clippy::too_many_lines)]
    pub fn claim_sprint_final_verification_dispatch(
        &mut self,
        permit: FreshFinalVerificationDispatchPermit,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        self.claim_sprint_final_verification_dispatch_inner(
            permit,
            None,
            opaque_transport_request_bytes,
        )
    }

    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)] // Consuming the optional acquired anchor keeps the public one-shot dispatch boundary uniform.
    fn claim_sprint_final_verification_dispatch_inner(
        &mut self,
        permit: FreshFinalVerificationDispatchPermit,
        output_capture_acquired: Option<CommandOutputCaptureAcquiredV1>,
        opaque_transport_request_bytes: &[u8],
    ) -> Result<(PersistedEffect, RunnerEffectTransportPermit), LedgerError> {
        self.require_writable()?;
        let FreshFinalVerificationDispatchPermit {
            effect: freshly_committed,
            launch: freshly_committed_launch,
            session: freshly_committed_session,
            admission: freshly_committed_admission,
            output_capture_intent,
            sensitive_output_detection_policy,
            ledger_instance_id,
        } = permit;
        if ledger_instance_id != self.instance_id {
            return Err(reference_mismatch(
                "sprint final-verification dispatch claim",
                "fresh permit belongs to another open EventLedger instance",
            ));
        }
        match (
            &output_capture_intent,
            &output_capture_acquired,
            &sensitive_output_detection_policy,
        ) {
            (Some(intent), Some(acquired), Some(policy)) => {
                acquired.validate_against(intent)?;
                policy.validate()?;
            }
            (Some(_), None, Some(_)) => {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "final-verification command requires its exact acquired anchor",
                ));
            }
            (None, Some(_), None) => {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "acquisition cannot be consumed without fresh final-verification capture authority",
                ));
            }
            (None, None, None) => {}
            _ => {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "fresh final-verification capture intent, acquisition, and persisted detector policy must be present together",
                ));
            }
        }
        if opaque_transport_request_bytes.is_empty()
            || opaque_transport_request_bytes.len() > MAX_RUNNER_TRANSPORT_REQUEST_BYTES
        {
            return Err(LedgerError::EffectPayloadSize {
                entity: "opaque runner transport request",
                effect_id: freshly_committed.intent.effect_id.clone(),
                actual_bytes: opaque_transport_request_bytes.len(),
                maximum_bytes: MAX_RUNNER_TRANSPORT_REQUEST_BYTES,
            });
        }
        if freshly_committed.dispatch_claim.is_some()
            || freshly_committed.observation.is_some()
            || freshly_committed.intent.kind != EffectKind::RunCommand
            || freshly_committed.intent.effect_id != freshly_committed_admission.effect_id
            || freshly_committed.intent.input_snapshot != freshly_committed_admission.final_snapshot
            || freshly_committed_launch.purpose != RunnerSessionPurpose::FinalVerifier
            || freshly_committed_session.purpose != RunnerSessionPurpose::FinalVerifier
        {
            return Err(reference_mismatch(
                "sprint final-verification dispatch claim",
                "fresh permit is not pristine exact FinalVerifier authority",
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_effect_from(&transaction, &freshly_committed.intent.effect_id)?;
        let binding = load_effect_runner_binding(&transaction, &current.intent)?;
        let session = binding.session.ok_or_else(|| LedgerError::Corrupt {
            entity: "sprint final-verification dispatch claim",
            detail: "effect lacks initialized final-verifier session".into(),
        })?;
        let admission = load_sprint_final_verification_admission_envelope_from(
            &transaction,
            &freshly_committed_admission.admission_id,
        )?;
        let current_sensitive_output_detection_policy =
            sensitive_output_rejection::load_policy_for_effect(
                &transaction,
                &current.intent.effect_id,
            )?;
        if current != freshly_committed
            || binding.launch != freshly_committed_launch
            || session != freshly_committed_session
            || admission != freshly_committed_admission
            || current_sensitive_output_detection_policy != sensitive_output_detection_policy
            || current_sprint_phase_state(&transaction, &admission.sprint_id)?
                != SprintState::FinalVerification
            || latest_sprint_phase_event(&transaction, &admission.sprint_id)?
                .as_ref()
                .map(|event| event.event_id.as_str())
                != Some(admission.sprint_phase_event_id.as_str())
            || derive_sprint_final_verification_snapshot(&transaction, &admission.sprint_id)?
                != admission.final_snapshot
        {
            return Err(reference_mismatch(
                "sprint final-verification dispatch claim",
                "fresh permit no longer matches the exact current FinalVerification phase",
            ));
        }
        runner_launch_cleanup_admission::require_open_authoritative(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        runner_launch_cleanup_admission::require_preparation_allows_session_work(
            &transaction,
            &admission.sprint_id,
            &admission.runner_launch_id,
        )?;
        let claim = PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: runner_effect_dispatch_claim_id(&current.intent.effect_id),
            effect_id: current.intent.effect_id.clone(),
            sprint_id: current.intent.sprint_id.clone(),
            launch_id: binding.launch.launch_id.clone(),
            session_id: session.session_id.clone(),
            running_boundary_id: None,
            authority: RunnerEffectRequestAuthority::SprintFinalVerification {
                sprint_phase_event_id: admission.sprint_phase_event_id.clone(),
            },
            request_digest: current.intent.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(opaque_transport_request_bytes),
            policy_hash: current.intent.policy_hash.clone(),
            input_snapshot: current.intent.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        if let Some(acquired) = output_capture_acquired.as_ref() {
            let capture = command_output_capture_authority::load_from_effect(
                &transaction,
                &current.intent.effect_id,
            )?
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "command output capture dispatch",
                detail: "final-verification effect lacks its capture intent".into(),
            })?;
            if capture.intent != *output_capture_intent.as_ref().expect("paired above")
                || capture.acquired.is_some()
                || capture.terminal.is_some()
                || acquired.dispatch_claim_id != claim.dispatch_claim_id
            {
                return Err(reference_mismatch(
                    "command output capture dispatch",
                    "final-verification acquisition is crossed or no longer pristine",
                ));
            }
            command_output_capture_authority::insert_acquired(
                &transaction,
                &capture.intent,
                acquired,
            )?;
        }
        insert_runner_effect_dispatch_claim_authority(&transaction, &claim)?;
        insert_runner_effect_dispatch_claim(&transaction, &claim)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "sprint final-verification dispatch claim",
                recovery_id: claim.effect_id.clone(),
                detail: error.to_string(),
            })?;
        let recovery_id = claim.effect_id.clone();
        self.read_back_authority_after_commit(
            "sprint final-verification dispatch claim",
            &recovery_id,
            |ledger| {
                let persisted = load_effect_from(&ledger.connection, &claim.effect_id)?;
                if persisted.dispatch_claim.as_ref() != Some(&claim)
                    || persisted.observation.is_some()
                    || load_sprint_final_verification_admission_from(
                        &ledger.connection,
                        &admission.admission_id,
                    )? != admission
                {
                    return Err(LedgerError::Corrupt {
                        entity: "sprint final-verification dispatch claim",
                        detail: "post-commit claim readback differs from exact phase authority"
                            .into(),
                    });
                }
                if let Some(expected_acquired) = output_capture_acquired.as_ref() {
                    let capture = command_output_capture_authority::load_from_effect(
                        &ledger.connection,
                        &claim.effect_id,
                    )?
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "command output capture dispatch",
                        detail: "claimed final-verification capture is absent".into(),
                    })?;
                    if capture.acquired.as_ref() != Some(expected_acquired)
                        || capture.terminal.is_some()
                    {
                        return Err(LedgerError::Corrupt {
                            entity: "command output capture dispatch",
                            detail: "final-verification acquisition differs on readback".into(),
                        });
                    }
                }
                let readback_sensitive_output_detection_policy =
                    sensitive_output_rejection::load_policy_for_effect(
                        &ledger.connection,
                        &claim.effect_id,
                    )?;
                if readback_sensitive_output_detection_policy
                    != sensitive_output_detection_policy
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture dispatch",
                        detail: "post-commit detector-policy readback differs from fresh final-verification admission"
                            .into(),
                    });
                }
                Ok((
                    persisted.clone(),
                    RunnerEffectTransportPermit {
                        effect: persisted,
                        claim,
                        launch: binding.launch,
                        session,
                        running_boundary: None,
                        formal_check_admission: None,
                        integration_admission: None,
                        final_verification_admission: Some(admission),
                        application_admission: None,
                        live_state_capture_admission: None,
                        sensitive_output_detection_policy,
                        ledger_instance_id: ledger.instance_id,
                    },
                ))
            },
        )
    }
}
