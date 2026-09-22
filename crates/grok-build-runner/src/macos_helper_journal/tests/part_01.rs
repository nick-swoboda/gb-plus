    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions as StdOpenOptions};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier, mpsc};

    use super::*;
    use crate::macos_helper_lifecycle::{
        intend_launcher_release, intend_launcher_release_for_test, prepare_identity_record,
        record_cleanup_agent, record_empty_domain, record_held_launcher, record_identity_released,
        record_launcher_released,
    };
    use crate::macos_helper_protocol::{
        MACOS_HELPER_PROTOCOL_VERSION, MacosChildDescriptorBinding, MacosChildDescriptorPurpose,
        MacosExecutableIdentity, MacosHeldPreparationEvidence, MacosHelperAttestation,
        MacosHelperInstallAudit, MacosHelperLaunchRequest, MacosHelperNetwork,
        MacosHelperPreparationBinding, MacosProcessObservation, MacosReleaseEvidence,
        MacosTerminationReason, descriptor_bindings_digest,
    };
    use grok_build_core::{
        CONTRACT_VERSION, PersistedRunnerLaunchPreparation, RunnerLaunchPreparationAttempt,
        RunnerLaunchPreparationDisposition, RunnerLaunchPreparationOutcome,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        top: PathBuf,
        root: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temp directory");
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let top = base.join(format!(
                "grok-build-macos-journal-{label}-{}-{sequence}",
                std::process::id()
            ));
            let root = top.join("journal");
            fs::create_dir(&top).expect("create test parent");
            fs::set_permissions(&top, fs::Permissions::from_mode(0o700))
                .expect("set test-parent mode");
            fs::create_dir(&root).expect("create test journal");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("set test-journal mode");
            Self { top, root }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.top);
        }
    }

    fn digest(value: u8) -> Digest {
        Digest::sha256(&[value])
    }

    fn identity(uid: u32) -> MacosExecutionIdentityRecord {
        MacosExecutionIdentityRecord {
            account_name: format!("_grokbuild{uid}"),
            uid,
            gid: uid,
            record_digest: Digest::sha256(&uid.to_be_bytes()),
            login_shell: "/usr/bin/false".into(),
            home_directory: format!("/var/empty/grok-build/{uid}"),
            supplementary_groups: Vec::new(),
            password_locked: true,
            interactive_session_count: 0,
        }
    }

    fn session_and_pool() -> (MacosHelperSession, MacosIdentityPoolObservation) {
        let mut pool = MacosIdentityPoolObservation {
            records: vec![identity(601), identity(602), identity(603)],
            pool_record_digest: digest(0),
        };
        pool.pool_record_digest = pool.computed_digest().expect("pool digest");
        let session = MacosHelperSession {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: 1,
            session_nonce: digest(1),
            helper_binary_digest: digest(2),
            helper_requirement_digest: digest(3),
            client_binary_digest: digest(4),
            client_requirement_digest: digest(5),
            pool_record_digest: pool.pool_record_digest.clone(),
            workspace_grant_hash: digest(6),
            execution_policy_hash: digest(7),
            command_network: MacosHelperNetwork::Denied,
            authenticated_at_unix_ms: 10,
            peer_requirement_matched: true,
            attestation: MacosHelperAttestation::LocalCodeIdentity {
                install_audit: MacosHelperInstallAudit {
                    auditing_uid: 501,
                    binary_owner_uid: 0,
                    binary_mode: 0o755,
                    directory_owner_uid: 0,
                    directory_mode: 0o755,
                },
            },
        };
        (session, pool)
    }

    fn renewed_session(
        original: &MacosHelperSession,
        nonce_marker: u8,
        authenticated_at_unix_ms: u64,
    ) -> MacosHelperSession {
        let mut renewed = original.clone();
        renewed.session_nonce = digest(nonce_marker);
        renewed.authenticated_at_unix_ms = authenticated_at_unix_ms;
        renewed
    }

    fn assigned(uid: u32) -> MacosAssignedIdentity {
        let record = identity(uid);
        MacosAssignedIdentity {
            account_name: record.account_name,
            uid,
            gid: record.gid,
            account_record_digest: record.record_digest,
        }
    }

    fn preparation(suffix: u8) -> MacosHelperPreparationBinding {
        MacosHelperPreparationBinding {
            contract_version: CONTRACT_VERSION,
            attempt_id: format!("attempt-{suffix}"),
            sprint_id: format!("sprint-{suffix}"),
            launch_id: format!("launch-{suffix}"),
            runner_session_id: format!("runner-{suffix}"),
            cleanup_effect_id: format!("cleanup-effect-{suffix}"),
            input_snapshot: digest(19 + suffix),
            native_journal_id: format!("native-journal-{suffix}"),
            expected_platform_binding_digest: digest(20 + suffix),
            claimed_at_unix_ms: 11,
        }
    }

    fn descriptors(suffix: u8) -> Vec<MacosChildDescriptorBinding> {
        [
            (0, MacosChildDescriptorPurpose::StandardInput, true),
            (1, MacosChildDescriptorPurpose::StandardOutput, true),
            (2, MacosChildDescriptorPurpose::StandardError, true),
            (3, MacosChildDescriptorPurpose::HoldControl, false),
            (4, MacosChildDescriptorPurpose::SetupReport, false),
        ]
        .into_iter()
        .map(
            |(target_fd, purpose, inherited_through_exec)| MacosChildDescriptorBinding {
                target_fd,
                purpose,
                object_digest: digest(30 + suffix + u8::try_from(target_fd).unwrap()),
                inherited_through_exec,
            },
        )
        .collect()
    }

    fn request(session: &MacosHelperSession, suffix: u8) -> MacosHelperLaunchRequest {
        let mut request = MacosHelperLaunchRequest {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: session.policy_version,
            session_nonce: session.session_nonce.clone(),
            request_id: format!("request-{suffix}"),
            preparation: preparation(suffix),
            runner_session_id: format!("runner-{suffix}"),
            effect_id: format!("effect-{suffix}"),
            workspace_grant_hash: session.workspace_grant_hash.clone(),
            execution_policy_hash: session.execution_policy_hash.clone(),
            staged_workspace_id: format!("shadow-{suffix}"),
            executable_identity: MacosExecutableIdentity::SystemToolchain {
                policy_entry_id: "cargo-1.97.0".into(),
                binary_digest: digest(8),
            },
            descriptor_bindings: descriptors(suffix),
            argv: vec!["cargo".into(), "test".into()],
            relative_working_directory: ".".into(),
            environment: BTreeMap::new(),
            deadline_unix_ms: 1_000,
            max_output_bytes: 1_024,
            max_processes: 8,
            max_memory_bytes: None,
            command_network: MacosHelperNetwork::Denied,
            seatbelt_profile_digest: digest(9),
            request_digest: digest(0),
        };
        request.request_digest = request.computed_digest().expect("request digest");
        request
    }

    fn held_evidence(
        session: &MacosHelperSession,
        record: &MacosHelperJournalRecord,
        held_at_unix_ms: u64,
    ) -> MacosHeldPreparationEvidence {
        let mut evidence = MacosHeldPreparationEvidence {
            authenticated_session: session.clone(),
            request_digest: record.request.request_digest.clone(),
            preparation: record.request.preparation.clone(),
            assigned_identity: record.assigned_identity.clone().unwrap(),
            descriptor_bindings_digest: descriptor_bindings_digest(
                &record.request.descriptor_bindings,
            )
            .unwrap(),
            setup_readback_digest: digest(40),
            held_at_unix_ms,
            evidence_digest: digest(0),
        };
        evidence.evidence_digest = evidence.computed_digest().unwrap();
        evidence
    }

    fn release_evidence(
        session: &MacosHelperSession,
        record: &MacosHelperJournalRecord,
        released_at_unix_ms: u64,
    ) -> MacosReleaseEvidence {
        let mut evidence = MacosReleaseEvidence {
            authenticated_session: session.clone(),
            request_digest: record.request.request_digest.clone(),
            preparation: record.request.preparation.clone(),
            held_preparation_evidence_digest: record
                .held_preparation_evidence
                .as_ref()
                .unwrap()
                .evidence_digest
                .clone(),
            release_observation_digest: digest(41),
            released_at_unix_ms,
            evidence_digest: digest(0),
        };
        evidence.evidence_digest = evidence.computed_digest().unwrap();
        evidence
    }

    fn release_authorization(
        record: &MacosHelperJournalRecord,
    ) -> crate::macos_helper_protocol::MacosOuterReleaseAuthorizationRecord {
        let expected = &record.request.preparation;
        let held = record.held_preparation_evidence.as_ref().unwrap();
        let persisted = PersistedRunnerLaunchPreparation {
            attempt: RunnerLaunchPreparationAttempt {
                contract_version: expected.contract_version,
                attempt_id: expected.attempt_id.clone(),
                sprint_id: expected.sprint_id.clone(),
                launch_id: expected.launch_id.clone(),
                cleanup_effect_id: expected.cleanup_effect_id.clone(),
                native_journal_id: expected.native_journal_id.clone(),
                expected_platform_binding_digest: expected.expected_platform_binding_digest.clone(),
                claimed_at_unix_ms: expected.claimed_at_unix_ms,
            },
            outcome: Some(RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                native_evidence_bytes: held.canonical_native_evidence_bytes().unwrap(),
                finished_at_unix_ms: held.held_at_unix_ms + 1,
            }),
        };
        crate::macos_helper_protocol::MacosOuterReleaseAuthorizationRecord::try_from_persisted_for_test(
            &persisted,
            expected,
            &record.request,
            held,
            record.assigned_identity.as_ref().unwrap(),
        )
        .unwrap()
    }

    fn observation(sequence: u32, time: u64, uid: u32, sealed: bool) -> MacosProcessObservation {
        let mut observation = MacosProcessObservation {
            sequence,
            observed_at_unix_ms: time,
            uid,
            process_ids: Vec::new(),
            enumeration_digest: digest(0),
            creation_sealed: sealed,
        };
        observation.enumeration_digest = observation.computed_digest().expect("observation digest");
        observation
    }

    fn prepared_transition(
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        suffix: u8,
    ) -> MacosLifecycleTransition {
        prepared_transition_for_uid(session, pool, suffix, 601)
    }

    fn prepared_transition_for_uid(
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        suffix: u8,
        uid: u32,
    ) -> MacosLifecycleTransition {
        let request = request(session, suffix);
        prepare_identity_record(
            session,
            &request,
            &request.preparation,
            pool,
            assigned(uid),
            [
                observation(1, 20, uid, false),
                observation(2, 21, uid, false),
            ],
            22,
        )
        .expect("prepare identity record")
    }

    fn provisioned(
        label: &str,
    ) -> (
        TestDirectory,
        MacosHelperSession,
        MacosIdentityPoolObservation,
        MacosHelperJournalReference,
        MacosHelperJournalStore,
    ) {
        let directory = TestDirectory::new(label);
        let (session, pool) = session_and_pool();
        let (store, reference) =
            MacosHelperJournalStore::provision(&directory.root, &session, &pool)
                .expect("provision journal");
        (directory, session, pool, reference, store)
    }

    fn expect_ready(outcome: MacosJournalAcquireOutcome<'_>) -> MacosJournalReadyLease<'_> {
        match outcome {
            MacosJournalAcquireOutcome::Ready(lease) => lease,
            MacosJournalAcquireOutcome::IndexedPreparationRequired(_) => {
                panic!("expected a ready account lease, found indexed preparation recovery")
            }
            MacosJournalAcquireOutcome::RecoveryRequired(_) => {
                panic!("expected a ready account lease, found recovery")
            }
            MacosJournalAcquireOutcome::ReconciliationRequired(lease) => {
                panic!("expected a ready account lease: {}", lease.cause())
            }
        }
    }

    fn expect_durable(outcome: MacosJournalAppendOutcome<'_>) -> MacosJournalDurableLease<'_> {
        match outcome {
            MacosJournalAppendOutcome::Durable(lease) => *lease,
            MacosJournalAppendOutcome::ReconciliationRequired(lease) => {
                panic!("expected a durable generation: {}", lease.cause())
            }
        }
    }

    fn expect_reconciliation(
        outcome: MacosJournalAcquireOutcome<'_>,
    ) -> MacosJournalReconciliationLease<'_> {
        match outcome {
            MacosJournalAcquireOutcome::ReconciliationRequired(lease) => lease,
            MacosJournalAcquireOutcome::Ready(_) => {
                panic!("uncertain journal was incorrectly treated as ready")
            }
            MacosJournalAcquireOutcome::IndexedPreparationRequired(_) => {
                panic!("uncertain journal was incorrectly treated as indexed preparation")
            }
            MacosJournalAcquireOutcome::RecoveryRequired(_) => {
                panic!("corrupt journal was incorrectly treated as recoverable")
            }
        }
    }

    fn durable_held<'store>(
        store: &'store MacosHelperJournalStore,
        session: &MacosHelperSession,
        pool: &MacosIdentityPoolObservation,
        suffix: u8,
    ) -> MacosJournalDurableLease<'store> {
        let ready = expect_ready(
            store
                .acquire(session, pool, assigned(601))
                .expect("acquire account for held lifecycle"),
        );
        let mut durable = expect_durable(ready.persist_initial(
            session,
            pool,
            prepared_transition(session, pool, suffix),
        ));
        let transition = intend_cleanup_agent(durable.record()).expect("cleanup-agent intent");
        durable = expect_durable(durable.persist_successor(session, pool, transition));
        let transition =
            record_cleanup_agent(durable.record(), digest(10)).expect("cleanup-agent record");
        durable = expect_durable(durable.persist_successor(session, pool, transition));
        let transition = record_held_launcher(
            durable.record(),
            session,
            held_evidence(session, durable.record(), 23),
        )
        .expect("held-launch record");
        expect_durable(durable.persist_successor(session, pool, transition))
    }

    fn write_owner_private(path: &Path, bytes: &[u8]) {
        let mut options = StdOpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(path).expect("create owner-private test file");
        file.write_all(bytes)
            .expect("write owner-private test file");
        file.sync_all().expect("sync owner-private test file");
    }

    #[test]
    fn full_lifecycle_persists_exact_successors_and_releases_only_after_cleaned() {
        let (_directory, session, pool, _reference, store) = provisioned("full-lifecycle");
        let ready = expect_ready(
            store
                .acquire(&session, &pool, assigned(601))
                .expect("acquire account"),
        );
        let mut durable = expect_durable(ready.persist_initial(
            &session,
            &pool,
            prepared_transition(&session, &pool, 1),
        ));
        assert_eq!(durable.post_persist_action(), MacosPostPersistAction::None);

        let transition = intend_cleanup_agent(durable.record()).expect("cleanup-agent intent");
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        assert_eq!(
            durable.post_persist_action(),
            MacosPostPersistAction::InstallCleanupAgent
        );
        let transition =
            record_cleanup_agent(durable.record(), digest(10)).expect("cleanup agent recorded");
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        assert_eq!(
            durable.post_persist_action(),
            MacosPostPersistAction::SpawnHeldLauncher
        );
        let transition = record_held_launcher(
            durable.record(),
            &session,
            held_evidence(&session, durable.record(), 23),
        )
        .expect("held launcher recorded");
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        assert_eq!(durable.post_persist_action(), MacosPostPersistAction::None);
        let transition = intend_launcher_release_for_test(
            durable.record(),
            release_authorization(durable.record()),
        )
        .expect("release intent");
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        assert_eq!(durable.post_persist_action(), MacosPostPersistAction::None);
        let transition = record_launcher_released(
            durable.record(),
            &session,
            release_evidence(&session, durable.record(), 24),
        )
        .expect("launcher release recorded");
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        let transition = begin_cleaning(durable.record(), MacosTerminationReason::Exited)
            .expect("cleaning intent");
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        assert_eq!(
            durable.post_persist_action(),
            MacosPostPersistAction::SealTerminateAndObserve
        );
        let transition = record_empty_domain(
            durable.record(),
            [observation(3, 30, 601, true), observation(4, 31, 601, true)],
        )
        .expect("empty domain proof");
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        assert_eq!(
            durable.post_persist_action(),
            MacosPostPersistAction::ReleaseIdentityReservation
        );
        let transition =
            record_identity_released(durable.record()).expect("reservation release recorded");
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        assert_eq!(durable.record().state, MacosHelperJournalState::Cleaned);
        drop(durable);

        let ready_again = expect_ready(
            store
                .acquire(&session, &pool, assigned(601))
                .expect("reacquire cleaned account"),
        );
        let second = expect_durable(ready_again.persist_initial(
            &session,
            &pool,
            prepared_transition(&session, &pool, 2),
        ));
        assert_eq!(second.record().runner_session_id(), "runner-2");
    }

    #[test]
    fn live_release_is_synchronous_and_restart_exposes_reconciliation_only() {
        let (_directory, session, pool, _reference, store) = provisioned("live-release");
        let durable = durable_held(&store, &session, &pool, 11);
        let guard = ();
        let authorization = release_authorization(durable.record()).retain_test_live(&guard);
        let transition = intend_launcher_release(durable.record(), authorization)
            .expect("construct live release transition");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let outcome = std::thread::scope(|scope| {
            let release_session = &session;
            let release_pool = &pool;
            let release = scope.spawn(move || {
                durable.persist_release_intent_and_execute(
                    release_session,
                    release_pool,
                    transition,
                    30,
                    |permit| {
                        assert_eq!(permit.release_started_at_unix_ms(), 30);
                        assert!(permit.authorization().authorized_at_unix_ms <= 30);
                        entered_tx.send(()).expect("signal native release entry");
                        finish_rx.recv().expect("finish native release callback");
                        "released-once"
                    },
                )
            });
            entered_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("native release callback entered");
            assert!(matches!(
                store.acquire(&session, &pool, assigned(601)),
                Err(MacosHelperJournalError::Lock(_))
            ));
            finish_tx.send(()).expect("finish native release");
            release.join().expect("join native release callback")
        });
        let MacosJournalReleaseOutcome::Executed { durable, released } = outcome else {
            panic!("fresh live release must execute after durable intent")
        };
        assert_eq!(released, "released-once");
        assert_eq!(
            durable.record().state,
            MacosHelperJournalState::ReleaseIntended
        );
        assert_eq!(durable.post_persist_action(), MacosPostPersistAction::None);
        drop(durable);

        let MacosJournalAcquireOutcome::RecoveryRequired(recovery) = store
            .acquire(&session, &pool, assigned(601))
            .expect("reopen release-intended account")
        else {
            panic!("release-intended restart must require reconciliation")
        };
        assert_eq!(recovery.action(), MacosRecoveryAction::ReconcileHeldRelease);
    }

    #[test]
    fn persistence_failure_or_deadline_crossing_executes_zero_native_releases() {
        let (directory, session, pool, _reference, store) = provisioned("release-persist-fail");
        let durable = durable_held(&store, &session, &pool, 12);
        let guard = ();
        let authorization = release_authorization(durable.record()).retain_test_live(&guard);
        let transition = intend_launcher_release(durable.record(), authorization)
            .expect("construct persistence-failure release transition");
        write_owner_private(
            &directory
                .root
                .join(account_directory_name(601))
                .join(".unexpected-release-residue.tmp"),
            b"uncertain",
        );
        let calls = AtomicU64::new(0);
        let outcome =
            durable.persist_release_intent_and_execute(&session, &pool, transition, 30, |_| {
                calls.fetch_add(1, Ordering::SeqCst);
            });
        assert!(matches!(
            outcome,
            MacosJournalReleaseOutcome::ReconciliationRequired(_)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(store);

        let (_directory, session, pool, _reference, store) = provisioned("release-deadline");
        let durable = durable_held(&store, &session, &pool, 13);
        let guard = ();
        let authorization = release_authorization(durable.record()).retain_test_live(&guard);
        let transition = intend_launcher_release(durable.record(), authorization)
            .expect("construct deadline release transition");
        let calls = AtomicU64::new(0);
        let outcome =
            durable.persist_release_intent_and_execute(&session, &pool, transition, 1_000, |_| {
                calls.fetch_add(1, Ordering::SeqCst);
            });
        let MacosJournalReleaseOutcome::ReconciliationRequired(reconciliation) = outcome else {
            panic!("deadline crossing must retain reconciliation authority")
        };
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            reconciliation
                .cause()
                .to_string()
                .contains("deadline crossed")
        );
        let MacosJournalAcquireOutcome::RecoveryRequired(recovery) =
            reconciliation.retry_validation(&session, &pool)
        else {
            panic!("durable release intent must restart as reconciliation")
        };
        assert_eq!(recovery.action(), MacosRecoveryAction::ReconcileHeldRelease);
    }

    #[test]
    fn dropping_live_release_transition_preserves_held_reconciliation_only() {
        let (_directory, session, pool, _reference, store) = provisioned("release-drop");
        let durable = durable_held(&store, &session, &pool, 14);
        let guard = ();
        let authorization = release_authorization(durable.record()).retain_test_live(&guard);
        let transition = intend_launcher_release(durable.record(), authorization)
            .expect("construct droppable live release transition");
        drop(transition);
        assert_eq!(
            durable.record().state,
            MacosHelperJournalState::HeldPrepared
        );
        drop(durable);

        let MacosJournalAcquireOutcome::RecoveryRequired(recovery) = store
            .acquire(&session, &pool, assigned(601))
            .expect("reopen held account after transition drop")
        else {
            panic!("dropped live transition must leave held state for reconciliation")
        };
        assert_eq!(
            recovery.action(),
            MacosRecoveryAction::ReconcileOuterPreparationOutcome
        );
    }

    #[test]
    fn dropping_the_account_lease_releases_it_past_a_duplicated_description() {
        let (_directory, session, pool, _reference, store) = provisioned("lease-release");
        let ready = expect_ready(
            store
                .acquire(&session, &pool, assigned(601))
                .expect("acquire account"),
        );

        // A second reference to the *same* open file description, which is what
        // owns the `flock` exclusion. Every `fork` behind a process spawn hands
        // exactly this to the child for every open descriptor until it execs.
        let duplicated = ready
            .lease
            .lock
            .file
            .try_clone()
            .expect("duplicate the account-lease description");

        drop(ready);

        // The lease must end with the lease value, not with the last surviving
        // duplicate of its descriptor.
        let reacquired = expect_ready(store.acquire(&session, &pool, assigned(601)).expect(
            "a dropped lease releases the account even while a duplicate description is open",
        ));

        drop(reacquired);
        drop(duplicated);
    }

    #[test]
    fn restart_returns_recovery_action_and_keeps_the_account_exclusive() {
        let (directory, session, pool, reference, store) = provisioned("restart-recovery");
        let reference_bytes = reference
            .canonical_bytes()
            .expect("encode durable journal reference");
        let mut obsolete_reference = reference.clone();
        obsolete_reference.format_version = 2;
        let obsolete_bytes = obsolete_reference
            .canonical_bytes()
            .expect("encode obsolete reference fixture");
        assert!(
            MacosHelperJournalReference::decode_canonical(&obsolete_bytes).is_err(),
            "v2 journal references must not be interpreted as v3 state"
        );
        let mut alternate_reference = reference_bytes.clone();
        alternate_reference.push(b'\n');
        assert!(
            MacosHelperJournalReference::decode_canonical(&alternate_reference).is_err(),
            "alternate reference bytes must fail closed"
        );
        let ready = expect_ready(
            store
                .acquire(&session, &pool, assigned(601))
                .expect("acquire account"),
        );
        let durable = expect_durable(ready.persist_initial(
            &session,
            &pool,
            prepared_transition(&session, &pool, 1),
        ));
        drop(durable);
        drop(store);

        let reference = MacosHelperJournalReference::decode_canonical(&reference_bytes)
            .expect("decode durable journal reference after restart");
        let reopened = MacosHelperJournalStore::open(&directory.root, &reference, &session, &pool)
            .expect("reopen journal");
        let MacosJournalAcquireOutcome::RecoveryRequired(recovery) = reopened
            .acquire(&session, &pool, assigned(601))
            .expect("acquire recovery account")
        else {
            panic!("unfinished prefix must require recovery")
        };
        assert_eq!(
            recovery.action(),
            MacosRecoveryAction::PersistCleanupAgentIntent
        );
        assert_eq!(recovery.record().state, MacosHelperJournalState::Prepared);
        assert!(matches!(
            reopened.acquire(&session, &pool, assigned(601)),
            Err(MacosHelperJournalError::Lock(_))
        ));
        let transition = intend_cleanup_agent(recovery.record()).expect("reconciled successor");
        let durable = expect_durable(recovery.persist_successor(&session, &pool, transition));
        assert_eq!(
            durable.post_persist_action(),
            MacosPostPersistAction::InstallCleanupAgent
        );
    }

    #[test]
    fn per_account_leases_are_fixed_distinct_and_pool_bound() {
        let (_directory, session, pool, _reference, store) = provisioned("account-leases");
        let first = expect_ready(
            store
                .acquire(&session, &pool, assigned(601))
                .expect("acquire first account"),
        );
        assert!(matches!(
            store.acquire(&session, &pool, assigned(601)),
            Err(MacosHelperJournalError::Lock(_))
        ));
        let second = expect_ready(
            store
                .acquire(&session, &pool, assigned(602))
                .expect("acquire distinct account"),
        );
        let mut foreign = assigned(603);
        foreign.account_record_digest = digest(99);
        assert!(matches!(
            store.acquire(&session, &pool, foreign),
            Err(MacosHelperJournalError::Pool(_))
        ));
        drop(first);
        drop(second);
    }

    #[test]
    fn pool_global_index_assigns_one_request_to_exactly_one_uid_concurrently() {
        let (_directory, session, pool, _reference, store) = provisioned("global-concurrent");
        let start = Arc::new(Barrier::new(2));
        let (first, second) = std::thread::scope(|scope| {
            let first_start = Arc::clone(&start);
            let first_store = &store;
            let first_session = &session;
            let first_pool = &pool;
            let first = scope.spawn(move || {
                let ready = expect_ready(
                    first_store
                        .acquire(first_session, first_pool, assigned(601))
                        .expect("lease first candidate UID"),
                );
                let transition = prepared_transition_for_uid(first_session, first_pool, 41, 601);
                first_start.wait();
                matches!(
                    ready.persist_initial(first_session, first_pool, transition),
                    MacosJournalAppendOutcome::Durable(_)
                )
            });
            let second_start = Arc::clone(&start);
            let second_store = &store;
            let second_session = &session;
            let second_pool = &pool;
            let second = scope.spawn(move || {
                let ready = expect_ready(
                    second_store
                        .acquire(second_session, second_pool, assigned(602))
                        .expect("lease second candidate UID"),
                );
                let transition = prepared_transition_for_uid(second_session, second_pool, 41, 602);
                second_start.wait();
                matches!(
                    ready.persist_initial(second_session, second_pool, transition),
                    MacosJournalAppendOutcome::Durable(_)
                )
            });
            (
                first.join().expect("join first admission"),
                second.join().expect("join second admission"),
            )
        });
        assert_ne!(first, second, "exactly one UID must own the request");

        let entries = store
            .read_admission_index(&session, &pool)
            .expect("read global admission index");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].assigned_identity.uid, 601 | 602));

        let ready = expect_ready(
            store
                .acquire(&session, &pool, assigned(603))
                .expect("lease third UID for a distinct request"),
        );
        let distinct = ready.persist_initial(
            &session,
            &pool,
            prepared_transition_for_uid(&session, &pool, 42, 603),
        );
        assert!(matches!(distinct, MacosJournalAppendOutcome::Durable(_)));
        assert_eq!(
            store
                .read_admission_index(&session, &pool)
                .expect("read index with distinct request")
                .len(),
            2
        );
    }

    #[test]
    fn durable_fence_without_generation_recovers_only_on_its_indexed_uid() {
        let (directory, session, pool, reference, store) = provisioned("fence-only-restart");
        let transition = prepared_transition_for_uid(&session, &pool, 51, 601);
        store
            .append_admission_fence(&session, &pool, transition.record())
            .expect("sync fence before simulated account-generation crash");
        drop(store);

        let renewed = renewed_session(&session, 91, 12);
        let reopened = MacosHelperJournalStore::open(&directory.root, &reference, &renewed, &pool)
            .expect("reopen fence-only journal under a fresh helper session");
        let crossed = expect_ready(
            reopened
                .acquire(&renewed, &pool, assigned(602))
                .expect("lease crossed UID"),
        )
        .persist_initial(
            &renewed,
            &pool,
            prepared_transition_for_uid(&renewed, &pool, 51, 602),
        );
        assert!(matches!(
            crossed,
            MacosJournalAppendOutcome::ReconciliationRequired(_)
        ));

        let MacosJournalAcquireOutcome::IndexedPreparationRequired(indexed) = reopened
            .acquire(&renewed, &pool, assigned(601))
            .expect("lease exactly indexed UID")
        else {
            panic!("fence-only UID must remain explicitly quarantined")
        };
        assert_eq!(indexed.record(), transition.record());
        let exact = indexed.persist_prepared_after_fresh_empty_reconciliation(
            &renewed,
            &pool,
            [
                observation(1, 20, 601, false),
                observation(2, 21, 601, false),
            ],
            22,
        );
        assert!(matches!(exact, MacosJournalAppendOutcome::Durable(_)));
        assert_eq!(
            reopened
                .read_admission_index(&renewed, &pool)
                .expect("read retained single fence")
                .len(),
            1,
            "exact pre-effect recovery must not append a second mapping"
        );
    }

    #[test]
    fn indexed_uid_needs_fresh_empty_reconciliation_and_expiry_stays_quarantined() {
        let (directory, session, pool, reference, store) = provisioned("indexed-expiry");
        let transition = prepared_transition_for_uid(&session, &pool, 61, 601);
        store
            .append_admission_fence(&session, &pool, transition.record())
            .expect("sync fence before restart");
        drop(store);

        let renewed = renewed_session(&session, 92, 30);
        let reopened = MacosHelperJournalStore::open(&directory.root, &reference, &renewed, &pool)
            .expect("reopen indexed UID under renewed session");
        let MacosJournalAcquireOutcome::IndexedPreparationRequired(indexed) = reopened
            .acquire(&renewed, &pool, assigned(601))
            .expect("acquire indexed UID")
        else {
            panic!("indexed UID must not be returned as generically ready")
        };
        let stale = indexed.persist_prepared_after_fresh_empty_reconciliation(
            &renewed,
            &pool,
            [
                observation(1, 20, 601, false),
                observation(2, 21, 601, false),
            ],
            31,
        );
        assert!(matches!(
            stale,
            MacosJournalAppendOutcome::ReconciliationRequired(_)
        ));
        drop(stale);

        let MacosJournalAcquireOutcome::IndexedPreparationRequired(indexed) = reopened
            .acquire(&renewed, &pool, assigned(601))
            .expect("reacquire still-indexed UID")
        else {
            panic!("failed fresh reconciliation must retain indexed quarantine")
        };
        let expired = indexed.persist_prepared_after_fresh_empty_reconciliation(
            &renewed,
            &pool,
            [
                observation(1, 31, 601, false),
                observation(2, 32, 601, false),
            ],
            1_000,
        );
        let MacosJournalAppendOutcome::ReconciliationRequired(reconciliation) = expired else {
            panic!("expired indexed request cannot publish Prepared")
        };
        assert!(reconciliation.cause().to_string().contains("expired"));
        assert!(matches!(
            reconciliation.retry_validation(&renewed, &pool),
            MacosJournalAcquireOutcome::IndexedPreparationRequired(_)
        ));
    }

    #[test]
    fn injected_persistence_boundaries_never_grant_blind_replay() {
        let faults = [
            PersistFaultPoint::TempCreated,
            PersistFaultPoint::BytesWritten,
            PersistFaultPoint::FileSynced,
            PersistFaultPoint::Renamed,
            PersistFaultPoint::DirectorySynced,
        ];
        for (index, fault) in faults.into_iter().enumerate() {
            let (directory, session, pool, reference, store) =
                provisioned(&format!("fault-{index}"));
            let ready = expect_ready(
                store
                    .acquire(&session, &pool, assigned(601))
                    .expect("acquire account"),
            );
            let expected_head = ready.head;
            let transition = prepared_transition(&session, &pool, 1);
            store
                .append_admission_fence(&session, &pool, transition.record())
                .expect("persist pool-global replay fence before account generation");
            let outcome = persist_transition(
                ready.lease,
                expected_head.as_ref(),
                transition,
                TransitionPosition::Initial,
                &session,
                &pool,
                Some(fault),
            );
            let reconciliation = match outcome {
                MacosJournalAppendOutcome::ReconciliationRequired(lease) => lease,
                MacosJournalAppendOutcome::Durable(_) => {
                    panic!("fault {fault:?} incorrectly reported durable")
                }
            };
            assert!(matches!(
                reconciliation.cause(),
                MacosHelperJournalError::InjectedFault(_)
            ));
            assert!(matches!(
                store.acquire(&session, &pool, assigned(601)),
                Err(MacosHelperJournalError::Lock(_))
            ));

            if matches!(
                fault,
                PersistFaultPoint::Renamed | PersistFaultPoint::DirectorySynced
            ) {
                let MacosJournalAcquireOutcome::RecoveryRequired(recovery) =
                    reconciliation.retry_validation(&session, &pool)
                else {
                    panic!("published fault {fault:?} must reconcile as persisted")
                };
                assert_eq!(
                    recovery.action(),
                    MacosRecoveryAction::PersistCleanupAgentIntent
                );
                drop(recovery);
            } else {
                let MacosJournalAcquireOutcome::ReconciliationRequired(still_uncertain) =
                    reconciliation.retry_validation(&session, &pool)
                else {
                    panic!("temporary residue for {fault:?} must remain fail-closed")
                };
                assert!(matches!(
                    store.acquire(&session, &pool, assigned(601)),
                    Err(MacosHelperJournalError::Lock(_))
                ));
                drop(still_uncertain);
            }
            drop(store);

            let reopened =
                MacosHelperJournalStore::open(&directory.root, &reference, &session, &pool)
                    .expect("reopen static layout");
            let outcome = reopened
                .acquire(&session, &pool, assigned(601))
                .expect("acquire after simulated restart");
            if matches!(
                fault,
                PersistFaultPoint::Renamed | PersistFaultPoint::DirectorySynced
            ) {
                assert!(matches!(
                    outcome,
                    MacosJournalAcquireOutcome::RecoveryRequired(_)
                ));
            } else {
                assert!(matches!(
                    outcome,
                    MacosJournalAcquireOutcome::ReconciliationRequired(_)
                ));
            }
        }
    }

    #[test]
    fn ambiguous_intent_publication_recovers_by_reconciliation_not_effect_replay() {
        let (_directory, session, pool, _reference, store) = provisioned("intent-recovery");
        let ready = expect_ready(
            store
                .acquire(&session, &pool, assigned(601))
                .expect("acquire account"),
        );
        let prepared = expect_durable(ready.persist_initial(
            &session,
            &pool,
            prepared_transition(&session, &pool, 1),
        ));
        let cleanup_transition =
            intend_cleanup_agent(prepared.record()).expect("cleanup-agent intent");
        let prepared_head = prepared.head;
        let cleanup_outcome = persist_transition(
            prepared.lease,
            Some(&prepared_head),
            cleanup_transition,
            TransitionPosition::Successor,
            &session,
            &pool,
            Some(PersistFaultPoint::DirectorySynced),
        );
        let MacosJournalAppendOutcome::ReconciliationRequired(cleanup_uncertain) = cleanup_outcome
        else {
            panic!("lost cleanup-intent response must be uncertain")
        };
        let MacosJournalAcquireOutcome::RecoveryRequired(cleanup_recovery) =
            cleanup_uncertain.retry_validation(&session, &pool)
        else {
            panic!("durable cleanup intent must require host reconciliation")
        };
        assert_eq!(
            cleanup_recovery.action(),
            MacosRecoveryAction::ReconcileCleanupAgent
        );

        let launch_transition = record_cleanup_agent(cleanup_recovery.record(), digest(10))
            .expect("record reconciled cleanup agent");
        let cleanup_head = cleanup_recovery.head;
        let launch_outcome = persist_transition(
            cleanup_recovery.lease,
            Some(&cleanup_head),
            launch_transition,
            TransitionPosition::Successor,
            &session,
            &pool,
            Some(PersistFaultPoint::DirectorySynced),
        );
        let MacosJournalAppendOutcome::ReconciliationRequired(launch_uncertain) = launch_outcome
        else {
            panic!("lost launch-intent response must be uncertain")
        };
        let MacosJournalAcquireOutcome::RecoveryRequired(launch_recovery) =
            launch_uncertain.retry_validation(&session, &pool)
        else {
            panic!("durable launch intent must require held-launch reconciliation")
        };
        assert_eq!(
            launch_recovery.action(),
            MacosRecoveryAction::ReconcileHeldLaunch
        );
        assert!(matches!(
            store.acquire(&session, &pool, assigned(601)),
            Err(MacosHelperJournalError::Lock(_))
        ));
    }

    #[test]
    fn release_intent_crash_restarts_as_reconciliation_and_retains_exact_request() {
        let (directory, session, pool, reference, store) = provisioned("release-intent-crash");
        let ready = expect_ready(
            store
                .acquire(&session, &pool, assigned(601))
                .expect("acquire account"),
        );
        let mut durable = expect_durable(ready.persist_initial(
            &session,
            &pool,
            prepared_transition(&session, &pool, 1),
        ));
        let transition = intend_cleanup_agent(durable.record()).unwrap();
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        let transition = record_cleanup_agent(durable.record(), digest(10)).unwrap();
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        let transition = record_held_launcher(
            durable.record(),
            &session,
            held_evidence(&session, durable.record(), 23),
        )
        .unwrap();
        durable = expect_durable(durable.persist_successor(&session, &pool, transition));
        let exact_request = durable.record().request.clone();
        assert_eq!(
            durable.record().state,
            MacosHelperJournalState::HeldPrepared
        );
        drop(durable);
        drop(store);

        let recovery_session = renewed_session(&session, 80, 24);
        let reopened =
            MacosHelperJournalStore::open(&directory.root, &reference, &recovery_session, &pool)
                .expect("reopen held journal under a fresh authenticated session");
        let MacosJournalAcquireOutcome::RecoveryRequired(recovery) = reopened
            .acquire(&recovery_session, &pool, assigned(601))
            .expect("acquire held recovery")
        else {
            panic!("held preparation must restart under recovery")
        };
        assert_eq!(
            recovery.action(),
            MacosRecoveryAction::ReconcileOuterPreparationOutcome
        );
        assert_eq!(recovery.record().request, exact_request);

        let transition = intend_launcher_release_for_test(
            recovery.record(),
            release_authorization(recovery.record()),
        )
        .unwrap();
        let expected_head = recovery.head;
        let outcome = persist_transition(
            recovery.lease,
            Some(&expected_head),
            transition,
            TransitionPosition::Successor,
            &recovery_session,
            &pool,
            Some(PersistFaultPoint::DirectorySynced),
        );
        let MacosJournalAppendOutcome::ReconciliationRequired(uncertain) = outcome else {
            panic!("lost release-intent response must be uncertain")
        };
        let MacosJournalAcquireOutcome::RecoveryRequired(reconcile_release) =
            uncertain.retry_validation(&recovery_session, &pool)
        else {
            panic!("durable release intent must never reauthorize release after ambiguity")
        };
        assert_eq!(
            reconcile_release.action(),
            MacosRecoveryAction::ReconcileHeldRelease
        );
        assert_eq!(reconcile_release.record().request, exact_request);
        drop(reconcile_release);
        drop(reopened);

        let second_recovery_session = renewed_session(&session, 81, 25);
        let restarted = MacosHelperJournalStore::open(
            &directory.root,
            &reference,
            &second_recovery_session,
            &pool,
        )
        .expect("reopen release-intent journal under another authenticated session");
        let MacosJournalAcquireOutcome::RecoveryRequired(recovery) = restarted
            .acquire(&second_recovery_session, &pool, assigned(601))
            .expect("acquire release reconciliation")
        else {
            panic!("release-intent restart must remain cleanup/reconciliation only")
        };
        assert_eq!(recovery.action(), MacosRecoveryAction::ReconcileHeldRelease);
        assert_eq!(recovery.record().request, exact_request);
    }

    #[derive(Clone, Copy, Debug)]
    enum Corruption {
        Temporary,
        Gap,
        Truncated,
        DigestMismatch,
        NonCanonical,
        Symlink,
        Hardlink,
    }

    #[test]
    fn temp_gap_truncation_corruption_links_and_noncanonical_bytes_fail_closed() {
        let corruptions = [
            Corruption::Temporary,
            Corruption::Gap,
            Corruption::Truncated,
            Corruption::DigestMismatch,
            Corruption::NonCanonical,
            Corruption::Symlink,
            Corruption::Hardlink,
        ];
        for (index, corruption) in corruptions.into_iter().enumerate() {
            let (directory, session, pool, _reference, store) =
                provisioned(&format!("corrupt-{index}"));
            let ready = expect_ready(
                store
                    .acquire(&session, &pool, assigned(601))
                    .expect("acquire account"),
            );
            let durable = expect_durable(ready.persist_initial(
                &session,
                &pool,
                prepared_transition(&session, &pool, 1),
            ));
            drop(durable);
            let account = directory.root.join(account_directory_name(601));
            let generation = account.join(generation_name(1));
            let bytes = fs::read(&generation).expect("read generation for corruption");
            match corruption {
                Corruption::Temporary => {
                    write_owner_private(&account.join(".generation-incomplete.tmp"), b"partial");
                }
                Corruption::Gap => {
                    fs::rename(&generation, account.join(generation_name(2)))
                        .expect("create generation gap");
                }
                Corruption::Truncated => {
                    fs::write(&generation, b"{").expect("truncate generation");
                }
                Corruption::DigestMismatch => {
                    let mut decoded: StoredGeneration =
                        serde_json::from_slice(&bytes).expect("decode generation");
                    decoded.record.request.effect_id = "forged-effect".into();
                    fs::write(
                        &generation,
                        serde_json::to_vec(&decoded).expect("encode forged generation"),
                    )
                    .expect("write digest mismatch");
                }
                Corruption::NonCanonical => {
                    let mut alternate = bytes;
                    alternate.push(b'\n');
                    fs::write(&generation, alternate).expect("write noncanonical generation");
                }
                Corruption::Symlink => {
                    let target = directory.top.join("symlink-target");
                    write_owner_private(&target, &bytes);
                    fs::remove_file(&generation).expect("remove generation for symlink");
                    symlink(&target, &generation).expect("replace generation with symlink");
                }
                Corruption::Hardlink => {
                    fs::hard_link(&generation, directory.top.join("generation-alias"))
                        .expect("create external hardlink");
                }
            }
            let reconciliation = expect_reconciliation(
                store
                    .acquire(&session, &pool, assigned(601))
                    .expect("acquire corrupt account"),
            );
            assert!(
                !reconciliation.cause().to_string().is_empty(),
                "corruption {corruption:?} must report a cause"
            );
        }
    }

    #[test]
    fn exact_prefix_validation_rejects_a_valid_but_skipped_lifecycle_record() {
        let (directory, session, pool, _reference, store) = provisioned("skipped-state");
        let ready = expect_ready(
            store
                .acquire(&session, &pool, assigned(601))
                .expect("acquire account"),
        );
        let durable = expect_durable(ready.persist_initial(
            &session,
            &pool,
            prepared_transition(&session, &pool, 1),
        ));
        let prepared_record = durable.record().clone();
        drop(durable);

        let cleanup = intend_cleanup_agent(&prepared_record)
            .expect("cleanup intent")
            .into_record();
        let skipped = record_cleanup_agent(&cleanup, digest(10))
            .expect("launch intent")
            .into_record();
        let first_bytes = fs::read(
            directory
                .root
                .join(account_directory_name(601))
                .join(generation_name(1)),
        )
        .expect("read first generation");
        let first: StoredGeneration =
            serde_json::from_slice(&first_bytes).expect("decode first generation");
        let mut second = StoredGeneration {
            format_version: JOURNAL_FORMAT_VERSION,
            generation: 2,
            previous_generation_digest: Some(first.generation_digest),
            pool_record_digest: pool.pool_record_digest.clone(),
            assigned_identity: assigned(601),
            record: skipped,
            generation_digest: digest(0),
        };
        second.generation_digest = second.computed_digest().expect("second digest");
        write_owner_private(
            &directory
                .root
                .join(account_directory_name(601))
                .join(generation_name(2)),
            &second
                .canonical_bytes()
                .expect("canonical second generation"),
        );
        let reconciliation = expect_reconciliation(
            store
                .acquire(&session, &pool, assigned(601))
                .expect("acquire skipped prefix"),
        );
        assert!(reconciliation.cause().to_string().contains("skipped"));
    }

    #[derive(Clone, Copy, Debug)]
    enum Replacement {
        Root,
        Account,
        Lock,
        Pool,
    }

    #[test]
    fn root_account_lock_replacement_and_pool_identity_drift_retain_reconciliation_lease() {
        let replacements = [
            Replacement::Root,
            Replacement::Account,
            Replacement::Lock,
            Replacement::Pool,
        ];
        for (index, replacement) in replacements.into_iter().enumerate() {
            let (directory, session, pool, _reference, store) =
                provisioned(&format!("replacement-{index}"));
            let ready = expect_ready(
                store
                    .acquire(&session, &pool, assigned(601))
                    .expect("acquire account"),
            );
            let expected_head = ready.head;
            let mut current_session = session.clone();
            let mut current_pool = pool.clone();
            match replacement {
                Replacement::Root => {
                    fs::rename(&directory.root, directory.top.join("moved-journal"))
                        .expect("move journal root");
                    fs::create_dir(&directory.root).expect("replace journal root");
                    fs::set_permissions(&directory.root, fs::Permissions::from_mode(0o700))
                        .expect("set replacement root mode");
                }
                Replacement::Account => {
                    let account = directory.root.join(account_directory_name(601));
                    fs::rename(&account, directory.top.join("moved-account"))
                        .expect("move account journal");
                    fs::create_dir(&account).expect("replace account journal");
                    fs::set_permissions(&account, fs::Permissions::from_mode(0o700))
                        .expect("set replacement account mode");
                }
                Replacement::Lock => {
                    let account = directory.root.join(account_directory_name(601));
                    fs::rename(account.join(LOCK_NAME), account.join("moved-lock"))
                        .expect("move lease file");
                    write_owner_private(&account.join(LOCK_NAME), b"");
                }
                Replacement::Pool => {
                    current_pool.records[0].record_digest = digest(99);
                    current_pool.pool_record_digest =
                        current_pool.computed_digest().expect("drifted pool digest");
                    current_session.pool_record_digest = current_pool.pool_record_digest.clone();
                }
            }
            let outcome = persist_transition(
                ready.lease,
                expected_head.as_ref(),
                prepared_transition(&session, &pool, 1),
                TransitionPosition::Initial,
                &current_session,
                &current_pool,
                None,
            );
            let reconciliation = match outcome {
                MacosJournalAppendOutcome::ReconciliationRequired(lease) => lease,
                MacosJournalAppendOutcome::Durable(_) => {
                    panic!("replacement {replacement:?} incorrectly allowed persistence")
                }
            };
            assert!(
                !reconciliation.cause().to_string().is_empty(),
                "replacement {replacement:?} must report its cause"
            );
        }
    }

    #[test]
    fn provision_and_open_reject_residue_symlink_and_hardlinked_manifest() {
        let residue = TestDirectory::new("provision-residue");
        let (session, pool) = session_and_pool();
        write_owner_private(&residue.root.join("unexpected"), b"residue");
        assert!(matches!(
            MacosHelperJournalStore::provision(&residue.root, &session, &pool),
            Err(MacosHelperJournalError::Layout(_))
        ));

        let (directory, session, pool, reference, store) = provisioned("manifest-hardlink");
        drop(store);
        fs::hard_link(
            directory.root.join(POOL_MANIFEST_NAME),
            directory.top.join("manifest-alias"),
        )
        .expect("hardlink pool manifest");
        assert!(
            MacosHelperJournalStore::open(&directory.root, &reference, &session, &pool).is_err()
        );

        let linked = TestDirectory::new("root-symlink");
        let real_root = linked.top.join("real-journal");
        fs::rename(&linked.root, &real_root).expect("move real root");
        symlink(&real_root, &linked.root).expect("create root symlink");
        assert!(MacosHelperJournalStore::provision(&linked.root, &session, &pool).is_err());
    }
