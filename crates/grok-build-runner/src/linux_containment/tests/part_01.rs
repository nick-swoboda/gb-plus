    use super::*;
    use std::collections::{BTreeMap, VecDeque};

    const DELEGATION_ID: CgroupObjectIdentity = CgroupObjectIdentity {
        device: 7,
        inode: 11,
    };
    const LEAF_ID: CgroupObjectIdentity = CgroupObjectIdentity {
        device: 7,
        inode: 12,
    };

    #[allow(
        clippy::struct_excessive_bools,
        reason = "the test host independently records orthogonal injected kernel and lock observations"
    )]
    #[derive(Debug)]
    struct MockHost {
        operation: usize,
        fail_at: Option<usize>,
        fail_unlock: bool,
        probe_failures_remaining: usize,
        probe_runs: usize,
        lock_acquires: usize,
        lock_releases: usize,
        lock_held: bool,
        calls: Vec<String>,
        writes: Vec<(LeafWriteFile, Vec<u8>)>,
        self_attach_values: Vec<Vec<u8>>,
        journals: Vec<DomainJournalRecord>,
        leaf_reads: BTreeMap<LeafFile, VecDeque<Vec<u8>>>,
        subtree_readback: Vec<u8>,
        delegation: DelegationObservation,
        leaf: NewLeafObservation,
        nonce: String,
        absent: bool,
        leaf_present: bool,
        staged_recovery: StagedLauncherRecoveryState,
        staged_observation: Option<StagedLauncherObservation>,
    }

    impl MockHost {
        fn valid() -> Self {
            let required_files = required_delegation_files()
                .iter()
                .map(|value| (*value).to_owned())
                .collect();
            let required_controllers: BTreeSet<_> =
                DomainController::REQUIRED.into_iter().collect();
            let mut leaf_reads = BTreeMap::new();
            leaf_reads.insert(LeafFile::PidsMax, VecDeque::from([b"4\n".to_vec()]));
            leaf_reads.insert(LeafFile::MemoryMax, VecDeque::from([b"1048576\n".to_vec()]));
            leaf_reads.insert(LeafFile::MemorySwapMax, VecDeque::from([b"0\n".to_vec()]));
            leaf_reads.insert(LeafFile::MemoryOomGroup, VecDeque::from([b"1\n".to_vec()]));
            leaf_reads.insert(
                LeafFile::CgroupEvents,
                VecDeque::from([b"populated 0\nfrozen 0\n".to_vec()]),
            );
            leaf_reads.insert(
                LeafFile::CgroupProcs,
                VecDeque::from([Vec::new(), Vec::new()]),
            );
            Self {
                operation: 0,
                fail_at: None,
                fail_unlock: false,
                probe_failures_remaining: 0,
                probe_runs: 0,
                lock_acquires: 0,
                lock_releases: 0,
                lock_held: false,
                calls: Vec::new(),
                writes: Vec::new(),
                self_attach_values: Vec::new(),
                journals: Vec::new(),
                leaf_reads,
                subtree_readback: b"memory pids\n".to_vec(),
                delegation: DelegationObservation {
                    filesystem_magic: CGROUP2_SUPER_MAGIC,
                    identity: DELEGATION_ID,
                    expected_identity: DELEGATION_ID,
                    owner_uid: 1000,
                    expected_owner_uid: 1000,
                    mode: 0o755,
                    named_entry_matches_descriptor: true,
                    descendant_of_authenticated_service: true,
                    world_writable_ancestor: false,
                    available_controllers: required_controllers.clone(),
                    enabled_controllers: required_controllers,
                    existing_processes: Vec::new(),
                    existing_children: Vec::new(),
                    required_files,
                    negative_probe: DelegationProbeEvidence {
                        created_no_replace: true,
                        configured_and_read_back: true,
                        kill_write_accepted: true,
                        populated_zero: true,
                        stable_empty_procs: true,
                        removed_exact_inode: true,
                    },
                },
                leaf: NewLeafObservation {
                    identity: LEAF_ID,
                    owner_uid: 1000,
                    mode: 0o755,
                    named_entry_matches_descriptor: true,
                    initial_events: b"populated 0\nfrozen 0\n".to_vec(),
                    initial_procs: Vec::new(),
                },
                nonce: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                absent: true,
                leaf_present: false,
                staged_recovery: StagedLauncherRecoveryState::HeldBeforeExec,
                staged_observation: None,
            }
        }

        fn install_record_leaf(&mut self, record: &DomainJournalRecord) {
            self.leaf_present = true;
            self.delegation.existing_children = vec![record.leaf_name.clone()];
            if let Some(identity) = record.leaf_identity {
                self.leaf.identity = identity;
            }
        }

        fn for_record(record: &DomainJournalRecord) -> Self {
            let mut host = Self::valid();
            if !matches!(
                record.state,
                DomainJournalState::CreateAborted | DomainJournalState::Removed
            ) {
                host.install_record_leaf(record);
            }
            host
        }

        fn step(&mut self, name: &'static str) -> Result<(), CgroupIoFailure> {
            self.operation += 1;
            self.calls.push(name.into());
            if self.fail_at == Some(self.operation) {
                Err(CgroupIoFailure {
                    operation: name,
                    certainty: EffectCertainty::Ambiguous,
                    detail: "injected".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    impl CgroupIo for MockHost {
        fn acquire_delegation_lock(&mut self) -> Result<DelegationLockToken, CgroupIoFailure> {
            self.step("lock")?;
            if self.lock_held {
                return Err(CgroupIoFailure {
                    operation: "lock",
                    certainty: EffectCertainty::NotApplied,
                    detail: "delegated root is already exclusively locked".into(),
                });
            }
            self.lock_held = true;
            self.lock_acquires += 1;
            Ok(DelegationLockToken::test(1))
        }

        fn release_delegation_lock(
            &mut self,
            _token: &DelegationLockToken,
        ) -> Result<(), CgroupIoFailure> {
            self.lock_releases += 1;
            self.step("unlock")?;
            if self.fail_unlock {
                return Err(CgroupIoFailure {
                    operation: "unlock",
                    certainty: EffectCertainty::Ambiguous,
                    detail: "injected unlock failure".into(),
                });
            }
            assert!(self.lock_held);
            self.lock_held = false;
            Ok(())
        }

        fn inspect_delegation(
            &mut self,
            _expected_identity: CgroupObjectIdentity,
            _expected_owner_uid: u32,
        ) -> Result<DelegationObservation, CgroupIoFailure> {
            self.step("inspect-delegation")?;
            Ok(self.delegation.clone())
        }

        fn run_delegation_probe(
            &mut self,
            _token: &DelegationLockToken,
        ) -> Result<DelegationProbeEvidence, CgroupIoFailure> {
            self.probe_runs += 1;
            if self.probe_failures_remaining > 0 {
                self.probe_failures_remaining -= 1;
                return Err(CgroupIoFailure {
                    operation: "durable-probe",
                    certainty: EffectCertainty::Ambiguous,
                    detail: "injected unresolved durable probe".into(),
                });
            }
            Ok(self.delegation.negative_probe.clone())
        }

        fn require_fresh_domain_episode(
            &mut self,
            _token: &DelegationLockToken,
            request: &PrepareDomainRequest,
        ) -> Result<(), CgroupIoFailure> {
            self.step("admit-domain-episode")?;
            let replayed = self.journals.iter().any(|record| {
                record.state == DomainJournalState::CreateIntended
                    && record.effect_id == request.effect_id
            });
            if replayed {
                Err(CgroupIoFailure {
                    operation: "validate-journal-episode-history",
                    certainty: EffectCertainty::PriorEffectCommitted,
                    detail: "command effect already exists in immutable mock history".into(),
                })
            } else {
                Ok(())
            }
        }

        fn enable_required_subtree_controllers(
            &mut self,
            _token: &DelegationLockToken,
            exact_value: &[u8],
        ) -> Result<(), CgroupIoFailure> {
            assert_eq!(exact_value, REQUIRED_SUBTREE_ENABLE);
            self.step("enable-subtree")
        }

        fn read_enabled_subtree_controllers(
            &mut self,
            _token: &DelegationLockToken,
            max_bytes: usize,
        ) -> Result<Vec<u8>, CgroupIoFailure> {
            assert!(self.subtree_readback.len() <= max_bytes);
            self.step("read-subtree")?;
            Ok(self.subtree_readback.clone())
        }

        fn unpredictable_leaf_nonce(&mut self) -> Result<String, CgroupIoFailure> {
            self.step("nonce")?;
            Ok(self.nonce.clone())
        }

        fn create_leaf_no_replace(
            &mut self,
            _token: &DelegationLockToken,
            leaf_name: &str,
        ) -> Result<NewLeafObservation, CgroupIoFailure> {
            self.step("create-leaf")?;
            assert!(!self.leaf_present);
            assert!(self.delegation.existing_children.is_empty());
            self.leaf_present = true;
            self.delegation.existing_children = vec![leaf_name.to_owned()];
            Ok(self.leaf.clone())
        }

        fn inspect_leaf(
            &mut self,
            _token: &DelegationLockToken,
            leaf_name: &str,
            max_events_bytes: usize,
            max_procs_bytes: usize,
        ) -> Result<Option<NewLeafObservation>, CgroupIoFailure> {
            self.step("inspect-leaf")?;
            assert!(self.leaf.initial_events.len() <= max_events_bytes);
            assert!(self.leaf.initial_procs.len() <= max_procs_bytes);
            if self.leaf_present {
                assert_eq!(self.delegation.existing_children, [leaf_name]);
            }
            Ok(self.leaf_present.then(|| self.leaf.clone()))
        }

        fn write_leaf_file(
            &mut self,
            _token: &DelegationLockToken,
            _leaf_name: &str,
            _identity: CgroupObjectIdentity,
            file: LeafWriteFile,
            exact_value: &[u8],
        ) -> Result<(), CgroupIoFailure> {
            self.step(file.name())?;
            self.writes.push((file, exact_value.to_vec()));
            Ok(())
        }

        fn self_attach_held_launcher(
            &mut self,
            _token: &DelegationLockToken,
            leaf_name: &str,
            identity: CgroupObjectIdentity,
            launcher: &StagedLauncherIdentity,
            exact_self_value: &[u8],
        ) -> Result<(), CgroupIoFailure> {
            self.step("launcher-self-attach")?;
            assert!(self.leaf_present);
            assert_eq!(self.delegation.existing_children, [leaf_name]);
            assert_eq!(self.leaf.identity, identity);
            assert!(launcher.held_before_exec);
            assert_eq!(exact_self_value, LAUNCHER_SELF_ATTACH_VALUE);
            self.self_attach_values.push(exact_self_value.to_vec());
            Ok(())
        }

        fn read_leaf_file(
            &mut self,
            _token: &DelegationLockToken,
            _leaf_name: &str,
            _identity: CgroupObjectIdentity,
            file: LeafFile,
            max_bytes: usize,
        ) -> Result<Vec<u8>, CgroupIoFailure> {
            self.step(file.name())?;
            let value = self
                .leaf_reads
                .get_mut(&file)
                .and_then(VecDeque::pop_front)
                .unwrap_or_default();
            assert!(value.len() <= max_bytes);
            Ok(value)
        }

        fn inspect_staged_launcher(
            &mut self,
            _token: &DelegationLockToken,
            _leaf_name: &str,
            _identity: CgroupObjectIdentity,
            launcher: &StagedLauncherIdentity,
            max_procs_bytes: usize,
        ) -> Result<StagedLauncherObservation, CgroupIoFailure> {
            self.step("inspect-staged-launcher")?;
            if let Some(observation) = &self.staged_observation {
                assert!(observation.cgroup_procs.len() <= max_procs_bytes);
                return Ok(observation.clone());
            }
            let cgroup_procs = format!("{}\n", launcher.pid).into_bytes();
            assert!(cgroup_procs.len() <= max_procs_bytes);
            Ok(StagedLauncherObservation {
                pid: launcher.pid,
                process_start_time_ticks: launcher.process_start_time_ticks,
                held_before_exec: self.staged_recovery
                    == StagedLauncherRecoveryState::HeldBeforeExec,
                cgroup_procs,
            })
        }

        fn inspect_staged_launcher_recovery_state(
            &mut self,
            _launcher: &StagedLauncherIdentity,
        ) -> Result<StagedLauncherRecoveryState, CgroupIoFailure> {
            self.step("inspect-staged-recovery")?;
            Ok(self.staged_recovery)
        }

        fn persist_journal(&mut self, record: &DomainJournalRecord) -> Result<(), CgroupIoFailure> {
            self.step("persist-journal")?;
            self.journals.push(record.clone());
            Ok(())
        }

        fn sync_journal(&mut self) -> Result<(), CgroupIoFailure> {
            self.step("sync-journal")
        }

        fn poll_barrier(&mut self) -> Result<(), CgroupIoFailure> {
            self.step("poll-barrier")
        }

        fn remove_leaf_exact(
            &mut self,
            _token: &DelegationLockToken,
            leaf_name: &str,
            identity: CgroupObjectIdentity,
        ) -> Result<(), CgroupIoFailure> {
            self.step("remove-leaf")?;
            assert!(self.leaf_present);
            assert_eq!(self.leaf.identity, identity);
            assert_eq!(self.delegation.existing_children, [leaf_name]);
            self.leaf_present = false;
            self.delegation.existing_children.clear();
            Ok(())
        }

        fn prove_leaf_absent(
            &mut self,
            _token: &DelegationLockToken,
            _leaf_name: &str,
        ) -> Result<bool, CgroupIoFailure> {
            self.step("prove-absent")?;
            Ok(self.absent && !self.leaf_present)
        }
    }

    impl HeldReleaseIo for MockHost {
        type ReleaseRequest = ();
        type PlannedRelease = HeldExecReleaseBinding;
        type PreparedRelease = HeldExecReleaseBinding;

        fn plan_held_release(
            &mut self,
            _token: &DelegationLockToken,
            _leaf_name: &str,
            _identity: CgroupObjectIdentity,
            _launcher: &StagedLauncherIdentity,
            (): Self::ReleaseRequest,
        ) -> Result<(Self::PlannedRelease, HeldExecReleaseBinding), CgroupIoFailure> {
            self.step("plan-held-release")?;
            let binding = HeldExecReleaseBinding::inert_test_fixture();
            Ok((binding.clone(), binding))
        }

        fn prepare_held_release(
            &mut self,
            _token: &DelegationLockToken,
            _leaf_name: &str,
            _identity: CgroupObjectIdentity,
            _launcher: &StagedLauncherIdentity,
            plan: Self::PlannedRelease,
        ) -> Result<Self::PreparedRelease, CgroupIoFailure> {
            self.step("prepare-held-release")?;
            plan.validate().map_err(|detail| CgroupIoFailure {
                operation: "prepare-held-release",
                certainty: EffectCertainty::NotApplied,
                detail,
            })?;
            Ok(plan)
        }

        fn commit_held_release(
            &mut self,
            _token: &DelegationLockToken,
            _leaf_name: &str,
            _identity: CgroupObjectIdentity,
            launcher: &StagedLauncherIdentity,
            prepared: Self::PreparedRelease,
        ) -> Result<HeldExecObservation, CgroupIoFailure> {
            self.step("commit-held-release")?;
            Ok(HeldExecObservation {
                pid: launcher.pid,
                process_start_time_ticks: launcher.process_start_time_ticks,
                release_spec_hash: prepared.release_spec_hash().to_owned(),
                executable_identity: prepared.executable_identity(),
                same_pid_exec_observed: true,
                cgroup_membership_revalidated: true,
                target_continued: true,
            })
        }
    }

    fn request() -> PrepareDomainRequest {
        let grant_hash = Digest::sha256(b"test-grant");
        let policy_hash = Digest::sha256(b"test-policy");
        let expected_platform_binding_digest = Digest::sha256(b"test-platform-binding");
        PrepareDomainRequest {
            native_launch: LinuxNativeLaunchIdentity {
                contract_version: CONTRACT_VERSION,
                attempt_id: "attempt-1".into(),
                native_journal_id: "native-journal-1".into(),
                expected_platform_binding_digest,
                sprint_id: "sprint-1".into(),
                launch_id: "launch-1".into(),
                session_id: "session-1".into(),
                cleanup_effect_id: "cleanup-effect-1".into(),
                input_snapshot: Digest::sha256(b"test-input-snapshot"),
                grant_hash: grant_hash.clone(),
                policy_hash: policy_hash.clone(),
                claimed_at_unix_ms: 10,
            },
            runner_session_id: "session-1".into(),
            effect_id: "effect-1".into(),
            grant_hash: grant_hash.to_string(),
            policy_hash: policy_hash.to_string(),
            command_hash: "command-hash".into(),
            request_digest: "d".repeat(64),
            expected_delegation_identity: DELEGATION_ID,
            expected_owner_uid: 1000,
            limits: RequestedDomainLimits::derive(4, Some(1_048_576)).unwrap(),
        }
    }

    fn staged_launcher() -> StagedLauncherIdentity {
        StagedLauncherIdentity {
            pid: 4242,
            process_start_time_ticks: 9_999,
            launch_request_hash: Digest::sha256(b"test-platform-binding").to_string(),
            held_before_exec: true,
        }
    }

    fn release_authorization(
        domain: &PreparedDomain,
    ) -> LinuxHeldChildReleaseAuthorization<'static, 'static> {
        LinuxHeldChildReleaseAuthorization::test_for_record(&domain.record)
    }

    fn recovery_binding() -> DomainRecoveryBinding {
        let request = request();
        DomainRecoveryBinding {
            native_launch: request.native_launch,
            runner_session_id: "session-1".into(),
            effect_id: "effect-1".into(),
            request_digest: "d".repeat(64),
        }
    }

    fn prepare_success(host: &mut MockHost) -> PreparedDomain {
        match prepare_domain(host, request()).unwrap() {
            PrepareDomainOutcome::Prepared(domain) => *domain,
            PrepareDomainOutcome::ReconciliationRequired(lease) => {
                panic!("unexpected reconciliation lease: {:?}", lease.cause())
            }
            PrepareDomainOutcome::ProbeReconciliationRequired(lease) => {
                panic!("unexpected probe reconciliation lease: {:?}", lease.cause())
            }
        }
    }

    fn recover_success(host: &mut MockHost, record: DomainJournalRecord) -> DomainRecoveryOutcome {
        match reconcile_persisted_domain(host, record, &recovery_binding(), 1).unwrap() {
            DomainRecoveryAttempt::Complete(outcome) => *outcome,
            DomainRecoveryAttempt::ReconciliationRequired(lease) => {
                panic!("unexpected recovery lease: {:?}", lease.cause())
            }
            DomainRecoveryAttempt::ProbeReconciliationRequired(lease) => {
                panic!("unexpected probe recovery lease: {:?}", lease.cause())
            }
        }
    }

    #[test]
    fn finite_memory_derives_zero_swap_and_no_cpu_control_exists() {
        let limits = RequestedDomainLimits::derive(3, Some(4096)).unwrap();
        assert_eq!(limits.memory_max, LimitValue::Value(4096));
        assert_eq!(limits.memory_swap_max, LimitValue::Value(0));
        assert!(LeafFile::ALL.iter().all(|file| file.name() != "cpu.max"));
    }

    #[test]
    fn parsers_reject_noncanonical_or_unmodeled_kernel_state() {
        assert_eq!(parse_limit(b"42\n", true).unwrap(), LimitValue::Value(42));
        assert!(parse_limit(b"042\n", true).is_err());
        assert!(parse_limit(b"max\n", false).is_err());
        assert!(parse_cgroup_procs(b"1\n1\n").is_err());
        assert!(parse_cgroup_events(b"populated 0\nunknown 0\n").is_err());
        assert!(parse_cgroup_events(b"populated 0\npopulated 0\n").is_err());
    }

    #[test]
    fn no_internal_process_and_unexpected_child_fail_closed() {
        let mut host = MockHost::valid();
        host.delegation.existing_processes.push(99);
        let error = prepare_domain(&mut host, request()).unwrap_err();
        assert!(matches!(
            error,
            CgroupError::NoInternalProcessViolation { .. }
        ));

        let mut host = MockHost::valid();
        host.delegation.existing_children.push("foreign".into());
        let error = prepare_domain(&mut host, request()).unwrap_err();
        assert!(matches!(error, CgroupError::UnexpectedChildren { .. }));
    }

    #[test]
    fn preparation_writes_and_reads_back_exact_limits() {
        let mut host = MockHost::valid();
        let domain = prepare_success(&mut host);
        assert_eq!(domain.state(), DomainJournalState::Prepared);
        assert_eq!(domain.leaf_identity().unwrap(), LEAF_ID);
        assert_eq!(domain.read_back_limits().unwrap().pids_max, 4);
        assert_eq!(
            host.writes,
            vec![
                (LeafWriteFile::PidsMax, b"4\n".to_vec()),
                (LeafWriteFile::MemoryMax, b"1048576\n".to_vec()),
                (LeafWriteFile::MemorySwapMax, b"0\n".to_vec()),
                (LeafWriteFile::MemoryOomGroup, b"1\n".to_vec()),
            ]
        );
    }

    #[test]
    fn completed_command_effect_is_one_shot_before_probe_nonce_create_or_persist() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        cleanup_domain(&mut host, &mut domain, 1).unwrap();
        assert_eq!(domain.state(), DomainJournalState::Removed);

        let journal_count = host.journals.len();
        let probe_runs = host.probe_runs;
        let mut changed_request = request();
        changed_request.request_digest = "e".repeat(64);
        let mut changed_command = request();
        changed_command.command_hash = "changed-command-hash".into();
        let mut changed_native_input = request();
        changed_native_input.native_launch.input_snapshot =
            Digest::sha256(b"crossed-command-effect-input");
        let mut changed_runner_session = request();
        changed_runner_session.runner_session_id = "session-2".into();
        changed_runner_session.native_launch.session_id = "session-2".into();
        for replay in [
            request(),
            changed_request,
            changed_command,
            changed_native_input,
            changed_runner_session,
        ] {
            host.calls.clear();
            host.operation = 0;
            let error = prepare_domain(&mut host, replay).unwrap_err();
            assert!(matches!(
                error,
                CgroupError::PreviouslyCommitted {
                    operation: "validate-journal-episode-history",
                    ..
                }
            ));
            assert_eq!(host.journals.len(), journal_count);
            assert_eq!(host.probe_runs, probe_runs);
            assert_eq!(host.calls, ["lock", "admit-domain-episode", "unlock"]);
            assert!(!host.leaf_present);
        }

        host.leaf_reads
            .insert(LeafFile::PidsMax, VecDeque::from([b"4\n".to_vec()]));
        host.leaf_reads
            .insert(LeafFile::MemoryMax, VecDeque::from([b"1048576\n".to_vec()]));
        host.leaf_reads
            .insert(LeafFile::MemorySwapMax, VecDeque::from([b"0\n".to_vec()]));
        host.leaf_reads
            .insert(LeafFile::MemoryOomGroup, VecDeque::from([b"1\n".to_vec()]));
        let mut distinct = request();
        distinct.effect_id = "effect-2".into();
        let outcome = prepare_domain(&mut host, distinct).unwrap();
        let PrepareDomainOutcome::Prepared(distinct_domain) = outcome else {
            panic!(
                "a distinct command effect may repeat the same request and command under the same outer launch"
            )
        };
        assert_eq!(distinct_domain.state(), DomainJournalState::Prepared);
    }

    #[test]
    fn synchronized_create_intent_precedes_no_replace_creation() {
        let mut host = MockHost::valid();
        prepare_success(&mut host);
        assert_eq!(
            host.journals
                .iter()
                .map(|record| record.state)
                .collect::<Vec<_>>(),
            vec![
                DomainJournalState::CreateIntended,
                DomainJournalState::Configuring,
                DomainJournalState::Prepared,
            ]
        );
        let create = host
            .calls
            .iter()
            .position(|call| call == "create-leaf")
            .unwrap();
        let first_persist = host
            .calls
            .iter()
            .position(|call| call == "persist-journal")
            .unwrap();
        let first_sync = host
            .calls
            .iter()
            .position(|call| call == "sync-journal")
            .unwrap();
        assert!(first_persist < first_sync && first_sync < create);
        assert!(host.journals[0].leaf_identity.is_none());
    }

    #[test]
    fn staged_launcher_is_attached_and_read_back_before_attached_state() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        host.operation = 0;
        host.calls.clear();
        host.journals.clear();
        attach_staged_launcher(&mut host, &mut domain, staged_launcher()).unwrap();
        assert_eq!(domain.state(), DomainJournalState::Attached);
        assert_eq!(
            host.journals[host.journals.len() - 2].state,
            DomainJournalState::AttachIntended
        );
        assert_eq!(
            host.journals.last().unwrap().state,
            DomainJournalState::Attached
        );
        let membership_write = host
            .calls
            .iter()
            .position(|call| call == "launcher-self-attach")
            .unwrap();
        let membership_readback = host
            .calls
            .iter()
            .position(|call| call == "inspect-staged-launcher")
            .unwrap();
        assert!(membership_write < membership_readback);
        assert!(
            host.self_attach_values
                .contains(&LAUNCHER_SELF_ATTACH_VALUE.to_vec())
        );
        assert_eq!(
            host.calls,
            vec![
                "persist-journal",
                "sync-journal",
                "launcher-self-attach",
                "inspect-staged-launcher",
                "persist-journal",
                "sync-journal",
            ]
        );
    }

    #[test]
    fn held_preparation_evidence_binds_the_exact_attached_journal_and_launcher() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        attach_staged_launcher(&mut host, &mut domain, staged_launcher()).unwrap();
        let canonical =
            LinuxHeldPreparationEvidence::canonical_native_evidence_bytes(&domain.record).unwrap();
        assert!(canonical.starts_with(LINUX_HELD_PREPARATION_EVIDENCE_DOMAIN));
        assert!(canonical.len() <= MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES);

        let mut substituted_launcher = domain.record.clone();
        substituted_launcher.staged_launcher.as_mut().unwrap().pid += 1;
        let mut substituted_snapshot = domain.record.clone();
        substituted_snapshot.native_launch.input_snapshot =
            Digest::sha256(b"substituted-held-input-snapshot");
        for substituted in [substituted_launcher, substituted_snapshot] {
            let substituted_bytes =
                LinuxHeldPreparationEvidence::canonical_native_evidence_bytes(&substituted)
                    .unwrap();
            assert_ne!(substituted_bytes, canonical);
        }

        let authorization = release_authorization(&domain);
        domain.record.staged_launcher.as_mut().unwrap().pid += 1;
        host.operation = 0;
        host.calls.clear();
        host.journals.clear();
        assert!(matches!(
            release_attached_inert_target(&mut host, &mut domain, authorization, ()),
            Err(CgroupError::InvalidRequest {
                field: "release_authorization.held_journal",
                ..
            })
        ));
        assert!(!domain.release_attempted);
        assert!(host.calls.is_empty());
        assert!(host.journals.is_empty());
    }

    #[test]
    fn held_release_is_journaled_before_and_after_the_one_shot_commit() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        attach_staged_launcher(&mut host, &mut domain, staged_launcher()).unwrap();
        let attached_record = domain.record.clone();
        host.operation = 0;
        host.calls.clear();
        host.journals.clear();

        let authorization = release_authorization(&domain);
        let observation =
            release_attached_inert_target(&mut host, &mut domain, authorization, ()).unwrap();
        assert_eq!(domain.state(), DomainJournalState::Released);
        assert_eq!(
            host.journals
                .iter()
                .map(|record| record.state)
                .collect::<Vec<_>>(),
            [
                DomainJournalState::Held,
                DomainJournalState::ReleaseIntended,
                DomainJournalState::Released,
            ]
        );
        let held = &host.journals[0];
        let persisted_authorization = held.release_authorization.as_ref().unwrap();
        assert_eq!(persisted_authorization.native_launch, held.native_launch);
        assert_eq!(
            persisted_authorization.native_evidence_digest,
            Digest::sha256(b"test-outer-preparation-evidence")
        );
        let expected_held_evidence =
            LinuxHeldPreparationEvidence::canonical_native_evidence_bytes(&attached_record)
                .unwrap();
        assert_eq!(
            persisted_authorization.held_preparation_evidence_digest,
            Digest::sha256(&expected_held_evidence)
        );
        assert!(held.release_binding.is_some());
        assert!(!held.release_intent_recorded);
        assert!(held.release_observation.is_none());
        let intended = &host.journals[1];
        assert_eq!(intended.release_authorization, held.release_authorization);
        assert!(intended.release_intent_recorded);
        assert!(intended.release_observation.is_none());
        let released = &host.journals[2];
        assert_eq!(released.release_authorization, held.release_authorization);
        assert_eq!(released.release_observation.as_ref(), Some(&observation));
        assert_eq!(
            host.calls,
            [
                "plan-held-release",
                "persist-journal",
                "sync-journal",
                "prepare-held-release",
                "persist-journal",
                "sync-journal",
                "commit-held-release",
                "persist-journal",
                "sync-journal",
            ]
        );
        let retry_authorization =
            LinuxHeldChildReleaseAuthorization::test_for_record(&attached_record);
        assert!(matches!(
            release_attached_inert_target(&mut host, &mut domain, retry_authorization, (),),
            Err(CgroupError::InvalidState(_))
        ));
    }

    #[test]
    fn release_authority_must_join_the_attached_domain_before_one_shot_is_burned() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        attach_staged_launcher(&mut host, &mut domain, staged_launcher()).unwrap();
        host.operation = 0;
        host.calls.clear();
        host.journals.clear();

        let mut foreign_record = domain.record.clone();
        foreign_record.native_launch.attempt_id = "foreign-release-attempt".into();
        let foreign = LinuxHeldChildReleaseAuthorization::test_for_record(&foreign_record);
        assert!(matches!(
            release_attached_inert_target(&mut host, &mut domain, foreign, ()),
            Err(CgroupError::InvalidRequest {
                field: "release_authorization.native_launch",
                ..
            })
        ));
        assert_eq!(domain.state(), DomainJournalState::Attached);
        assert!(!domain.release_attempted);
        assert!(host.calls.is_empty());
        assert!(host.journals.is_empty());

        let exact = release_authorization(&domain);
        release_attached_inert_target(&mut host, &mut domain, exact, ()).unwrap();
        assert_eq!(domain.state(), DomainJournalState::Released);
    }

    #[test]
    fn every_release_boundary_failure_is_cleanup_only_and_nonretryable() {
        let mut baseline = MockHost::valid();
        let mut baseline_domain = prepare_success(&mut baseline);
        attach_staged_launcher(&mut baseline, &mut baseline_domain, staged_launcher()).unwrap();
        baseline.operation = 0;
        baseline.calls.clear();
        let authorization = release_authorization(&baseline_domain);
        release_attached_inert_target(&mut baseline, &mut baseline_domain, authorization, ())
            .unwrap();
        let total = baseline.operation;

        for failure in 1..=total {
            let mut host = MockHost::valid();
            let mut domain = prepare_success(&mut host);
            attach_staged_launcher(&mut host, &mut domain, staged_launcher()).unwrap();
            let attached_record = domain.record.clone();
            host.operation = 0;
            host.calls.clear();
            host.fail_at = Some(failure);
            let authorization = release_authorization(&domain);
            let error = release_attached_inert_target(&mut host, &mut domain, authorization, ())
                .unwrap_err();
            assert!(
                matches!(error, CgroupError::ReconciliationRequired { .. }),
                "release failure {failure} returned {error:?}"
            );
            host.fail_at = None;
            let retry_authorization =
                LinuxHeldChildReleaseAuthorization::test_for_record(&attached_record);
            assert!(matches!(
                release_attached_inert_target(&mut host, &mut domain, retry_authorization, (),),
                Err(CgroupError::InvalidState(_))
            ));
        }
    }

    #[test]
    fn cleanup_first_permanently_prevents_release() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        attach_staged_launcher(&mut host, &mut domain, staged_launcher()).unwrap();
        let attached_record = domain.record.clone();
        cleanup_domain(&mut host, &mut domain, 1).unwrap();
        assert_eq!(domain.state(), DomainJournalState::Removed);
        let authorization = LinuxHeldChildReleaseAuthorization::test_for_record(&attached_record);
        assert!(matches!(
            release_attached_inert_target(&mut host, &mut domain, authorization, (),),
            Err(CgroupError::InvalidState(_))
        ));
        assert!(host.journals.iter().all(|record| !matches!(
            record.state,
            DomainJournalState::Held
                | DomainJournalState::ReleaseIntended
                | DomainJournalState::Released
        )));
    }

    #[test]
    fn restart_from_release_intent_never_replays_and_remains_unknown_after_cleanup() {
        let mut source = MockHost::valid();
        let mut domain = prepare_success(&mut source);
        attach_staged_launcher(&mut source, &mut domain, staged_launcher()).unwrap();
        source.operation = 0;
        source.calls.clear();
        source.fail_at = Some(7); // commit-held-release, after synchronized intent.
        let authorization = release_authorization(&domain);
        assert!(matches!(
            release_attached_inert_target(&mut source, &mut domain, authorization, (),),
            Err(CgroupError::ReconciliationRequired { .. })
        ));
        assert_eq!(domain.state(), DomainJournalState::ReleaseIntended);
        let intent = domain.record.clone();

        let mut recovered = MockHost::for_record(&intent);
        let outcome = recover_success(&mut recovered, intent);
        assert!(matches!(
            outcome,
            DomainRecoveryOutcome::CleanedCommandOutcomeUnknown(_)
        ));
        assert!(recovered.calls.iter().all(|call| !matches!(
            call.as_str(),
            "plan-held-release" | "prepare-held-release" | "commit-held-release"
        )));
        let removed = recovered.journals.last().unwrap().clone();
        assert_eq!(removed.state, DomainJournalState::Removed);
        assert!(removed.release_intent_recorded);
        let mut second_restart = MockHost::for_record(&removed);
        assert!(matches!(
            recover_success(&mut second_restart, removed),
            DomainRecoveryOutcome::CleanedCommandOutcomeUnknown(_)
        ));
    }

    #[test]
    fn every_injected_attach_failure_requires_reconciliation() {
        let mut baseline = MockHost::valid();
        let mut domain = prepare_success(&mut baseline);
        baseline.operation = 0;
        baseline.calls.clear();
        attach_staged_launcher(&mut baseline, &mut domain, staged_launcher()).unwrap();
        let total = baseline.operation;

        for failure in 1..=total {
            let mut host = MockHost::valid();
            let mut domain = prepare_success(&mut host);
            host.operation = 0;
            host.calls.clear();
            host.fail_at = Some(failure);
            let error =
                attach_staged_launcher(&mut host, &mut domain, staged_launcher()).unwrap_err();
            assert!(
                matches!(error, CgroupError::ReconciliationRequired { .. }),
                "attach failure {failure} returned {error:?}"
            );
        }
    }

    #[test]
    fn recovery_covers_create_configure_cleanup_and_removed_states() {
        let mut source = MockHost::valid();
        let mut domain = prepare_success(&mut source);
        let create_intent = source.journals[0].clone();
        let configuring = source.journals[1].clone();

        let mut absent_host = MockHost::valid();
        absent_host.leaf_present = false;
        let outcome = recover_success(&mut absent_host, create_intent);
        assert!(matches!(
            outcome,
            DomainRecoveryOutcome::AbortedBeforeCreate(DomainJournalRecord {
                state: DomainJournalState::CreateAborted,
                ..
            })
        ));

        let mut configuring_host = MockHost::for_record(&configuring);
        let outcome = recover_success(&mut configuring_host, configuring);
        assert!(matches!(outcome, DomainRecoveryOutcome::Cleaned(_)));

        let evidence = cleanup_domain(&mut source, &mut domain, 1).unwrap();
        for state in [
            DomainJournalState::EmptyProven,
            DomainJournalState::RemoveIntended,
            DomainJournalState::Removed,
        ] {
            let record = source
                .journals
                .iter()
                .find(|record| record.state == state)
                .cloned()
                .unwrap_or_else(|| evidence.journal_record.clone());
            let mut recovery_host = MockHost::for_record(&record);
            let recovered = recover_success(&mut recovery_host, record);
            assert!(matches!(recovered, DomainRecoveryOutcome::Cleaned(_)));
        }
    }

    #[test]
    fn recovery_covers_attach_attached_and_killing_states() {
        let mut source = MockHost::valid();
        let mut domain = prepare_success(&mut source);
        attach_staged_launcher(&mut source, &mut domain, staged_launcher()).unwrap();
        let attach_intent = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::AttachIntended)
            .unwrap()
            .clone();
        let attached = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::Attached)
            .unwrap()
            .clone();
        cleanup_domain(&mut source, &mut domain, 1).unwrap();
        let killing = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::Killing)
            .unwrap()
            .clone();

        for record in [attach_intent, attached, killing] {
            let mut recovery_host = MockHost::for_record(&record);
            let outcome = recover_success(&mut recovery_host, record);
            assert!(matches!(outcome, DomainRecoveryOutcome::Cleaned(_)));
        }
    }

    #[test]
    fn recovery_accepts_realistic_child_presence_for_every_journal_state() {
        let mut source = MockHost::valid();
        let mut domain = prepare_success(&mut source);
        attach_staged_launcher(&mut source, &mut domain, staged_launcher()).unwrap();
        let authorization = release_authorization(&domain);
        release_attached_inert_target(&mut source, &mut domain, authorization, ()).unwrap();
        let evidence = cleanup_domain(&mut source, &mut domain, 1).unwrap();

        let mut records = DomainJournalState::ALL
            .iter()
            .filter_map(|state| {
                source
                    .journals
                    .iter()
                    .find(|record| record.state == *state)
                    .cloned()
            })
            .collect::<Vec<_>>();
        let mut aborted = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::CreateIntended)
            .unwrap()
            .clone();
        aborted.state = DomainJournalState::CreateAborted;
        aborted.validate().unwrap();
        records.push(aborted);
        assert_eq!(records.len(), DomainJournalState::ALL.len());

        for record in records {
            let state = record.state;
            let mut host = MockHost::for_record(&record);
            let outcome = recover_success(&mut host, record);
            assert!(
                matches!(
                    outcome,
                    DomainRecoveryOutcome::AbortedBeforeCreate(_)
                        | DomainRecoveryOutcome::Cleaned(_)
                        | DomainRecoveryOutcome::CleanedCommandOutcomeUnknown(_)
                ),
                "state {state:?} did not reach an authoritative recovery outcome"
            );
            assert!(!host.lock_held);
        }
        evidence.validate().unwrap();
    }

    #[test]
    fn recovery_rejects_foreign_children_and_child_inspection_disagreement() {
        let mut source = MockHost::valid();
        prepare_success(&mut source);
        let record = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::Prepared)
            .unwrap()
            .clone();

        let mut foreign = MockHost::for_record(&record);
        foreign.delegation.existing_children.push("foreign".into());
        let attempt =
            reconcile_persisted_domain(&mut foreign, record.clone(), &recovery_binding(), 1)
                .unwrap();
        let DomainRecoveryAttempt::ReconciliationRequired(lease) = attempt else {
            panic!("foreign child must block recovery")
        };
        assert!(matches!(
            lease.cause(),
            CgroupError::UnexpectedChildren { .. }
        ));
        assert!(lease.is_active());
        assert!(foreign.lock_held);

        let mut inconsistent = MockHost::for_record(&record);
        inconsistent.leaf_present = false;
        let attempt =
            reconcile_persisted_domain(&mut inconsistent, record, &recovery_binding(), 1).unwrap();
        let DomainRecoveryAttempt::ReconciliationRequired(lease) = attempt else {
            panic!("child/inspection disagreement must block recovery")
        };
        assert!(matches!(
            lease.cause(),
            CgroupError::ReconciliationRequired {
                phase: "recover-child-readback",
                ..
            }
        ));
    }

    #[test]
    fn journal_state_shape_rejects_impossible_fields_for_every_phase() {
        let mut source = MockHost::valid();
        let mut domain = prepare_success(&mut source);
        attach_staged_launcher(&mut source, &mut domain, staged_launcher()).unwrap();
        let authorization = release_authorization(&domain);
        release_attached_inert_target(&mut source, &mut domain, authorization, ()).unwrap();
        let evidence = cleanup_domain(&mut source, &mut domain, 1).unwrap();
        let by_state = |state| {
            source
                .journals
                .iter()
                .find(|record| record.state == state)
                .unwrap()
                .clone()
        };

        let mut forged = Vec::new();
        let mut create = by_state(DomainJournalState::CreateIntended);
        create.leaf_identity = Some(LEAF_ID);
        forged.push(create);

        let mut aborted = by_state(DomainJournalState::CreateIntended);
        aborted.state = DomainJournalState::CreateAborted;
        aborted.staged_launcher = Some(staged_launcher());
        forged.push(aborted);

        let mut configuring = by_state(DomainJournalState::Configuring);
        configuring.read_back_limits = Some(evidence.read_back_limits);
        forged.push(configuring);

        let mut prepared = by_state(DomainJournalState::Prepared);
        prepared.staged_launcher = Some(staged_launcher());
        forged.push(prepared);

        let mut held = by_state(DomainJournalState::Held);
        held.release_binding = None;
        forged.push(held);

        let mut release_intended = by_state(DomainJournalState::ReleaseIntended);
        release_intended.release_intent_recorded = false;
        forged.push(release_intended);

        let mut released = by_state(DomainJournalState::Released);
        released.release_observation = None;
        forged.push(released);

        for state in [
            DomainJournalState::AttachIntended,
            DomainJournalState::Attached,
            DomainJournalState::Killing,
        ] {
            let mut record = by_state(state);
            record.kill_value = Some(CGROUP_KILL_VALUE.to_vec());
            forged.push(record);
        }

        for state in [
            DomainJournalState::EmptyProven,
            DomainJournalState::RemoveIntended,
            DomainJournalState::Removed,
        ] {
            let mut record = by_state(state);
            record.kill_value = None;
            forged.push(record);
        }

        assert!(forged.iter().all(|record| record.validate().is_err()));
    }

    #[test]
    fn request_digest_is_bound_across_recovery_and_cleanup_evidence() {
        let mut source = MockHost::valid();
        let mut domain = prepare_success(&mut source);
        let prepared = source.journals.last().unwrap().clone();
        let mut wrong_binding = recovery_binding();
        wrong_binding.request_digest = "e".repeat(64);
        let mut recovery_host = MockHost::valid();
        assert!(
            reconcile_persisted_domain(&mut recovery_host, prepared, &wrong_binding, 1,).is_err()
        );
        assert_eq!(recovery_host.lock_acquires, 0);

        let mut crossed_native_binding = recovery_binding();
        crossed_native_binding.native_launch.attempt_id = "crossed-attempt".into();
        let prepared = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::Prepared)
            .unwrap()
            .clone();
        assert!(
            reconcile_persisted_domain(&mut recovery_host, prepared, &crossed_native_binding, 1,)
                .is_err()
        );
        assert_eq!(recovery_host.lock_acquires, 0);

        let mut crossed_snapshot_binding = recovery_binding();
        crossed_snapshot_binding.native_launch.input_snapshot =
            Digest::sha256(b"crossed-recovery-snapshot");
        let prepared = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::Prepared)
            .unwrap()
            .clone();
        assert!(
            reconcile_persisted_domain(&mut recovery_host, prepared, &crossed_snapshot_binding, 1,)
                .is_err()
        );
        assert_eq!(recovery_host.lock_acquires, 0);

        let mut evidence = cleanup_domain(&mut source, &mut domain, 1).unwrap();
        evidence.journal_record.request_digest = "e".repeat(64);
        assert!(evidence.validate().is_err());
    }

    #[test]
    fn released_attach_hold_is_observed_only_killed_and_classified_unknown() {
        let mut source = MockHost::valid();
        let mut domain = prepare_success(&mut source);
        attach_staged_launcher(&mut source, &mut domain, staged_launcher()).unwrap();
        let attach_intent = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::AttachIntended)
            .unwrap()
            .clone();

        let mut recovery_host = MockHost::for_record(&attach_intent);
        recovery_host.staged_recovery = StagedLauncherRecoveryState::ReleasedOrUnknown;
        let outcome = recover_success(&mut recovery_host, attach_intent);
        let DomainRecoveryOutcome::CleanedCommandOutcomeUnknown(unknown) = outcome else {
            panic!("released launcher must keep command outcome unknown")
        };
        assert_eq!(
            unknown.escaped_membership,
            EscapedMembershipStatus::ProvenInsideDomain
        );
        assert!(unknown.blocks_completion());
        assert!(recovery_host.self_attach_values.is_empty());
        assert!(
            recovery_host
                .writes
                .contains(&(LeafWriteFile::CgroupKill, b"1\n".to_vec()))
        );
        assert_eq!(recovery_host.lock_acquires, recovery_host.lock_releases);
    }

    #[test]
    fn pid_reuse_during_initial_attach_never_reaches_attached_state() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        let launcher = staged_launcher();
        host.staged_observation = Some(StagedLauncherObservation {
            pid: launcher.pid,
            process_start_time_ticks: launcher.process_start_time_ticks + 1,
            held_before_exec: true,
            cgroup_procs: format!("{}\n", launcher.pid).into_bytes(),
        });
        let error = attach_staged_launcher(&mut host, &mut domain, launcher.clone()).unwrap_err();
        assert!(matches!(
            error,
            CgroupError::ReconciliationRequired {
                phase: "attach-membership-readback",
                ..
            }
        ));
        assert_eq!(domain.state(), DomainJournalState::AttachIntended);
        assert_eq!(host.self_attach_values, [LAUNCHER_SELF_ATTACH_VALUE]);
        assert!(
            host.journals
                .iter()
                .all(|record| record.state != DomainJournalState::Attached)
        );
        assert!(
            host.writes
                .iter()
                .all(|(file, _)| file.name() != "cgroup.procs")
        );
    }

    #[test]
    fn released_reused_pid_is_never_moved_or_targeted_and_blocks_completion() {
        let mut source = MockHost::valid();
        let mut domain = prepare_success(&mut source);
        attach_staged_launcher(&mut source, &mut domain, staged_launcher()).unwrap();
        let attach_intent = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::AttachIntended)
            .unwrap()
            .clone();

        let launcher = attach_intent.staged_launcher.as_ref().unwrap();
        let mut host = MockHost::for_record(&attach_intent);
        host.staged_recovery = StagedLauncherRecoveryState::ReleasedOrUnknown;
        host.staged_observation = Some(StagedLauncherObservation {
            pid: launcher.pid,
            process_start_time_ticks: launcher.process_start_time_ticks + 1,
            held_before_exec: false,
            cgroup_procs: Vec::new(),
        });
        let outcome = recover_success(&mut host, attach_intent);
        let DomainRecoveryOutcome::CleanedCommandOutcomeUnknown(unknown) = outcome else {
            panic!("reused PID must keep command outcome unknown")
        };
        assert_eq!(
            unknown.escaped_membership,
            EscapedMembershipStatus::UnprovenBlockingCompletion
        );
        assert!(unknown.blocks_completion());
        assert!(host.self_attach_values.is_empty());
        assert!(
            host.writes
                .iter()
                .all(|(file, _)| file.name() != "cgroup.procs")
        );
        assert!(
            host.writes
                .contains(&(LeafWriteFile::CgroupKill, CGROUP_KILL_VALUE.to_vec()))
        );
    }

    #[test]
    fn unexpectedly_populated_prepared_path_is_killed_before_unknown_finish() {
        let mut source = MockHost::valid();
        prepare_success(&mut source);
        let create_intended = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::CreateIntended)
            .unwrap()
            .clone();
        let configuring = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::Configuring)
            .unwrap()
            .clone();

        for record in [create_intended, configuring] {
            let mut recovery_host = MockHost::for_record(&record);
            recovery_host.leaf.initial_events = b"populated 1\nfrozen 0\n".to_vec();
            recovery_host.leaf.initial_procs = b"77\n".to_vec();
            recovery_host.leaf_reads.insert(
                LeafFile::CgroupEvents,
                VecDeque::from([
                    b"populated 0\nfrozen 0\n".to_vec(),
                    b"populated 0\nfrozen 0\n".to_vec(),
                ]),
            );
            recovery_host.leaf_reads.insert(
                LeafFile::CgroupProcs,
                VecDeque::from([Vec::new(), Vec::new(), Vec::new(), Vec::new()]),
            );
            let outcome = recover_success(&mut recovery_host, record);
            assert!(matches!(
                outcome,
                DomainRecoveryOutcome::CleanedCommandOutcomeUnknown(_)
            ));
            assert_eq!(
                recovery_host
                    .writes
                    .iter()
                    .filter(|(file, bytes)| {
                        *file == LeafWriteFile::CgroupKill && bytes.as_slice() == CGROUP_KILL_VALUE
                    })
                    .count(),
                2
            );
        }
    }

    #[test]
    fn readback_mismatch_is_reconciliation_required() {
        let mut host = MockHost::valid();
        host.leaf_reads
            .insert(LeafFile::PidsMax, VecDeque::from([b"5\n".to_vec()]));
        let outcome = prepare_domain(&mut host, request()).unwrap();
        let PrepareDomainOutcome::ReconciliationRequired(lease) = outcome else {
            panic!("read-back mismatch must retain a reconciliation lease")
        };
        assert!(matches!(
            lease.cause(),
            CgroupError::ReconciliationRequired {
                phase: "prepare-readback",
                ..
            }
        ));
        assert!(lease.is_active());
        assert!(host.lock_held);
        assert_eq!(host.lock_releases, 0);
    }

    #[test]
    fn post_create_recovery_reuses_the_same_exclusive_lease_until_cleanup() {
        let mut host = MockHost::valid();
        host.leaf_reads
            .insert(LeafFile::PidsMax, VecDeque::from([b"5\n".to_vec()]));
        let outcome = prepare_domain(&mut host, request()).unwrap();
        let PrepareDomainOutcome::ReconciliationRequired(mut lease) = outcome else {
            panic!("post-create mismatch must retain a lease")
        };
        let record = host.journals.last().unwrap().clone();
        assert_eq!(record.state, DomainJournalState::Configuring);
        assert_eq!(host.lock_acquires, 1);
        assert_eq!(host.lock_releases, 0);

        host.leaf_reads
            .insert(LeafFile::PidsMax, VecDeque::from([b"4\n".to_vec()]));
        host.leaf_reads
            .insert(LeafFile::MemoryMax, VecDeque::from([b"1048576\n".to_vec()]));
        host.leaf_reads
            .insert(LeafFile::MemorySwapMax, VecDeque::from([b"0\n".to_vec()]));
        host.leaf_reads
            .insert(LeafFile::MemoryOomGroup, VecDeque::from([b"1\n".to_vec()]));

        host.operation = 0;
        host.fail_at = Some(1);
        assert!(
            reconcile_persisted_domain_with_lease(
                &mut host,
                &mut lease,
                record.clone(),
                &recovery_binding(),
                1,
            )
            .is_err()
        );
        assert!(lease.is_active());
        assert!(host.lock_held);
        assert_eq!(host.lock_acquires, 1);
        assert_eq!(host.lock_releases, 0);

        host.fail_at = None;
        let outcome = reconcile_persisted_domain_with_lease(
            &mut host,
            &mut lease,
            record,
            &recovery_binding(),
            1,
        )
        .unwrap();
        assert!(matches!(outcome, DomainRecoveryOutcome::Cleaned(_)));
        assert!(!lease.is_active());
        assert!(!host.lock_held);
        assert_eq!(host.lock_acquires, 1);
        assert_eq!(host.lock_releases, 1);
    }

    #[test]
    fn recovery_unlock_failure_keeps_a_retryable_exclusive_lease() {
        let mut source = MockHost::valid();
        prepare_success(&mut source);
        let mut aborted = source.journals[0].clone();
        aborted.state = DomainJournalState::CreateAborted;
        aborted.validate().unwrap();

        let mut host = MockHost::valid();
        host.fail_unlock = true;
        let attempt =
            reconcile_persisted_domain(&mut host, aborted.clone(), &recovery_binding(), 1).unwrap();
        let DomainRecoveryAttempt::ReconciliationRequired(mut lease) = attempt else {
            panic!("unlock uncertainty must retain the recovery lease")
        };
        assert!(matches!(
            lease.cause(),
            CgroupError::LockReleaseFailed { primary: None, .. }
        ));
        assert!(lease.is_active());
        assert!(host.lock_held);

        host.fail_unlock = false;
        let outcome = reconcile_persisted_domain_with_lease(
            &mut host,
            &mut lease,
            aborted,
            &recovery_binding(),
            1,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            DomainRecoveryOutcome::AbortedBeforeCreate(_)
        ));
        assert!(!lease.is_active());
        assert!(!host.lock_held);
    }

    #[test]
    fn every_injected_prepare_failure_before_create_refuses_without_leaf_reconciliation() {
        let mut baseline = MockHost::valid();
        let _ = prepare_success(&mut baseline);
        let create_position = baseline
            .calls
            .iter()
            .position(|call| call == "create-leaf")
            .unwrap()
            + 1;
        for failure in 1..create_position {
            let mut host = MockHost::valid();
            host.fail_at = Some(failure);
            let error = prepare_domain(&mut host, request()).unwrap_err();
            assert!(
                !matches!(error, CgroupError::ReconciliationRequired { .. }),
                "pre-create failure {failure} returned {error:?}"
            );
            assert!(!host.calls.iter().any(|call| call == "create-leaf"));
            assert_eq!(host.lock_acquires, host.lock_releases);
        }
    }

    #[test]
    fn every_injected_prepare_failure_after_create_requires_reconciliation() {
        let mut baseline = MockHost::valid();
        let _ = prepare_success(&mut baseline);
        let create_position = baseline
            .calls
            .iter()
            .position(|call| call == "create-leaf")
            .unwrap()
            + 1;
        let total = baseline.operation;
        for failure in create_position..=total {
            let mut host = MockHost::valid();
            host.fail_at = Some(failure);
            let outcome = prepare_domain(&mut host, request()).unwrap();
            let PrepareDomainOutcome::ReconciliationRequired(lease) = outcome else {
                panic!("post-create failure {failure} did not retain a lease")
            };
            assert!(
                matches!(lease.cause(), CgroupError::ReconciliationRequired { .. }),
                "failure {failure} returned {:?}",
                lease.cause()
            );
            assert!(lease.is_active());
            assert_eq!(host.lock_acquires, 1);
            assert_eq!(host.lock_releases, 0);
            assert!(host.lock_held);
            assert!(host.acquire_delegation_lock().is_err());
        }
    }

    #[test]
    fn every_injected_recovery_failure_retains_exclusive_lease() {
        let mut source = MockHost::valid();
        prepare_success(&mut source);
        let record = source
            .journals
            .iter()
            .find(|record| record.state == DomainJournalState::Prepared)
            .unwrap()
            .clone();

        let mut baseline = MockHost::for_record(&record);
        recover_success(&mut baseline, record.clone());
        let total = baseline.operation;
        assert_eq!(baseline.lock_acquires, 1);
        assert_eq!(baseline.lock_releases, 1);

        for failure in 1..=total {
            let mut host = MockHost::for_record(&record);
            host.fail_at = Some(failure);
            let attempt =
                reconcile_persisted_domain(&mut host, record.clone(), &recovery_binding(), 1);
            if failure == 1 {
                assert!(attempt.is_err());
                assert_eq!(host.lock_acquires, 0);
                continue;
            }
            let DomainRecoveryAttempt::ReconciliationRequired(lease) = attempt.unwrap() else {
                panic!("recovery failure {failure} unexpectedly completed")
            };
            assert!(lease.is_active());
            assert_eq!(host.lock_acquires, 1);
            assert_eq!(host.lock_releases, usize::from(failure == total));
            assert!(host.lock_held);
        }
    }

    #[test]
    fn lock_release_failure_preserves_primary_reconciliation_error() {
        let mut host = MockHost::valid();
        host.delegation.named_entry_matches_descriptor = false;
        host.fail_unlock = true;
        let error = prepare_domain(&mut host, request()).unwrap_err();
        assert!(matches!(
            error,
            CgroupError::LockReleaseFailed {
                primary: Some(_),
                ..
            }
        ));
        assert_eq!(host.lock_acquires, 1);
        assert_eq!(host.lock_releases, 1);
    }

    #[test]
    fn cleanup_writes_exact_kill_then_requires_two_stable_empty_reads() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        let evidence = cleanup_domain(&mut host, &mut domain, 3).unwrap();
        assert_eq!(evidence.kill_value, b"1\n");
        assert_eq!(evidence.stable_empty_reads, 2);
        assert_eq!(evidence.surviving_processes, 0);
        assert!(evidence.leaf_removed);
        evidence.validate().unwrap();
        assert!(
            host.writes
                .contains(&(LeafWriteFile::CgroupKill, b"1\n".to_vec()))
        );
        let kill = host
            .calls
            .iter()
            .position(|call| call == "cgroup.kill")
            .unwrap();
        let first_events = host
            .calls
            .iter()
            .position(|call| call == "cgroup.events")
            .unwrap();
        assert!(kill < first_events);
    }

    #[test]
    fn every_injected_cleanup_effect_failure_requires_reconciliation() {
        let mut baseline = MockHost::valid();
        let mut domain = prepare_success(&mut baseline);
        baseline.operation = 0;
        baseline.calls.clear();
        cleanup_domain(&mut baseline, &mut domain, 1).unwrap();
        let total = baseline.operation;

        for failure in 1..=total {
            let mut host = MockHost::valid();
            let mut domain = prepare_success(&mut host);
            host.operation = 0;
            host.calls.clear();
            host.fail_at = Some(failure);
            let error = cleanup_domain(&mut host, &mut domain, 1).unwrap_err();
            assert!(
                matches!(error, CgroupError::ReconciliationRequired { .. }),
                "cleanup failure {failure} returned {error:?}"
            );
        }
    }

    #[test]
    fn killing_reconciliation_reissues_idempotent_kill() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        host.operation = 0;
        host.calls.clear();
        // persist + sync are operations 1 and 2; kill is operation 3.
        host.fail_at = Some(3);
        assert!(matches!(
            cleanup_domain(&mut host, &mut domain, 1).unwrap_err(),
            CgroupError::ReconciliationRequired { .. }
        ));
        assert_eq!(domain.state(), DomainJournalState::Killing);

        host.fail_at = None;
        host.leaf_reads.insert(
            LeafFile::CgroupEvents,
            VecDeque::from([b"populated 0\nfrozen 0\n".to_vec()]),
        );
        host.leaf_reads.insert(
            LeafFile::CgroupProcs,
            VecDeque::from([Vec::new(), Vec::new()]),
        );
        let evidence = cleanup_domain(&mut host, &mut domain, 1).unwrap();
        evidence.validate().unwrap();
        assert_eq!(
            host.calls
                .iter()
                .filter(|call| call.as_str() == "cgroup.kill")
                .count(),
            2
        );
    }

    #[test]
    fn cleanup_evidence_validator_rejects_forged_empty_claim() {
        let mut host = MockHost::valid();
        let mut domain = prepare_success(&mut host);
        let mut evidence = cleanup_domain(&mut host, &mut domain, 1).unwrap();
        evidence.observations.last_mut().unwrap().bytes = b"9\n".to_vec();
        assert!(evidence.validate().is_err());
    }

    #[test]
    fn populated_or_unstable_leaf_never_produces_cleanup_evidence() {
        let mut host = MockHost::valid();
        host.leaf_reads.insert(
            LeafFile::CgroupEvents,
            VecDeque::from([
                b"populated 1\nfrozen 0\n".to_vec(),
                b"populated 0\nfrozen 0\n".to_vec(),
            ]),
        );
        host.leaf_reads.insert(
            LeafFile::CgroupProcs,
            VecDeque::from([b"44\n".to_vec(), Vec::new(), Vec::new(), Vec::new()]),
        );
        let mut domain = prepare_success(&mut host);
        let evidence = cleanup_domain(&mut host, &mut domain, 2).unwrap();
        assert_eq!(evidence.observations.len(), 6);

        let mut host = MockHost::valid();
        host.leaf_reads.insert(
            LeafFile::CgroupEvents,
            VecDeque::from([b"populated 1\nfrozen 0\n".to_vec()]),
        );
        host.leaf_reads.insert(
            LeafFile::CgroupProcs,
            VecDeque::from([b"44\n".to_vec(), b"44\n".to_vec()]),
        );
        let mut domain = prepare_success(&mut host);
        let error = cleanup_domain(&mut host, &mut domain, 1).unwrap_err();
        assert!(matches!(error, CgroupError::CleanupIncomplete { .. }));
        assert_eq!(domain.state(), DomainJournalState::Killing);
    }

    #[test]
    fn active_probe_and_delegation_identity_are_hard_requirements() {
        let mut host = MockHost::valid();
        host.delegation.negative_probe.stable_empty_procs = false;
        assert!(matches!(
            prepare_domain(&mut host, request()).unwrap_err(),
            CgroupError::UnsupportedKernelApi { .. }
        ));

        let mut host = MockHost::valid();
        host.delegation.named_entry_matches_descriptor = false;
        assert!(matches!(
            prepare_domain(&mut host, request()).unwrap_err(),
            CgroupError::InvalidObservation { .. }
        ));
    }

    #[test]
    fn prepare_surfaces_distinct_live_probe_lease_and_retry_consumes_it() {
        let mut host = MockHost::valid();
        host.probe_failures_remaining = 1;
        let outcome = prepare_domain(&mut host, request()).unwrap();
        let PrepareDomainOutcome::ProbeReconciliationRequired(mut lease) = outcome else {
            panic!("unresolved durable probe must return its distinct lease")
        };
        assert!(lease.is_active());
        assert!(host.lock_held);
        assert!(host.journals.is_empty());
        assert!(host.calls.iter().all(|call| call != "create-leaf"));
        assert!(matches!(
            lease.cause(),
            CgroupError::ProbeReconciliationRequired { .. }
        ));

        let evidence = reconcile_preflight_probe_with_lease(&mut host, &mut lease).unwrap();
        evidence.validate().unwrap();
        assert!(!lease.is_active());
        assert!(!host.lock_held);
        assert_eq!(host.probe_runs, 2);
    }

    #[test]
    fn restart_probe_recovery_retains_lock_and_blocks_domain_recovery() {
        let mut host = MockHost::valid();
        host.probe_failures_remaining = 1;
        let attempt = reconcile_preflight_probe_on_restart(&mut host).unwrap();
        let ProbeRecoveryAttempt::ReconciliationRequired(mut lease) = attempt else {
            panic!("restart uncertainty must retain a typed probe lease")
        };
        assert!(lease.is_active());
        assert!(host.lock_held);
        assert!(host.acquire_delegation_lock().is_err());
        reconcile_preflight_probe_with_lease(&mut host, &mut lease).unwrap();
        assert!(!host.lock_held);

        let mut source = MockHost::valid();
        let record = prepare_success(&mut source).record;
        let mut recovery_host = MockHost::for_record(&record);
        recovery_host.probe_failures_remaining = 1;
        let attempt =
            reconcile_persisted_domain(&mut recovery_host, record, &recovery_binding(), 1).unwrap();
        let DomainRecoveryAttempt::ProbeReconciliationRequired(lease) = attempt else {
            panic!("domain restart must stop at the independent unresolved probe")
        };
        assert!(lease.is_active());
        assert!(recovery_host.lock_held);
    }
