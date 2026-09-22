    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct EmptyDirectory {
        root: PathBuf,
    }

    impl EmptyDirectory {
        fn new(label: &str) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "grok-build-gate-1-empty-{label}-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("create empty evidence fixture");
            Self { root }
        }
    }

    impl Drop for EmptyDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct Fixture {
        root: PathBuf,
        bundle: Gate1EvidenceBundle,
    }

    impl Fixture {
        #[allow(
            clippy::too_many_lines,
            reason = "the fixture keeps one complete, internally correlated Gate 1 evidence bundle visible for adversarial mutation tests"
        )]
        fn new(platform: Gate1Platform) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "grok-build-gate-1-evidence-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("outputs")).expect("create evidence fixture");

            let commitments = FixtureCommitments {
                workspace: digest(1),
                policy: digest(2),
                admitted_snapshot: digest(3),
            };
            let mut cases = Vec::new();
            for (index, case_id) in required_case_ids(platform).into_iter().enumerate() {
                let bytes = format!("authoritative evidence for {case_id}\n").into_bytes();
                let complete_output = complete_output(&root, case_id, case_id, &bytes, b"");
                cases.push(CaseEvidence {
                    case_id: case_id.into(),
                    outcome: CaseOutcome::Passed,
                    started_unix_milliseconds: 1_001 + u64::try_from(index).unwrap(),
                    finished_unix_milliseconds: 1_002 + u64::try_from(index).unwrap(),
                    exit_code: 0,
                    production_policy: true,
                    workspace_digest: commitments.workspace.clone(),
                    policy_digest: commitments.policy.clone(),
                    snapshot_digest: commitments.admitted_snapshot.clone(),
                    authoritative_observation_digest: digest(u8::try_from(index + 10).unwrap()),
                    complete_output,
                });
            }
            let aggregate_bytes = b"complete fixture output\n";
            let aggregate_output =
                complete_output(&root, "fixture", "aggregate", aggregate_bytes, b"");
            let execution = ExecutionEvidence {
                target_triple: platform.target_triple().into(),
                operating_system_image: match platform {
                    Gate1Platform::Macos15AppleSilicon => "macOS 15.7".into(),
                    Gate1Platform::Ubuntu2604X8664 => "Ubuntu 26.04".into(),
                    Gate1Platform::Fedora44X8664 => "Fedora 44".into(),
                },
                kernel_release: "fixture-kernel".into(),
                rustc_version: PINNED_RUSTC_VERSION.into(),
                cargo_version: PINNED_CARGO_VERSION.into(),
                exact_command: GATE_1_EXACT_COMMAND.into(),
                started_unix_milliseconds: 1_000,
                finished_unix_milliseconds: 2_000,
                exit_code: 0,
                complete_output: aggregate_output,
            };
            let worker_id = "worker-gate-1";
            let lease_epoch = 1;
            let lease_id = grok_build_core::WorkerLease::derive_lease_id(
                "sprint-gate-1",
                "task-gate-1",
                worker_id,
                lease_epoch,
            )
            .expect("derive fixture worker lease id");
            let mut worker_lease = WorkerLeaseEvidence {
                worker_id: worker_id.into(),
                lease_id: lease_id.clone(),
                lease_epoch,
                worker_lease_digest: digest(100),
                acquisition_event_id: "event-ready-to-leased".into(),
                acquisition_event_sequence: 7,
                acquired_at_unix_milliseconds: 1_005,
                ready_to_leased_atomically_committed: ProofClaim::PRESENT,
                atomic_acquisition: lease_stage(&lease_id, lease_epoch, 101),
                runner_launch: lease_stage(&lease_id, lease_epoch, 102),
                session_registration: lease_stage(&lease_id, lease_epoch, 103),
                all_task_effects: lease_stage(&lease_id, lease_epoch, 104),
                integration: lease_stage(&lease_id, lease_epoch, 105),
                cleanup: lease_stage(&lease_id, lease_epoch, 106),
                terminal_release: lease_stage(&lease_id, lease_epoch, 107),
                lease_chain_commitment_digest: String::new(),
                active_worker_leases_after_completion: 0,
            };
            worker_lease.lease_chain_commitment_digest =
                worker_lease_chain_commitment_digest(&worker_lease)
                    .expect("commit fixture worker lease chain");
            let workflow = WorkflowEvidence {
                contract_version: grok_build_core::CONTRACT_VERSION,
                sprint_id: "sprint-gate-1".into(),
                graph_id: "graph-gate-1".into(),
                task_id: "task-gate-1".into(),
                provider_kind: "deterministic_fake_model_provider".into(),
                max_workers: 1,
                task_graph_node_count: 1,
                terminal_state: SprintTerminalState::Completed,
                restart_source: "sqlite_readback".into(),
                final_report_id: "report-gate-1".into(),
                verified_snapshot_digest: digest(4),
                applied_snapshot_digest: digest(4),
                verification_receipt_digest: digest(5),
                completion_evidence_digest: digest(6),
                final_report_digest: digest(7),
                application_journal_digest: digest(8),
                rollback_journal_digest: digest(9),
                pre_sprint_snapshot_digest: commitments.admitted_snapshot.clone(),
                post_rollback_snapshot_digest: commitments.admitted_snapshot.clone(),
                restart_projection_digest_before: digest(10),
                restart_projection_digest_after: digest(10),
                restart_receipts_digest_before: digest(11),
                restart_receipts_digest_after: digest(11),
                contained_command_count: 2,
                uncertain_effect_replay_count: 0,
                descendants_after_cleanup: 0,
                worker_lease,
                production_runner_protocol_used: ProofClaim::PRESENT,
                verification_preceded_application: ProofClaim::PRESENT,
                application_target_only: ProofClaim::PRESENT,
                rollback_proven: ProofClaim::PRESENT,
            };
            Self {
                root,
                bundle: Gate1EvidenceBundle {
                    schema_version: GATE_1_EVIDENCE_SCHEMA_VERSION,
                    fixture_id: GATE_1_FIXTURE_ID.into(),
                    release_target_manifest_version: RELEASE_TARGET_MANIFEST_VERSION,
                    platform,
                    source: source_evidence(),
                    execution,
                    commitments,
                    workflow,
                    cases,
                },
            }
        }

        fn publish(&self) {
            let canonical = serde_json::to_vec(&self.bundle).expect("encode canonical bundle");
            fs::write(self.root.join(BUNDLE_FILE_NAME), canonical).expect("publish bundle");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn digest(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    fn output(
        result_id: &str,
        stream: OutputStream,
        path: impl Into<String>,
        bytes: &[u8],
    ) -> OutputArtifact {
        let mut artifact = OutputArtifact {
            result_id: result_id.into(),
            stream,
            relative_path: path.into(),
            byte_count: u64::try_from(bytes.len()).unwrap(),
            sha256: lowercase_hex(&Sha256::digest(bytes)),
            commitment_sha256: String::new(),
        };
        artifact.commitment_sha256 = output_artifact_commitment(&artifact).unwrap();
        artifact
    }

    fn complete_output(
        root: &Path,
        result_id: &str,
        stem: &str,
        stdout: &[u8],
        stderr: &[u8],
    ) -> CompleteOutputEvidence {
        let stdout_path = format!("outputs/{stem}.stdout");
        let stderr_path = format!("outputs/{stem}.stderr");
        fs::write(root.join(&stdout_path), stdout).expect("write stdout evidence");
        fs::write(root.join(&stderr_path), stderr).expect("write stderr evidence");
        CompleteOutputEvidence {
            stdout: output(result_id, OutputStream::Stdout, stdout_path, stdout),
            stderr: output(result_id, OutputStream::Stderr, stderr_path, stderr),
        }
    }

    fn source_evidence() -> SourceEvidence {
        let mut bindings = Vec::new();
        for (index, (kind, relative_path, file_paths)) in FIXED_SOURCE_BINDINGS.iter().enumerate() {
            let files: Vec<_> = file_paths
                .iter()
                .enumerate()
                .map(|(file_index, file_path)| SourceFileArtifact {
                    relative_path: (*file_path).into(),
                    byte_count: 1,
                    sha256: digest(u8::try_from(index * 8 + file_index + 16).unwrap()),
                })
                .collect();
            let mut binding = SourceBinding {
                kind: *kind,
                relative_path: (*relative_path).into(),
                byte_count: u64::try_from(files.len()).unwrap(),
                files,
                sha256: String::new(),
            };
            binding.sha256 = source_binding_digest(&binding).unwrap();
            bindings.push(binding);
        }
        let mut source = SourceEvidence {
            revision: std::env::var("GITHUB_SHA").unwrap_or_else(|_| "a".repeat(40)),
            git_tree_object: "b".repeat(40),
            source_tree_digest: String::new(),
            repository_dirty: false,
            untracked_source_count: 0,
            bindings,
        };
        source.source_tree_digest = source_tree_digest(&source).unwrap();
        source
    }

    fn recommit_source(source: &mut SourceEvidence) {
        for binding in &mut source.bindings {
            binding.byte_count = binding.files.iter().map(|file| file.byte_count).sum();
            binding.sha256 = source_binding_digest(binding).unwrap();
        }
        source.source_tree_digest = source_tree_digest(source).unwrap();
    }

    fn recommit_output(artifact: &mut OutputArtifact) {
        artifact.commitment_sha256 = output_artifact_commitment(artifact).unwrap();
    }

    fn lease_stage(lease_id: &str, lease_epoch: u64, digest_seed: u8) -> WorkerLeaseStageEvidence {
        WorkerLeaseStageEvidence {
            lease_id: lease_id.into(),
            lease_epoch,
            authoritative_observation_digest: digest(digest_seed),
        }
    }

    fn recommit_worker_lease(fixture: &mut Fixture) {
        let commitment =
            worker_lease_chain_commitment_digest(&fixture.bundle.workflow.worker_lease)
                .expect("recommit fixture worker lease chain");
        fixture
            .bundle
            .workflow
            .worker_lease
            .lease_chain_commitment_digest = commitment;
    }

    #[test]
    fn exact_bundle_validates_for_each_supported_platform() {
        for platform in [
            Gate1Platform::Macos15AppleSilicon,
            Gate1Platform::Ubuntu2604X8664,
            Gate1Platform::Fedora44X8664,
        ] {
            let fixture = Fixture::new(platform);
            fixture.publish();
            lint_gate1_evidence_candidate_structure(&fixture.root).unwrap();
        }
    }

    #[test]
    fn dirty_or_untracked_source_cannot_pass() {
        let mut dirty = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        dirty.bundle.source.repository_dirty = true;
        dirty.publish();
        assert!(
            lint_gate1_evidence_candidate_structure(&dirty.root)
                .unwrap_err()
                .to_string()
                .contains("dirty source")
        );

        let mut untracked = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        untracked.bundle.source.untracked_source_count = 1;
        untracked.publish();
        assert!(
            lint_gate1_evidence_candidate_structure(&untracked.root)
                .unwrap_err()
                .to_string()
                .contains("unbound untracked source")
        );
    }

    #[test]
    fn fixed_source_binding_omission_or_mutation_cannot_pass() {
        let mut omitted = Fixture::new(Gate1Platform::Fedora44X8664);
        omitted.bundle.source.bindings.pop();
        recommit_source(&mut omitted.bundle.source);
        omitted.publish();
        assert!(
            lint_gate1_evidence_candidate_structure(&omitted.root)
                .unwrap_err()
                .to_string()
                .contains("source binding count")
        );

        let mut mutated = Fixture::new(Gate1Platform::Fedora44X8664);
        mutated.bundle.source.bindings[1].files[0].sha256 = digest(240);
        mutated.bundle.source.bindings[1].sha256 =
            source_binding_digest(&mutated.bundle.source.bindings[1]).unwrap();
        mutated.publish();
        assert!(
            lint_gate1_evidence_candidate_structure(&mutated.root)
                .unwrap_err()
                .to_string()
                .contains("source-tree commitment")
        );
    }

    #[test]
    fn git_status_rejects_dirty_and_unbound_source_but_allows_exact_outputs() {
        validate_git_status_bytes(b"", Some("gate-evidence")).unwrap();
        validate_git_status_bytes(
            b"?? gate-evidence/outputs/diagnostic.stdout\0!! target/\0",
            Some("gate-evidence"),
        )
        .unwrap();
        assert!(
            validate_git_status_bytes(b"?? src/untracked.rs\0", Some("gate-evidence"))
                .unwrap_err()
                .to_string()
                .contains("unbound untracked source")
        );
        assert!(
            validate_git_status_bytes(b" M src/lib.rs\0", Some("gate-evidence"))
                .unwrap_err()
                .to_string()
                .contains("dirty")
        );
        assert!(
            validate_git_status_bytes(b"!! .env\0", Some("gate-evidence"))
                .unwrap_err()
                .to_string()
                .contains("ignored source")
        );
    }

    #[test]
    fn durable_capture_keeps_complete_stdout_and_stderr_distinct() {
        let fixture = EmptyDirectory::new("durable-capture");
        fs::create_dir(fixture.root.join("outputs")).unwrap();
        let root = EvidenceDirectory::open(&fixture.root).unwrap();
        let outputs = root.open_child_directory("outputs").unwrap();
        let stdout = b"stdout byte stream\n";
        let stderr = b"stderr byte stream\n";
        let (captured, retained) = capture_complete_output(
            &outputs,
            "capture-test",
            "capture-test.stdout",
            std::io::Cursor::new(stdout),
            "capture-test.stderr",
            std::io::Cursor::new(stderr),
        )
        .unwrap();
        assert_ne!(captured.stdout.relative_path, captured.stderr.relative_path);
        assert_eq!(captured.stdout.byte_count, stdout.len() as u64);
        assert_eq!(captured.stderr.byte_count, stderr.len() as u64);
        assert_eq!(
            captured.stdout.sha256,
            lowercase_hex(&Sha256::digest(stdout))
        );
        assert_eq!(
            captured.stderr.sha256,
            lowercase_hex(&Sha256::digest(stderr))
        );
        for file in retained {
            file.revalidate(&outputs, "captured test output").unwrap();
        }
    }

    #[test]
    fn retained_file_detects_same_byte_name_replacement() {
        let fixture = EmptyDirectory::new("retained-replacement");
        fs::write(fixture.root.join("artifact"), b"same bytes").unwrap();
        let root = EvidenceDirectory::open(&fixture.root).unwrap();
        let (_, retained) = read_retained_file(
            &root.descriptor,
            Path::new("artifact"),
            1_024,
            false,
            "replacement test artifact",
        )
        .unwrap();
        fs::remove_file(fixture.root.join("artifact")).unwrap();
        fs::write(fixture.root.join("artifact"), b"same bytes").unwrap();
        let error = retained
            .revalidate(&root.descriptor, "replacement test artifact")
            .unwrap_err()
            .to_string();
        assert!(error.contains("mutated") || error.contains("replaced"));
    }

    #[test]
    fn fixed_native_case_counts_remain_unchanged() {
        assert_eq!(
            required_case_ids(Gate1Platform::Macos15AppleSilicon).len(),
            29
        );
        assert_eq!(required_case_ids(Gate1Platform::Ubuntu2604X8664).len(), 32);
        assert_eq!(required_case_ids(Gate1Platform::Fedora44X8664).len(), 32);
    }

    #[test]
    fn macos_major_newer_than_manifest_target_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        fixture.bundle.execution.operating_system_image = "macOS 16.0".into();
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("operating-system image"));
    }

    #[test]
    fn prior_evidence_schema_cannot_substitute_for_v3() {
        let mut fixture = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        fixture.bundle.schema_version = 1;
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported Gate 1 evidence schema 1")
        );
    }

    #[test]
    fn different_release_target_manifest_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        fixture.bundle.release_target_manifest_version = 2;
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("release-target manifest version 2")
        );
    }

    #[test]
    fn missing_worker_lease_evidence_cannot_pass() {
        let fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        let mut value = serde_json::to_value(&fixture.bundle).expect("encode fixture value");
        value["workflow"]
            .as_object_mut()
            .expect("workflow object")
            .remove("worker_lease");
        fs::write(
            fixture.root.join(BUNDLE_FILE_NAME),
            serde_json::to_vec(&value).expect("encode fixture without lease"),
        )
        .expect("publish fixture without lease");

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("missing field `worker_lease`"));
    }

    #[test]
    fn missing_worker_lease_chain_stage_cannot_pass() {
        let fixture = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        let mut value = serde_json::to_value(&fixture.bundle).expect("encode fixture value");
        value["workflow"]["worker_lease"]
            .as_object_mut()
            .expect("worker lease object")
            .remove("cleanup");
        fs::write(
            fixture.root.join(BUNDLE_FILE_NAME),
            serde_json::to_vec(&value).expect("encode fixture without cleanup stage"),
        )
        .expect("publish fixture without cleanup stage");

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("missing field `cleanup`"));
    }

    #[test]
    fn zero_worker_lease_epoch_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        fixture.bundle.workflow.worker_lease.lease_epoch = 0;
        recommit_worker_lease(&mut fixture);
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("epoch must be greater than zero")
        );
    }

    #[test]
    fn zero_worker_lease_acquisition_sequence_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        fixture
            .bundle
            .workflow
            .worker_lease
            .acquisition_event_sequence = 0;
        recommit_worker_lease(&mut fixture);
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("acquisition event sequence must be greater than zero")
        );
    }

    #[test]
    fn nonzero_active_worker_lease_count_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        fixture
            .bundle
            .workflow
            .worker_lease
            .active_worker_leases_after_completion = 1;
        recommit_worker_lease(&mut fixture);
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("active worker leases"));
    }

    #[test]
    fn non_atomic_worker_lease_acquisition_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        fixture
            .bundle
            .workflow
            .worker_lease
            .ready_to_leased_atomically_committed = ProofClaim(false);
        recommit_worker_lease(&mut fixture);
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("atomic Ready-to-Leased"));
    }

    #[test]
    fn crossed_worker_lease_stage_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        fixture.bundle.workflow.worker_lease.integration.lease_epoch = 2;
        recommit_worker_lease(&mut fixture);
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("integration evidence is crossed")
        );
    }

    #[test]
    fn substituted_worker_lease_identity_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        let substituted_id = grok_build_core::WorkerLease::derive_lease_id(
            "sprint-gate-1",
            "task-gate-1",
            "different-worker",
            fixture.bundle.workflow.worker_lease.lease_epoch,
        )
        .expect("derive substituted lease id");
        fixture.bundle.workflow.worker_lease.lease_id = substituted_id.clone();
        for stage in [
            &mut fixture.bundle.workflow.worker_lease.atomic_acquisition,
            &mut fixture.bundle.workflow.worker_lease.runner_launch,
            &mut fixture.bundle.workflow.worker_lease.session_registration,
            &mut fixture.bundle.workflow.worker_lease.all_task_effects,
            &mut fixture.bundle.workflow.worker_lease.integration,
            &mut fixture.bundle.workflow.worker_lease.cleanup,
            &mut fixture.bundle.workflow.worker_lease.terminal_release,
        ] {
            stage.lease_id.clone_from(&substituted_id);
        }
        recommit_worker_lease(&mut fixture);
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("canonical sprint/task/worker/epoch")
        );
    }

    #[test]
    fn substituted_worker_lease_stage_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        fixture.bundle.workflow.worker_lease.cleanup =
            fixture.bundle.workflow.worker_lease.integration.clone();
        recommit_worker_lease(&mut fixture);
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("substituted or reused"));
    }

    #[test]
    fn stale_worker_lease_chain_commitment_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        fixture
            .bundle
            .workflow
            .worker_lease
            .terminal_release
            .authoritative_observation_digest = digest(108);
        fixture.publish();

        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("chain commitment does not bind"));
    }

    #[test]
    fn structurally_valid_candidate_still_maps_to_not_completed_exit_three() {
        let fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        fixture.publish();

        let outcome = crate::run_with_arguments([
            std::ffi::OsString::from("--validate-evidence-directory"),
            fixture.root.clone().into_os_string(),
        ])
        .expect("structurally valid candidate reaches the fail-closed CLI outcome");

        assert_eq!(crate::Outcome::exit_code(), std::process::ExitCode::from(3));
        assert!(outcome.reason().contains("no independent source"));
    }

    #[test]
    fn missing_case_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        fixture.bundle.cases.pop();
        fixture.publish();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("case cardinality"));
    }

    #[test]
    fn skipped_case_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        fixture.bundle.cases[0].outcome = CaseOutcome::Skipped;
        fixture.publish();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("unqualified pass"));
    }

    #[test]
    fn crossed_case_commitment_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        fixture.bundle.cases[0].policy_digest = digest(99);
        fixture.publish();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("crossed"));
    }

    #[test]
    fn tampered_complete_output_cannot_pass() {
        let fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        fixture.publish();
        let artifact = fixture.bundle.cases[0]
            .complete_output
            .stdout
            .relative_path
            .clone();
        fs::write(fixture.root.join(artifact), b"tampered output").unwrap();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("length") || error.to_string().contains("SHA-256"));
    }

    #[test]
    fn non_completed_workflow_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        fixture.bundle.workflow.terminal_state = SprintTerminalState::Blocked;
        fixture.publish();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("only computed Completed"));
    }

    #[test]
    fn noncanonical_json_cannot_pass() {
        let fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        let pretty = serde_json::to_vec_pretty(&fixture.bundle).unwrap();
        fs::write(fixture.root.join(BUNDLE_FILE_NAME), pretty).unwrap();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("canonical JSON"));
    }

    #[test]
    fn artifact_reuse_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        let reused = fixture.bundle.cases[0].complete_output.stdout.clone();
        fixture.bundle.cases[1].complete_output.stdout = OutputArtifact {
            result_id: fixture.bundle.cases[1].case_id.clone(),
            stream: OutputStream::Stdout,
            relative_path: reused.relative_path,
            byte_count: reused.byte_count,
            sha256: reused.sha256,
            commitment_sha256: String::new(),
        };
        recommit_output(&mut fixture.bundle.cases[1].complete_output.stdout);
        fixture.publish();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("reused"));
    }

    #[test]
    fn crossed_output_result_or_stream_cannot_pass() {
        let mut crossed_result = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        crossed_result.bundle.cases[1].complete_output.stdout = crossed_result.bundle.cases[0]
            .complete_output
            .stdout
            .clone();
        crossed_result.publish();
        assert!(
            lint_gate1_evidence_candidate_structure(&crossed_result.root)
                .unwrap_err()
                .to_string()
                .contains("crossed")
        );

        let mut crossed_stream = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        let output = &mut crossed_stream.bundle.cases[0].complete_output;
        std::mem::swap(&mut output.stdout, &mut output.stderr);
        crossed_stream.publish();
        assert!(
            lint_gate1_evidence_candidate_structure(&crossed_stream.root)
                .unwrap_err()
                .to_string()
                .contains("different result or stream")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_complete_output_cannot_pass() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        let stdout = fixture.bundle.cases[0]
            .complete_output
            .stdout
            .relative_path
            .clone();
        let stderr = fixture.bundle.cases[0]
            .complete_output
            .stderr
            .relative_path
            .clone();
        fs::remove_file(fixture.root.join(&stdout)).unwrap();
        let stderr_name = Path::new(&stderr).file_name().unwrap();
        symlink(stderr_name, fixture.root.join(&stdout)).unwrap();
        fixture.publish();
        assert!(
            lint_gate1_evidence_candidate_structure(&fixture.root)
                .unwrap_err()
                .to_string()
                .contains("without following links")
        );
    }

    #[test]
    fn hardlinked_bundle_cannot_pass() {
        let fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        fixture.publish();
        fs::hard_link(
            fixture.root.join(BUNDLE_FILE_NAME),
            fixture.root.join("bundle-alias.json"),
        )
        .unwrap();
        assert!(
            lint_gate1_evidence_candidate_structure(&fixture.root)
                .unwrap_err()
                .to_string()
                .contains("aliases or hardlinks")
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_complete_output_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Macos15AppleSilicon);
        let original = fixture.bundle.cases[0].complete_output.stdout.clone();
        let alias = "outputs/hardlinked-alias.stdout";
        fs::hard_link(
            fixture.root.join(&original.relative_path),
            fixture.root.join(alias),
        )
        .unwrap();
        fixture.bundle.cases[1].complete_output.stdout = OutputArtifact {
            result_id: fixture.bundle.cases[1].case_id.clone(),
            stream: OutputStream::Stdout,
            relative_path: alias.into(),
            byte_count: original.byte_count,
            sha256: original.sha256,
            commitment_sha256: String::new(),
        };
        recommit_output(&mut fixture.bundle.cases[1].complete_output.stdout);
        fixture.publish();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("aliases or hardlinks"));
    }

    #[test]
    fn traversal_artifact_path_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        fixture.bundle.cases[0].complete_output.stdout.relative_path = "../outside.log".into();
        recommit_output(&mut fixture.bundle.cases[0].complete_output.stdout);
        fixture.publish();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("normal relative path"));
    }

    #[test]
    fn stale_output_commitment_cannot_pass() {
        let mut fixture = Fixture::new(Gate1Platform::Ubuntu2604X8664);
        fixture.bundle.cases[0].complete_output.stdout.byte_count += 1;
        fixture.publish();
        let error = lint_gate1_evidence_candidate_structure(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("stale or crossed commitment"));
    }

    #[test]
    fn rollback_or_restart_mismatch_cannot_pass() {
        let mut rollback_fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        rollback_fixture
            .bundle
            .workflow
            .post_rollback_snapshot_digest = digest(88);
        rollback_fixture.publish();
        assert!(
            lint_gate1_evidence_candidate_structure(&rollback_fixture.root)
                .unwrap_err()
                .to_string()
                .contains("rollback")
        );

        let mut restart_fixture = Fixture::new(Gate1Platform::Fedora44X8664);
        restart_fixture
            .bundle
            .workflow
            .restart_receipts_digest_after = digest(87);
        restart_fixture.publish();
        assert!(
            lint_gate1_evidence_candidate_structure(&restart_fixture.root)
                .unwrap_err()
                .to_string()
                .contains("restart")
        );
    }

    #[test]
    fn diagnostic_is_explicitly_non_passing_and_atomic() {
        let fixture = EmptyDirectory::new("diagnostic");
        let path = write_not_completed_diagnostic(&fixture.root).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(
            value["schema_version"].as_u64(),
            Some(u64::from(GATE_1_EVIDENCE_SCHEMA_VERSION))
        );
        assert_eq!(value["fixture_id"].as_str(), Some(GATE_1_FIXTURE_ID));
        assert_eq!(
            value["release_target_manifest_version"].as_u64(),
            Some(u64::from(RELEASE_TARGET_MANIFEST_VERSION))
        );
        assert_eq!(value["status"], "not_completed");
        assert!(value.get("cases").is_none());
        assert_eq!(value["complete_output"]["stdout"]["stream"], "stdout");
        assert_eq!(value["complete_output"]["stderr"]["stream"], "stderr");
        assert_eq!(
            value["source_admission"]["status"],
            if value["source_admission"]["evidence"].is_object() {
                "admitted"
            } else {
                "rejected"
            }
        );
        let entries: BTreeSet<_> = fs::read_dir(&fixture.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            BTreeSet::from([
                std::ffi::OsString::from(DIAGNOSTIC_FILE_NAME),
                std::ffi::OsString::from("outputs"),
            ])
        );
        for artifact in [
            &value["complete_output"]["stdout"],
            &value["complete_output"]["stderr"],
        ] {
            let relative = artifact["relative_path"].as_str().unwrap();
            let bytes = fs::read(fixture.root.join(relative)).unwrap();
            assert_eq!(artifact["byte_count"].as_u64(), Some(bytes.len() as u64));
            assert_eq!(
                artifact["sha256"].as_str(),
                Some(lowercase_hex(&Sha256::digest(bytes)).as_str())
            );
        }
    }

    #[test]
    fn diagnostic_rejects_a_stale_evidence_bundle() {
        let fixture = EmptyDirectory::new("stale-bundle");
        fs::write(fixture.root.join(BUNDLE_FILE_NAME), b"stale candidate").unwrap();

        let error = write_not_completed_diagnostic(&fixture.root).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("existing Gate 1 evidence bundle")
        );
        assert!(!fixture.root.join(DIAGNOSTIC_FILE_NAME).exists());
    }

    #[test]
    fn diagnostic_rejects_every_unexpected_existing_entry() {
        let fixture = EmptyDirectory::new("unexpected-entry");
        fs::create_dir(fixture.root.join("outputs")).unwrap();

        let error = write_not_completed_diagnostic(&fixture.root).unwrap_err();
        assert!(error.to_string().contains("unexpected entry"));
        assert!(!fixture.root.join(DIAGNOSTIC_FILE_NAME).exists());
    }
