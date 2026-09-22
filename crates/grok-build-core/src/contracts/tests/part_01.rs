    use super::*;

    fn digest(character: char) -> Digest {
        Digest::parse(character.to_string().repeat(64)).expect("valid digest")
    }

    fn verification_receipt(
        exit_status: Option<i32>,
        termination: Option<CommandTerminationV1>,
    ) -> VerificationReceipt {
        VerificationReceipt {
            receipt_id: "verification-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            snapshot_id: digest('a'),
            command: CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            },
            policy_hash: digest('b'),
            exit_status,
            termination,
            output_digest: digest('c'),
            duration_ms: 5,
            finished_at_unix_ms: 10,
        }
    }

    fn current_verification_effect_evidence() -> VerificationEffectEvidence {
        let mut verification =
            verification_receipt(Some(0), Some(CommandTerminationV1::Exited { code: 0 }));
        let stdout = b"complete stdout";
        let command_bytes = serde_json::to_vec(&verification.command).expect("encode command");
        let output_artifacts = CommandOutputArtifactSetReferenceV1::try_new(
            CommandOutputArtifactSourceV1 {
                sprint_id: verification.sprint_id.clone(),
                runner_launch_id: "launch-1".into(),
                runner_session_id: "session-1".into(),
                effect_id: "effect-1".into(),
                request_digest: Digest::sha256(&command_bytes),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stdout,
                byte_length: u64::try_from(stdout.len()).expect("test output length fits u64"),
                content_digest: Digest::sha256(stdout),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stderr,
                byte_length: 0,
                content_digest: Digest::sha256(&[]),
            },
        )
        .expect("construct artifact reference");
        let output_evidence_bytes = output_artifacts
            .output_evidence_bytes()
            .expect("construct output commitment");
        verification.output_digest = Digest::sha256(&output_evidence_bytes);
        VerificationEffectEvidence {
            contract_version: CONTRACT_VERSION,
            verification,
            effect_id: "effect-1".into(),
            observation_id: "observation-1".into(),
            runner_launch_id: "launch-1".into(),
            runner_session_id: "session-1".into(),
            output_artifacts: Some(output_artifacts),
            output_evidence_bytes,
        }
    }

    fn grant() -> WorkspaceGrant {
        WorkspaceGrant {
            grant_id: "grant-1".into(),
            canonical_root: PathBuf::from("/work/project"),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: digest('a'),
        }
    }

    fn sprint() -> SprintSpec {
        SprintSpec {
            sprint_id: "sprint-1".into(),
            objective: "Implement the requested feature".into(),
            acceptance_criteria: vec![AcceptanceCriterion {
                criterion_id: "tests-pass".into(),
                description: "Focused tests pass".into(),
                kind: AcceptanceKind::Automated(CommandSpec {
                    program: "cargo".into(),
                    arguments: vec!["test".into()],
                    working_directory: PathBuf::new(),
                }),
            }],
            provider: ProviderProfile {
                backend_id: "fake".into(),
                model_id: "deterministic-v1".into(),
                execution_origin: ExecutionOrigin::HostIsolated,
            },
            budget: SprintBudget {
                max_tasks: 8,
                max_attempts_per_task: 3,
                max_tool_calls: 100,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: grant(),
            base_snapshot: digest('b'),
        }
    }

    fn task(task_id: &str, dependencies: &[&str]) -> TaskSpec {
        TaskSpec {
            task_id: task_id.into(),
            goal: format!("Complete {task_id}"),
            dependencies: dependencies.iter().map(ToString::to_string).collect(),
            path_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
            acceptance_checks: vec!["tests-pass".into()],
            base_snapshot: digest('b'),
            required: true,
        }
    }

    #[test]
    fn digest_requires_canonical_sha256_text() {
        assert!(Digest::parse("a".repeat(64)).is_ok());
        assert!(Digest::parse("A".repeat(64)).is_err());
        assert!(Digest::parse("g".repeat(64)).is_err());
        assert!(Digest::parse("a".repeat(63)).is_err());
        assert_eq!(
            Digest::sha256(b"abc").as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn direct_exec_command(
        program: impl Into<String>,
        arguments: Vec<String>,
        working_directory: impl Into<PathBuf>,
    ) -> CommandSpec {
        CommandSpec {
            program: program.into(),
            arguments,
            working_directory: working_directory.into(),
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the current direct-exec boundary test enumerates every admitted bound and rejected shape"
    )]
    fn current_direct_exec_v1_accepts_only_its_exact_closed_command_shape() {
        for command in [
            direct_exec_command("cargo", vec!["test".into()], PathBuf::new()),
            direct_exec_command("/usr/bin/true", Vec::new(), "src"),
            direct_exec_command(
                "x".repeat(CURRENT_DIRECT_EXEC_MAX_TEXT_BYTES_V1),
                vec!["y".repeat(CURRENT_DIRECT_EXEC_MAX_TEXT_BYTES_V1)],
                "z".repeat(CURRENT_DIRECT_EXEC_MAX_PATH_BYTES_V1),
            ),
            direct_exec_command(
                "true",
                vec!["x".into(); CURRENT_DIRECT_EXEC_MAX_ARGUMENTS_V1],
                PathBuf::new(),
            ),
        ] {
            validate_current_direct_exec_command_v1(&command)
                .expect("exact boundary command is representable");
        }

        let rejected = [
            (
                direct_exec_command("", Vec::new(), PathBuf::new()),
                "command program or argument count is outside bounds",
            ),
            (
                direct_exec_command(
                    "x".repeat(CURRENT_DIRECT_EXEC_MAX_TEXT_BYTES_V1 + 1),
                    Vec::new(),
                    PathBuf::new(),
                ),
                "command program or argument count is outside bounds",
            ),
            (
                direct_exec_command(
                    "true",
                    vec!["x".into(); CURRENT_DIRECT_EXEC_MAX_ARGUMENTS_V1 + 1],
                    PathBuf::new(),
                ),
                "command program or argument count is outside bounds",
            ),
            (
                direct_exec_command("/usr/bin/BaSh", Vec::new(), PathBuf::new()),
                "shell and command-wrapper programs are forbidden",
            ),
            (
                direct_exec_command("nu", Vec::new(), PathBuf::new()),
                "shell and command-wrapper programs are forbidden",
            ),
            (
                direct_exec_command("/usr/bin/xonsh", Vec::new(), PathBuf::new()),
                "shell and command-wrapper programs are forbidden",
            ),
            (
                direct_exec_command("./cargo", Vec::new(), PathBuf::new()),
                "program must be an absolute path or a bare executable name",
            ),
            (
                direct_exec_command("bin/tool", Vec::new(), PathBuf::new()),
                "program must be an absolute path or a bare executable name",
            ),
            (
                direct_exec_command("../tool", Vec::new(), PathBuf::new()),
                "program must be an absolute path or a bare executable name",
            ),
            (
                direct_exec_command(
                    "true",
                    vec!["x".repeat(CURRENT_DIRECT_EXEC_MAX_TEXT_BYTES_V1 + 1)],
                    PathBuf::new(),
                ),
                "command argument is outside the text bound",
            ),
            (
                direct_exec_command(
                    "true",
                    Vec::new(),
                    "x".repeat(CURRENT_DIRECT_EXEC_MAX_PATH_BYTES_V1 + 1),
                ),
                "working directory is oversized or contains NUL",
            ),
            (
                direct_exec_command("true", Vec::new(), "/workspace"),
                "path must be normalized and workspace-relative",
            ),
            (
                direct_exec_command("true", Vec::new(), "src/../tests"),
                "path contains a non-normal component",
            ),
            (
                direct_exec_command("true", Vec::new(), "src/.GiT/objects"),
                "protected .git paths are forbidden case-insensitively",
            ),
            (
                direct_exec_command("true\0crossed", Vec::new(), PathBuf::new()),
                "command program or argument count is outside bounds",
            ),
            (
                direct_exec_command("true", vec!["crossed\0argument".into()], PathBuf::new()),
                "command argument is outside the text bound",
            ),
        ];
        for (command, expected_message) in rejected {
            assert_eq!(
                validate_current_direct_exec_command_v1(&command)
                    .expect_err("closed direct-exec shape rejects this command")
                    .message(),
                expected_message
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn current_direct_exec_v1_rejects_non_utf8_working_directories() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let command = direct_exec_command(
            "true",
            Vec::new(),
            PathBuf::from(OsString::from_vec(vec![b's', b'r', b'c', 0xff])),
        );
        assert_eq!(
            validate_current_direct_exec_command_v1(&command)
                .expect_err("wire V13 cannot represent non-UTF-8 paths")
                .message(),
            "working directory is not UTF-8"
        );
    }

    #[test]
    fn command_termination_v1_is_canonical_and_only_exit_zero_passes() {
        let cases = [
            (CommandTerminationV1::Exited { code: 0 }, Some(0), true),
            (CommandTerminationV1::Exited { code: 7 }, Some(7), false),
            (CommandTerminationV1::Signaled { signal: 9 }, None, false),
            (CommandTerminationV1::TimedOut, None, false),
            (CommandTerminationV1::Canceled, None, false),
            (CommandTerminationV1::OutputLimitExceeded, None, false),
        ];
        for (termination, exit_status, passed) in cases {
            let receipt = verification_receipt(exit_status, Some(termination));
            assert_eq!(receipt.validate_current(), Ok(()));
            assert_eq!(receipt.passed(), passed);
            assert_eq!(termination.passed(), passed);
            assert_eq!(termination.exit_status(), exit_status);
        }

        assert_eq!(
            serde_json::to_vec(&CommandTerminationV1::Exited { code: 7 })
                .expect("encode canonical typed exit"),
            br#"{"kind":"exited","code":7}"#
        );
        assert_eq!(
            serde_json::to_vec(&CommandTerminationV1::OutputLimitExceeded)
                .expect("encode canonical typed output limit"),
            br#"{"kind":"output_limit_exceeded"}"#
        );
        assert!(
            serde_json::from_slice::<CommandTerminationV1>(
                br#"{"kind":"exited","code":0,"unknown":true}"#
            )
            .is_err()
        );
        assert!(
            CommandTerminationV1::Exited { code: -1 }
                .validate()
                .is_err()
        );
        assert!(
            CommandTerminationV1::Signaled { signal: 0 }
                .validate()
                .is_err()
        );
    }

    #[test]
    fn command_output_artifact_reference_is_canonical_strict_and_empty_stream_safe() {
        let evidence = current_verification_effect_evidence();
        let reference = evidence
            .output_artifacts
            .as_ref()
            .expect("current evidence has artifacts");
        assert_eq!(reference.validate(), Ok(()));
        assert_eq!(evidence.validate_current(), Ok(()));
        assert_eq!(
            reference.manifest_digest.as_str(),
            "4e63eb609588a279885ca57c5ad94b62f231daa6a99394b4d766936df0910192"
        );
        assert_eq!(reference.stderr.byte_length, 0);
        assert_eq!(reference.stderr.content_digest, Digest::sha256(&[]));

        let encoded = serde_json::to_vec(reference).expect("encode artifact reference");
        let decoded: CommandOutputArtifactSetReferenceV1 =
            serde_json::from_slice(&encoded).expect("decode artifact reference");
        assert_eq!(decoded, *reference);
        assert_eq!(serde_json::to_vec(&decoded).expect("re-encode"), encoded);

        let mut crossed = reference.clone();
        crossed.stdout.stream = CommandOutputStreamV1::Stderr;
        assert_eq!(
            crossed
                .validate()
                .expect_err("crossed stream role must fail")
                .field(),
            "command_output_artifact_set_reference_v1.stdout.stream"
        );
        assert!(
            serde_json::from_slice::<CommandOutputArtifactSetReferenceV1>(
                br#"{"format_version":1,"source":{"sprint_id":"s","runner_launch_id":"l","runner_session_id":"r","effect_id":"e","request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unknown":true},"stdout":{"stream":"stdout","byte_length":0,"content_digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"stderr":{"stream":"stderr","byte_length":0,"content_digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},"manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn present_output_artifacts_fail_historical_validation_when_crossed() {
        let mut evidence = current_verification_effect_evidence();
        assert_eq!(evidence.validate(), Ok(()));
        let mut source = evidence
            .output_artifacts
            .as_ref()
            .expect("current artifacts")
            .source
            .clone();
        source.effect_id = "effect-crossed".into();
        let prior = evidence
            .output_artifacts
            .as_ref()
            .expect("current artifacts");
        evidence.output_artifacts = Some(
            CommandOutputArtifactSetReferenceV1::try_new(
                source,
                prior.stdout.clone(),
                prior.stderr.clone(),
            )
            .expect("standalone crossed reference remains canonical"),
        );
        assert_eq!(
            evidence
                .validate()
                .expect_err("present crossed artifacts must fail every read path")
                .field(),
            "verification_effect_evidence.output_artifacts.source.effect_id"
        );
    }

    #[test]
    fn historical_verification_effect_evidence_round_trips_without_artifacts() {
        const HISTORICAL: &[u8] = br#"{"contract_version":1,"verification":{"receipt_id":"verification-1","sprint_id":"sprint-1","task_id":null,"snapshot_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"program":"cargo","arguments":["test"],"working_directory":""},"policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","exit_status":0,"termination":{"kind":"exited","code":0},"output_digest":"4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a","duration_ms":5,"finished_at_unix_ms":10},"effect_id":"effect-1","observation_id":"observation-1","runner_launch_id":"launch-1","runner_session_id":"session-1","output_evidence_bytes":[1]}"#;

        let evidence: VerificationEffectEvidence =
            serde_json::from_slice(HISTORICAL).expect("decode historical effect evidence");
        assert_eq!(evidence.output_artifacts, None);
        assert_eq!(evidence.validate(), Ok(()));
        assert_eq!(
            evidence
                .validate_current()
                .expect_err("historical evidence cannot mint current authority")
                .field(),
            "verification_effect_evidence.output_artifacts"
        );
        assert_eq!(
            serde_json::to_vec(&evidence).expect("re-encode historical effect evidence"),
            HISTORICAL
        );
    }

    #[test]
    fn verification_termination_rejects_missing_crossed_and_synthetic_exit_shapes() {
        let missing = verification_receipt(None, None);
        assert!(!missing.passed());
        assert_eq!(
            missing
                .validate()
                .expect_err("missing terminal must fail")
                .field(),
            "verification_receipt.termination"
        );

        let missing_exit =
            verification_receipt(None, Some(CommandTerminationV1::Exited { code: 0 }));
        assert!(!missing_exit.passed());
        assert_eq!(
            missing_exit
                .validate()
                .expect_err("typed exit requires compatibility code")
                .field(),
            "verification_receipt.exit_status"
        );

        let crossed_exit =
            verification_receipt(Some(7), Some(CommandTerminationV1::Exited { code: 0 }));
        assert!(!crossed_exit.passed());
        assert_eq!(
            crossed_exit
                .validate()
                .expect_err("crossed typed and legacy exits must fail")
                .field(),
            "verification_receipt.exit_status"
        );

        for termination in [
            CommandTerminationV1::Signaled { signal: 9 },
            CommandTerminationV1::TimedOut,
            CommandTerminationV1::Canceled,
            CommandTerminationV1::OutputLimitExceeded,
        ] {
            let synthetic_exit = verification_receipt(Some(1), Some(termination));
            assert_eq!(
                synthetic_exit
                    .validate()
                    .expect_err("non-exit terminal cannot carry synthetic status")
                    .field(),
                "verification_receipt.exit_status"
            );
            assert!(!synthetic_exit.passed());
        }
    }

    #[test]
    fn historical_verification_receipt_round_trips_exact_bytes_but_is_not_current() {
        const HISTORICAL: &[u8] = br#"{"receipt_id":"verification-1","sprint_id":"sprint-1","task_id":null,"snapshot_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"program":"cargo","arguments":["test"],"working_directory":""},"policy_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","exit_status":0,"output_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","duration_ms":5,"finished_at_unix_ms":10}"#;

        let receipt: VerificationReceipt =
            serde_json::from_slice(HISTORICAL).expect("decode historical receipt");
        assert_eq!(receipt, verification_receipt(Some(0), None));
        assert_eq!(receipt.validate(), Ok(()));
        assert!(receipt.passed());
        assert_eq!(
            receipt
                .validate_current()
                .expect_err("historical receipt cannot be minted now")
                .field(),
            "verification_receipt.termination"
        );
        assert_eq!(
            serde_json::to_vec(&receipt).expect("re-encode historical receipt"),
            HISTORICAL
        );
    }

    #[test]
    fn workspace_grant_rejects_permission_escalation_shapes() {
        let mut invalid = grant();
        invalid.permissions.write_regular_files = false;
        assert_eq!(
            invalid
                .validate()
                .expect_err("integration must need writes")
                .field(),
            "workspace_grant.permissions.integrate_changes"
        );

        let mut relative = grant();
        relative.canonical_root = PathBuf::from("relative/project");
        assert_eq!(
            relative
                .validate()
                .expect_err("root must be absolute")
                .field(),
            "workspace_grant.canonical_root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authority_paths_reject_non_utf8_identities() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut invalid_grant = grant();
        invalid_grant.canonical_root =
            PathBuf::from(OsString::from_vec(b"/work/project-\xff".to_vec()));
        assert_eq!(
            invalid_grant
                .validate()
                .expect_err("a grant root must cross the wire without loss")
                .field(),
            "workspace_grant.canonical_root"
        );

        let invalid_change = ChangeSet {
            change_set_id: "changes-non-utf8".into(),
            base_snapshot: digest('b'),
            result_snapshot: digest('c'),
            operations: vec![FileOperation::Delete {
                path: PathBuf::from(OsString::from_vec(b"src/file-\xff".to_vec())),
                base_hash: digest('d'),
            }],
        };
        assert_eq!(
            invalid_change
                .validate()
                .expect_err("a change path must cross the wire without loss")
                .field(),
            "change_set.operation.path"
        );
    }

    #[test]
    fn sprint_rejects_duplicate_criteria_and_invalid_worker_count() {
        let mut duplicate = sprint();
        duplicate
            .acceptance_criteria
            .push(duplicate.acceptance_criteria[0].clone());
        assert!(duplicate.validate().is_err());

        let mut too_many_workers = sprint();
        too_many_workers.max_workers = 4;
        assert_eq!(
            too_many_workers
                .validate()
                .expect_err("three is the ceiling")
                .field(),
            "sprint.max_workers"
        );
    }

    #[test]
    fn task_graph_accepts_a_valid_dag() {
        let graph = TaskGraph {
            graph_id: "graph-1".into(),
            tasks: vec![task("first", &[]), task("second", &["first"])],
        };
        assert_eq!(graph.validate_for_sprint(&sprint()), Ok(()));
        assert_eq!(
            graph.task("second").map(|task| task.goal.as_str()),
            Some("Complete second")
        );
    }

    #[test]
    fn task_graph_rejects_cycles_unknown_edges_and_uncovered_criteria() {
        let cyclic = TaskGraph {
            graph_id: "graph".into(),
            tasks: vec![task("one", &["two"]), task("two", &["one"])],
        };
        assert!(cyclic.validate_for_sprint(&sprint()).is_err());

        let unknown = TaskGraph {
            graph_id: "graph".into(),
            tasks: vec![task("one", &["missing"])],
        };
        assert!(unknown.validate_for_sprint(&sprint()).is_err());

        let mut unrelated = task("one", &[]);
        unrelated.acceptance_checks = vec!["not-a-criterion".into()];
        let graph = TaskGraph {
            graph_id: "graph".into(),
            tasks: vec![unrelated],
        };
        assert!(graph.validate_for_sprint(&sprint()).is_err());
    }

    #[test]
    fn task_graph_rejects_a_task_planned_from_another_snapshot() {
        let sprint = sprint();
        let mut stale_task = task("one", &[]);
        stale_task.base_snapshot = digest('c');
        let graph = TaskGraph {
            graph_id: "graph".into(),
            tasks: vec![stale_task],
        };

        assert_eq!(
            graph
                .validate_for_sprint(&sprint)
                .expect_err("stale task base must fail")
                .field(),
            "task.base_snapshot"
        );
    }

    #[test]
    fn planning_provider_response_is_strict_versioned_and_sprint_bound() {
        let sprint = sprint();
        let graph = TaskGraph {
            graph_id: "graph".into(),
            tasks: vec![task("one", &[])],
        };
        let mut response = ProviderResponse {
            contract_version: CONTRACT_VERSION,
            sprint_id: sprint.sprint_id.clone(),
            result: ProviderResponseResult::PlanningComplete { task_graph: graph },
        };
        assert_eq!(response.validate_for_sprint(&sprint), Ok(()));

        let mut value = serde_json::to_value(&response).expect("encode response");
        value
            .as_object_mut()
            .expect("response object")
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<ProviderResponse>(value).is_err());

        response.sprint_id = "another-sprint".into();
        assert_eq!(
            response
                .validate_for_sprint(&sprint)
                .expect_err("cross-sprint response must fail")
                .field(),
            "provider_response.sprint_id"
        );
    }

    #[test]
    fn terminal_evidence_is_typed_strict_and_utf8_byte_bounded() {
        for state in [
            NonSuccessTerminalState::Blocked,
            NonSuccessTerminalState::Failed,
            NonSuccessTerminalState::Canceled,
            NonSuccessTerminalState::Unknown,
        ] {
            let evidence = SprintTerminalEvidence {
                contract_version: CONTRACT_VERSION,
                record_id: format!("terminal-{state:?}"),
                sprint_id: "sprint-1".into(),
                state,
                reason: "Exact bounded reason".into(),
                terminal_at_unix_ms: 2_000,
            };
            assert_eq!(evidence.validate(), Ok(()));
        }

        let mut invalid = SprintTerminalEvidence {
            contract_version: CONTRACT_VERSION,
            record_id: "terminal-1".into(),
            sprint_id: "sprint-1".into(),
            state: NonSuccessTerminalState::Failed,
            reason: " ".into(),
            terminal_at_unix_ms: 2_000,
        };
        assert_eq!(
            invalid
                .validate()
                .expect_err("blank reason must fail")
                .field(),
            "sprint_terminal_evidence.reason"
        );
        invalid.reason = "é".repeat((MAX_TERMINAL_REASON_BYTES / 2) + 1);
        assert!(
            invalid.validate().is_err(),
            "bound is measured in UTF-8 bytes"
        );

        invalid.reason = "valid".into();
        let mut encoded = serde_json::to_value(&invalid).expect("encode evidence");
        encoded
            .as_object_mut()
            .expect("evidence object")
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SprintTerminalEvidence>(encoded).is_err());
    }

    #[test]
    fn task_and_change_paths_reject_escape_components() {
        let mut escaping_task = task("one", &[]);
        escaping_task.path_scopes = vec![PathScope::Relative(PathBuf::from("../outside"))];
        assert!(escaping_task.validate().is_err());

        let changes = ChangeSet {
            change_set_id: "changes-1".into(),
            base_snapshot: digest('b'),
            result_snapshot: digest('c'),
            operations: vec![FileOperation::Delete {
                path: PathBuf::from("../secret"),
                base_hash: digest('d'),
            }],
        };
        assert!(changes.validate().is_err());
    }

    #[test]
    fn change_set_rejects_duplicate_targets_and_no_op_modifications() {
        let duplicate = ChangeSet {
            change_set_id: "changes-1".into(),
            base_snapshot: digest('b'),
            result_snapshot: digest('c'),
            operations: vec![
                FileOperation::Create {
                    path: PathBuf::from("src/new.rs"),
                    result_hash: digest('d'),
                },
                FileOperation::Delete {
                    path: PathBuf::from("src/new.rs"),
                    base_hash: digest('e'),
                },
            ],
        };
        assert!(duplicate.validate().is_err());

        let no_op = ChangeSet {
            change_set_id: "changes-2".into(),
            base_snapshot: digest('b'),
            result_snapshot: digest('c'),
            operations: vec![FileOperation::Modify {
                path: PathBuf::from("src/lib.rs"),
                base_hash: digest('d'),
                result_hash: digest('d'),
            }],
        };
        assert!(no_op.validate().is_err());
    }

    #[test]
    fn explicit_empty_change_set_is_the_only_task_verified_no_op_shape() {
        let snapshot = digest('b');
        let verified_no_op = ChangeSet {
            change_set_id: "changes-empty".into(),
            base_snapshot: snapshot.clone(),
            result_snapshot: snapshot.clone(),
            operations: Vec::new(),
        };
        assert_eq!(verified_no_op.validate(), Ok(()));

        let mut empty_but_progressing = verified_no_op.clone();
        empty_but_progressing.result_snapshot = digest('c');
        assert_eq!(
            empty_but_progressing
                .validate()
                .expect_err("empty operations cannot claim snapshot progress")
                .field(),
            "change_set.operations"
        );

        let mut changed_but_equal = verified_no_op.clone();
        changed_but_equal.operations.push(FileOperation::Create {
            path: PathBuf::from("invented.txt"),
            result_hash: digest('d'),
        });
        assert_eq!(
            changed_but_equal
                .validate()
                .expect_err("nonempty operations cannot claim an unchanged snapshot")
                .field(),
            "change_set.operations"
        );

        let artifact = TaskIntegrationArtifactReference {
            format_version: 1,
            artifact_digest: digest('e'),
            change_set_id: verified_no_op.change_set_id.clone(),
            base_snapshot: snapshot.clone(),
            result_snapshot: snapshot,
        };
        assert_eq!(
            TaskIntegrationRequest {
                contract_version: CONTRACT_VERSION,
                change_set: verified_no_op.clone(),
                artifact: artifact.clone(),
            }
            .validate(),
            Ok(())
        );
        assert_eq!(
            ApplicationRequest {
                contract_version: CONTRACT_VERSION,
                change_set: verified_no_op,
                artifact,
            }
            .validate()
            .expect_err("empty task result cannot authorize a live application")
            .field(),
            "application_request.change_set"
        );
    }

    #[test]
    fn execution_policy_cannot_widen_grant() {
        let policy = ExecutionPolicy {
            policy_id: "policy-1".into(),
            grant_hash: digest('a'),
            workspace_root: PathBuf::from("/work/project"),
            read_scopes: vec![PathScope::Workspace],
            write_scopes: Vec::new(),
            environment: vec![EnvironmentVariable {
                name: "PATH".into(),
                value: "/usr/bin".into(),
            }],
            network: ExecutionNetwork::None,
            mutation_mode: MutationMode::ReadOnly,
            resource_limits: ResourceLimits {
                wall_time_ms: 10_000,
                max_output_bytes: 1_000_000,
                max_processes: 8,
                max_memory_bytes: Some(512_000_000),
            },
            approval_id: None,
            policy_hash: digest('f'),
        };
        assert_eq!(policy.validate_against(&grant()), Ok(()));

        let mut networked = policy.clone();
        networked.network = ExecutionNetwork::FullForAction;
        assert_eq!(
            networked
                .validate_against(&grant())
                .expect_err("network must not widen")
                .field(),
            "execution_policy.network"
        );

        let mut writable_read_only = policy;
        writable_read_only.write_scopes = vec![PathScope::Workspace];
        assert!(writable_read_only.validate_against(&grant()).is_err());
    }

    #[test]
    fn agent_event_enforces_version_sequence_and_causation() {
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: 1,
            event_id: "event-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "correlation-1".into(),
            policy_hash: None,
            occurred_at_unix_ms: 1,
            payload: AgentEventKind::Diagnostic("started".into()),
        };
        assert_eq!(event.validate(), Ok(()));

        let mut invalid_version = event.clone();
        invalid_version.contract_version += 1;
        assert!(invalid_version.validate().is_err());

        let mut self_caused = event;
        self_caused.causation_id = Some(self_caused.event_id.clone());
        assert!(self_caused.validate().is_err());
    }

    #[test]
    fn effect_observation_is_bound_to_exact_intent_identity() {
        let worker_lease = WorkerLease::new(
            "sprint-1".into(),
            1,
            "task-1".into(),
            "worker-1".into(),
            vec![PathScope::Workspace],
            99,
        )
        .expect("canonical worker lease");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "effect-1".into(),
            idempotency_key: "key-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            worker_id: Some("worker-1".into()),
            worker_lease: Some(worker_lease.clone()),
            causation_event_id: Some("event-before".into()),
            correlation_id: "correlation-1".into(),
            kind: EffectKind::RunCommand,
            request_digest: digest('1'),
            policy_hash: digest('2'),
            input_snapshot: digest('3'),
            created_at_unix_ms: 100,
        };
        assert_eq!(intent.validate(), Ok(()));

        let mut observation = EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id: "observation-1".into(),
            effect_id: intent.effect_id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            worker_lease: intent.worker_lease.clone(),
            correlation_id: intent.correlation_id.clone(),
            kind: intent.kind,
            request_digest: intent.request_digest.clone(),
            policy_hash: intent.policy_hash.clone(),
            input_snapshot: intent.input_snapshot.clone(),
            outcome: EffectOutcome::Unknown {
                evidence_digest: digest('4'),
            },
            observed_at_unix_ms: 101,
        };
        assert_eq!(observation.validate_against(&intent), Ok(()));

        observation.policy_hash = digest('5');
        assert_eq!(
            observation
                .validate_against(&intent)
                .expect_err("cross-policy observation must fail")
                .field(),
            "effect_observation.intent_identity"
        );
        observation.policy_hash = intent.policy_hash.clone();
        observation.observed_at_unix_ms = 99;
        assert_eq!(
            observation
                .validate_against(&intent)
                .expect_err("observation cannot predate intent")
                .field(),
            "effect_observation.observed_at_unix_ms"
        );

        let mut one_sided_scope = intent;
        one_sided_scope.worker_id = None;
        assert_eq!(
            one_sided_scope
                .validate()
                .expect_err("task and worker scope must be paired")
                .field(),
            "effect_intent.scope"
        );
    }

    #[test]
    fn effect_kinds_have_unique_stable_registered_tool_names() {
        let kinds = [
            EffectKind::ProviderRequest,
            EffectKind::ReadRelativeFile,
            EffectKind::SearchLiteral,
            EffectKind::RunCommand,
            EffectKind::CreateRegularFile,
            EffectKind::ReplaceRegularFile,
            EffectKind::DeleteRegularFile,
            EffectKind::IntegrateChangeSet,
            EffectKind::ApplyChangeSet,
        ];
        let names: BTreeSet<&str> = kinds.iter().map(|kind| (*kind).tool_name()).collect();
        assert_eq!(names.len(), kinds.len());
    }

    #[test]
    fn mutation_artifact_link_is_strict_versioned_and_snapshot_bound() {
        let link = MutationArtifactLink {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            effect_id: "effect-1".into(),
            observation_id: "observation-1".into(),
            input_snapshot: digest('a'),
            result_snapshot: digest('b'),
            change_set_id: "change-1".into(),
        };
        assert_eq!(link.validate(), Ok(()));

        let mut unsupported = link.clone();
        unsupported.contract_version += 1;
        assert_eq!(
            unsupported
                .validate()
                .expect_err("future contract must fail")
                .field(),
            "mutation_artifact_link.contract_version"
        );
        let mut no_progress = link.clone();
        no_progress.result_snapshot = no_progress.input_snapshot.clone();
        assert_eq!(
            no_progress
                .validate()
                .expect_err("mutation must change its input snapshot")
                .field(),
            "mutation_artifact_link.result_snapshot"
        );
        let mut blank_identity = link;
        blank_identity.change_set_id = " ".into();
        assert!(blank_identity.validate().is_err());

        let unknown_field = br#"{
            "contract_version":1,
            "sprint_id":"sprint-1",
            "effect_id":"effect-1",
            "observation_id":"observation-1",
            "input_snapshot":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "result_snapshot":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "change_set_id":"change-1",
            "invented":"authority"
        }"#;
        assert!(serde_json::from_slice::<MutationArtifactLink>(unknown_field).is_err());
    }

    #[test]
    fn application_request_is_strict_bounded_and_artifact_authenticated() {
        let change_set = ChangeSet {
            change_set_id: "change-application".into(),
            base_snapshot: digest('a'),
            result_snapshot: digest('b'),
            operations: vec![FileOperation::Create {
                path: PathBuf::from("result.txt"),
                result_hash: digest('c'),
            }],
        };
        let artifact = TaskIntegrationArtifactReference {
            format_version: 1,
            artifact_digest: digest('d'),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
        };
        let request = ApplicationRequest {
            contract_version: CONTRACT_VERSION,
            change_set,
            artifact,
        };
        assert_eq!(request.validate(), Ok(()));
        let canonical = serde_json::to_vec(&request).expect("encode application request");

        let mut substituted = request.clone();
        substituted.artifact.artifact_digest = digest('e');
        assert_eq!(substituted.validate(), Ok(()));
        assert_ne!(
            Digest::sha256(&canonical),
            Digest::sha256(&serde_json::to_vec(&substituted).expect("encode substituted artifact"))
        );

        let mut crossed = request.clone();
        crossed.artifact.result_snapshot = digest('f');
        assert_eq!(
            crossed
                .validate()
                .expect_err("crossed artifact relationship must fail")
                .field(),
            "application_request.artifact"
        );

        let mut unknown = serde_json::to_value(&request).expect("encode strict request");
        unknown.as_object_mut().expect("request object").insert(
            "artifact_path".into(),
            serde_json::json!("/private/substitute"),
        );
        assert!(serde_json::from_value::<ApplicationRequest>(unknown).is_err());

        let mut oversized = request;
        oversized.change_set.operations = vec![FileOperation::Create {
            path: PathBuf::from("x".repeat(MAX_APPLICATION_REQUEST_BYTES)),
            result_hash: digest('c'),
        }];
        assert_eq!(
            oversized
                .validate()
                .expect_err("oversized canonical request must fail")
                .field(),
            "application_request"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One strict envelope is mutated across every cross-link.
    fn task_integration_evidence_binds_the_exact_restart_artifact() {
        let worker_lease = WorkerLease::new(
            "sprint-1".into(),
            1,
            "task-1".into(),
            "worker-1".into(),
            vec![PathScope::Workspace],
            99,
        )
        .expect("canonical worker lease");
        let receipt = TaskIntegrationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "integration-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            worker_id: "worker-1".into(),
            worker_lease: Some(worker_lease),
            worker_launch_id: "launch-1".into(),
            worker_session_id: "session-1".into(),
            worker_policy_hash: digest('a'),
            effect_id: "effect-1".into(),
            observation_id: "observation-1".into(),
            change_set_id: "change-1".into(),
            input_snapshot: digest('b'),
            result_snapshot: digest('c'),
            task_verification_receipt_ids: vec!["verification-1".into()],
            integration_ordinal: 0,
            integrated_at_unix_ms: 100,
        };
        let artifact = TaskIntegrationArtifactReference {
            format_version: 1,
            artifact_digest: digest('d'),
            change_set_id: receipt.change_set_id.clone(),
            base_snapshot: receipt.input_snapshot.clone(),
            result_snapshot: receipt.result_snapshot.clone(),
        };
        let evidence = TaskIntegrationEvidence {
            contract_version: CONTRACT_VERSION,
            artifact,
            validation: TaskIntegrationValidationEvidence {
                mode: TaskIntegrationValidationMode::WorkerPublication,
                runner_launch_id: receipt.worker_launch_id.clone(),
                runner_session_id: receipt.worker_session_id.clone(),
                policy_hash: receipt.worker_policy_hash.clone(),
                grant_hash: digest('e'),
                private_state_digest: digest('f'),
            },
            receipt,
        };
        let request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: ChangeSet {
                change_set_id: evidence.receipt.change_set_id.clone(),
                base_snapshot: evidence.receipt.input_snapshot.clone(),
                result_snapshot: evidence.receipt.result_snapshot.clone(),
                operations: vec![FileOperation::Create {
                    path: PathBuf::from("result.txt"),
                    result_hash: digest('e'),
                }],
            },
            artifact: evidence.artifact.clone(),
        };
        assert_eq!(request.validate(), Ok(()));
        assert_eq!(evidence.validate(), Ok(()));

        let mut wrong_request = request;
        wrong_request.artifact.result_snapshot = digest('f');
        assert_eq!(
            wrong_request
                .validate()
                .expect_err("a different requested artifact must fail")
                .field(),
            "task_integration_request.artifact"
        );

        let mut wrong_change = evidence.clone();
        wrong_change.artifact.change_set_id = "change-2".into();
        assert_eq!(
            wrong_change
                .validate()
                .expect_err("a different artifact change set must fail")
                .field(),
            "task_integration_evidence.artifact"
        );

        let mut wrong_worker_session = evidence.clone();
        wrong_worker_session.validation.runner_session_id = "session-2".into();
        assert_eq!(
            wrong_worker_session
                .validate()
                .expect_err("worker publication must bind its exact session")
                .field(),
            "task_integration_evidence.validation"
        );

        let mut recovery = evidence.clone();
        recovery.validation.mode = TaskIntegrationValidationMode::RecoveryApplierReconciliation;
        recovery.validation.runner_launch_id = "launch-recovery".into();
        recovery.validation.runner_session_id = "session-recovery".into();
        recovery.validation.policy_hash = digest('9');
        assert_eq!(recovery.validate(), Ok(()));

        recovery.validation.runner_session_id = evidence.receipt.worker_session_id.clone();
        assert_eq!(
            recovery
                .validate()
                .expect_err("recovery cannot replay the worker session")
                .field(),
            "task_integration_evidence.validation"
        );

        let mut unversioned = evidence.clone();
        unversioned.artifact.format_version = 0;
        assert_eq!(
            unversioned
                .validate()
                .expect_err("an unversioned artifact must fail")
                .field(),
            "task_integration_artifact_reference.format_version"
        );

        let mut encoded = serde_json::to_value(evidence).expect("encode integration evidence");
        encoded.as_object_mut().expect("evidence object").insert(
            "filesystem_path".into(),
            serde_json::json!("/private/escape"),
        );
        assert!(serde_json::from_value::<TaskIntegrationEvidence>(encoded).is_err());
    }

    #[test]
    fn final_report_digest_covers_the_exact_utf8_body() {
        let body = "Completed with π-safe UTF-8.".to_owned();
        let mut report = FinalReport {
            report_id: "report-1".into(),
            sprint_id: "sprint-1".into(),
            final_snapshot: digest('c'),
            content_digest: FinalReport::digest_body(&body),
            body,
            created_at_unix_ms: 1,
        };
        assert_eq!(report.validate(), Ok(()));
        assert_eq!(report.content_digest.as_str().len(), 64);

        report.body.push('!');
        assert_eq!(
            report
                .validate()
                .expect_err("body mutation must invalidate its digest")
                .field(),
            "final_report.content_digest"
        );
    }

    fn test_attempt(ordinal: u32, epoch: u64) -> TaskAttempt {
        TaskAttempt::new(
            WorkerLease::new(
                "sprint-1".into(),
                epoch,
                "task-1".into(),
                format!("worker-{epoch}"),
                vec![PathScope::Relative(PathBuf::from("src"))],
                1_000 + epoch,
            )
            .expect("lease"),
            ordinal,
            format!("opening-{ordinal}"),
        )
        .expect("attempt")
    }

    fn test_attempt_evidence(kind: TaskAttemptEvidenceKind, identity: &str) -> TaskAttemptEvidence {
        TaskAttemptEvidence::new(identity.into(), kind, identity.as_bytes().to_vec())
            .expect("evidence")
    }

    fn no_launch_release(
        attempt: &TaskAttempt,
        evidence: TaskAttemptEvidence,
    ) -> WorkerLeaseNeverLaunchedRelease {
        WorkerLeaseNeverLaunchedRelease {
            contract_version: CONTRACT_VERSION,
            release_id: format!("release-{}", attempt.attempt_ordinal),
            attempt: attempt.clone(),
            absence_evidence: evidence,
            released_at_unix_ms: attempt.opened_at_unix_ms + 10,
        }
    }

    fn cleanup_release(attempt: &TaskAttempt) -> TaskAttemptCleanupRelease {
        let cleaned_at_unix_ms = attempt.opened_at_unix_ms + 20;
        TaskAttemptCleanupRelease {
            contract_version: CONTRACT_VERSION,
            release_id: format!("cleanup-release-{}", attempt.attempt_ordinal),
            attempt: attempt.clone(),
            cleanup_receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: format!("cleanup-receipt-{}", attempt.attempt_ordinal),
                sprint_id: attempt.worker_lease.sprint_id.clone(),
                launch_id: format!("launch-{}", attempt.attempt_ordinal),
                effect_id: format!("cleanup-effect-{}", attempt.attempt_ordinal),
                observation_id: format!("cleanup-observation-{}", attempt.attempt_ordinal),
                session_id: format!("session-{}", attempt.attempt_ordinal),
                worker_lease: Some(attempt.worker_lease.clone()),
                policy_hash: digest('1'),
                grant_hash: digest('2'),
                policy_version: 1,
                platform_backend: WorkerCleanupBackend::LinuxCgroupV2,
                os_evidence_digest: digest('3'),
                surviving_processes: 0,
                cleaned_at_unix_ms,
            },
            released_at_unix_ms: cleaned_at_unix_ms,
        }
    }

    fn test_running_boundary(attempt: &TaskAttempt) -> TaskAttemptRunningBoundary {
        TaskAttemptRunningBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "running-boundary-1".into(),
            attempt: attempt.clone(),
            runner_launch_id: "launch-1".into(),
            runner_session_id: "session-1".into(),
            transition_event_id: "to-running-1".into(),
            started_at_unix_ms: attempt.opened_at_unix_ms + 1,
        }
    }

    fn test_verification_boundary(attempt: &TaskAttempt) -> TaskAttemptVerificationBoundary {
        TaskAttemptVerificationBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "verification-boundary-1".into(),
            attempt: attempt.clone(),
            runner_launch_id: "launch-1".into(),
            runner_session_id: "session-1".into(),
            change_set_id: "changes-1".into(),
            sealed_snapshot: digest('4'),
            transition_event_id: "to-verifying-1".into(),
            terminal_non_cleanup_effects: Vec::new(),
            sealed_at_unix_ms: attempt.opened_at_unix_ms + 1,
        }
    }

    fn test_formal_check(
        attempt: &TaskAttempt,
        boundary: &TaskAttemptVerificationBoundary,
        passed: bool,
    ) -> TaskAttemptFormalCheck {
        let AcceptanceKind::Automated(command) = &sprint().acceptance_criteria[0].kind else {
            unreachable!();
        };
        TaskAttemptFormalCheck {
            contract_version: CONTRACT_VERSION,
            formal_check_id: "formal-check-1".into(),
            attempt: attempt.clone(),
            criterion_ordinal: 0,
            criterion_id: "tests-pass".into(),
            effect_id: "formal-effect-1".into(),
            observation_id: "formal-observation-1".into(),
            verification_receipt: VerificationReceipt {
                receipt_id: "verification-receipt-1".into(),
                sprint_id: "sprint-1".into(),
                task_id: Some("task-1".into()),
                snapshot_id: boundary.sealed_snapshot.clone(),
                command: command.clone(),
                policy_hash: digest('5'),
                exit_status: Some(i32::from(!passed)),
                termination: Some(CommandTerminationV1::Exited {
                    code: i32::from(!passed),
                }),
                output_digest: digest('6'),
                duration_ms: 1,
                finished_at_unix_ms: attempt.opened_at_unix_ms + 2,
            },
            runner_session_id: boundary.runner_session_id.clone(),
            sealed_snapshot: boundary.sealed_snapshot.clone(),
        }
    }

    fn disposition_metadata(attempt: &TaskAttempt) -> TaskAttemptDispositionMetadata {
        TaskAttemptDispositionMetadata {
            contract_version: CONTRACT_VERSION,
            disposition_id: format!("disposition-{}", attempt.attempt_ordinal),
            attempt: attempt.clone(),
            from_state: TaskState::Leased,
            state_transition_event_id: format!("disposition-event-{}", attempt.attempt_ordinal),
            disposed_at_unix_ms: attempt.opened_at_unix_ms + 30,
        }
    }

    fn legacy_entry(
        ordinal: u32,
        classification: LegacyTaskAttemptClassification,
        active: bool,
    ) -> TaskAttemptHistoryEntry {
        let attempt = test_attempt(ordinal, u64::from(ordinal));
        let lease_state = if active {
            TaskAttemptLeaseState::Active
        } else {
            TaskAttemptLeaseState::Released {
                release_id: format!("legacy-release-{ordinal}"),
                released_at_unix_ms: attempt.opened_at_unix_ms + 1,
            }
        };
        TaskAttemptHistoryEntry {
            attempt,
            running_boundary: None,
            verification_boundary: None,
            formal_checks: Vec::new(),
            candidate_boundary: None,
            disposition: None,
            legacy_classification: Some(classification),
            lease_state,
        }
    }

    fn legacy_history(
        classification: LegacyTaskAttemptClassification,
        task_state: TaskState,
        sprint_state: SprintState,
        active: bool,
    ) -> TaskAttemptHistory {
        TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state,
            sprint_state,
            attempts: vec![legacy_entry(1, classification, active)],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        }
    }

    #[test]
    fn task_attempt_identity_is_exact_strict_and_timestamp_canonical() {
        let attempt = test_attempt(1, 1);
        assert_eq!(attempt.attempt_id, attempt.worker_lease.lease_id);
        assert_eq!(attempt.validate(), Ok(()));

        let mut substituted = attempt.clone();
        substituted.attempt_id = format!("lease-{}", "f".repeat(64));
        assert_eq!(
            substituted
                .validate()
                .expect_err("substituted attempt id")
                .field(),
            "task_attempt.attempt_id"
        );
        let mut wrong_time = attempt.clone();
        wrong_time.opened_at_unix_ms += 1;
        assert_eq!(
            wrong_time
                .validate()
                .expect_err("opening time must equal acquisition")
                .field(),
            "task_attempt.opened_at_unix_ms"
        );
        let mut oversized = attempt.clone();
        oversized.opening_event_id = "x".repeat(MAX_TASK_ATTEMPT_ID_BYTES + 1);
        assert_eq!(
            oversized
                .validate()
                .expect_err("attempt identities are bounded")
                .field(),
            "task_attempt.opening_event_id"
        );
        let mut encoded = serde_json::to_value(attempt).expect("attempt json");
        encoded["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TaskAttempt>(encoded).is_err());
    }

    #[test]
    fn running_boundary_is_exact_required_and_monotonic_across_current_phases() {
        let sprint = sprint();
        let task = task("task-1", &[]);
        let attempt = test_attempt(1, 1);
        let running = test_running_boundary(&attempt);
        assert_eq!(running.validate(), Ok(()));

        let mut before_opening = running.clone();
        before_opening.started_at_unix_ms = attempt.opened_at_unix_ms - 1;
        assert_eq!(
            before_opening
                .validate()
                .expect_err("Running cannot precede acquisition")
                .field(),
            "task_attempt_running_boundary.started_at_unix_ms"
        );

        let mut history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state: TaskState::Running,
            sprint_state: SprintState::Running,
            attempts: vec![TaskAttemptHistoryEntry {
                attempt: attempt.clone(),
                running_boundary: None,
                verification_boundary: None,
                formal_checks: Vec::new(),
                candidate_boundary: None,
                disposition: None,
                legacy_classification: None,
                lease_state: TaskAttemptLeaseState::Active,
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        };
        assert!(
            history
                .validate_for_task(&sprint, &task)
                .expect_err("current Running requires its durable boundary")
                .message()
                .contains("Running requires")
        );
        history.attempts[0].running_boundary = Some(running.clone());
        assert_eq!(history.validate_for_task(&sprint, &task), Ok(()));

        let mut crossed = history.clone();
        crossed.attempts[0]
            .running_boundary
            .as_mut()
            .expect("boundary")
            .attempt = test_attempt(1, 2);
        assert_eq!(
            crossed
                .validate_for_task(&sprint, &task)
                .expect_err("boundary cannot cross attempts")
                .field(),
            "task_attempt_disposition.attempt"
        );

        history.task_state = TaskState::Verifying;
        history.attempts[0].verification_boundary = Some(test_verification_boundary(&attempt));
        assert_eq!(history.validate_for_task(&sprint, &task), Ok(()));
        for crossed_identity in ["launch", "session"] {
            let mut crossed = history.clone();
            let verification = crossed.attempts[0]
                .verification_boundary
                .as_mut()
                .expect("verification");
            if crossed_identity == "launch" {
                verification.runner_launch_id = "crossed-launch".into();
            } else {
                verification.runner_session_id = "crossed-session".into();
            }
            assert!(
                crossed
                    .validate_for_task(&sprint, &task)
                    .expect_err("verification must retain Running authority")
                    .message()
                    .contains("exact Running-boundary launch and session")
            );
        }

        history.attempts[0]
            .running_boundary
            .as_mut()
            .expect("running")
            .started_at_unix_ms += 1;
        assert!(
            history
                .validate_for_task(&sprint, &task)
                .expect_err("verification cannot precede Running")
                .message()
                .contains("must not precede the Running boundary")
        );

        let mut leased = history;
        leased.task_state = TaskState::Leased;
        leased.attempts[0].verification_boundary = None;
        assert!(
            leased
                .validate_for_task(&sprint, &task)
                .expect_err("Leased cannot claim it already entered Running")
                .message()
                .contains("Leased attempts cannot carry Running")
        );
    }

    #[test]
    fn retry_disposition_is_ledger_computed_and_release_shape_coupled() {
        let attempt = test_attempt(1, 1);
        let evidence = test_attempt_evidence(TaskAttemptEvidenceKind::NeverLaunched, "absence-1");
        let disposition = TaskAttemptDisposition::Retryable(TaskAttemptRetryableDisposition {
            metadata: disposition_metadata(&attempt),
            cause: TaskAttemptRetryableCause::NeverLaunched {
                evidence: evidence.clone(),
            },
            release_proof: TaskAttemptReleaseProof::NeverLaunched(no_launch_release(
                &attempt, evidence,
            )),
        });
        assert_eq!(disposition.validate_for_budget(3), Ok(()));
        assert!(disposition.validate_for_budget(1).is_err());

        let mut crossed = disposition.clone();
        let TaskAttemptDisposition::Retryable(crossed_record) = &mut crossed else {
            unreachable!();
        };
        crossed_record.cause = TaskAttemptRetryableCause::NeverLaunched {
            evidence: test_attempt_evidence(
                TaskAttemptEvidenceKind::NeverLaunched,
                "different-absence",
            ),
        };
        assert!(
            crossed_record
                .release_proof
                .validate_against(&crossed_record.metadata.attempt)
                .is_ok()
        );
        assert!(
            TaskAttemptDisposition::Retryable((*crossed_record).clone())
                .validate_for_budget(3)
                .expect_err("independent absence evidence must fail")
                .message()
                .contains("exactly equal")
        );

        crossed_record.cause = TaskAttemptRetryableCause::KnownWorkerExit {
            launch_id: "launch-1".into(),
            session_id: "session-1".into(),
            evidence: test_attempt_evidence(TaskAttemptEvidenceKind::KnownWorkerExit, "exit-1"),
        };
        assert!(
            TaskAttemptDisposition::Retryable((*crossed_record).clone())
                .validate_for_budget(3)
                .expect_err("worker exit requires cleanup")
                .message()
                .contains("requires cleanup")
        );
    }

    #[test]
    fn task_integration_receipt_allows_empty_and_declared_nonlexical_check_order() {
        let attempt = test_attempt(1, 1);
        let mut receipt = TaskIntegrationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "integration-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            worker_id: "worker-1".into(),
            worker_lease: Some(attempt.worker_lease),
            worker_launch_id: "launch-1".into(),
            worker_session_id: "session-1".into(),
            worker_policy_hash: digest('1'),
            effect_id: "effect-1".into(),
            observation_id: "observation-1".into(),
            change_set_id: "changes-1".into(),
            input_snapshot: digest('2'),
            result_snapshot: digest('3'),
            task_verification_receipt_ids: Vec::new(),
            integration_ordinal: 0,
            integrated_at_unix_ms: 2_000,
        };
        assert_eq!(receipt.validate(), Ok(()), "human-only set may be empty");
        receipt.task_verification_receipt_ids = vec!["verify-z".into(), "verify-a".into()];
        assert_eq!(
            receipt.validate(),
            Ok(()),
            "declared criterion order is not lexical order"
        );
        receipt
            .task_verification_receipt_ids
            .push("verify-z".into());
        assert!(
            receipt.validate().is_err(),
            "receipt identities remain unique"
        );
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn every_legacy_attempt_classification_is_readable_but_exactly_shaped() {
        let sprint = sprint();
        let task = task("task-1", &[]);
        let cases = [
            (
                LegacyTaskAttemptClassification::LegacyReleased,
                TaskState::Ready,
                SprintState::Running,
                false,
            ),
            (
                LegacyTaskAttemptClassification::LegacyOpen,
                TaskState::Leased,
                SprintState::Running,
                true,
            ),
            (
                LegacyTaskAttemptClassification::LegacyIntegratedCleanupPending,
                TaskState::Integrated,
                SprintState::Running,
                true,
            ),
            (
                LegacyTaskAttemptClassification::LegacyIntegratedReleased,
                TaskState::Integrated,
                SprintState::Running,
                false,
            ),
            (
                LegacyTaskAttemptClassification::LegacyReleasedActiveState,
                TaskState::Running,
                SprintState::Running,
                false,
            ),
            (
                LegacyTaskAttemptClassification::LegacyUnknownQuarantine,
                TaskState::Unknown,
                SprintState::Unknown,
                true,
            ),
        ];
        for (classification, task_state, sprint_state, active) in cases {
            let history = legacy_history(classification, task_state, sprint_state, active);
            assert_eq!(
                history.validate_for_task(&sprint, &task),
                Ok(()),
                "{classification:?}"
            );
        }
        for terminal_state in [
            TaskState::Blocked,
            TaskState::Failed,
            TaskState::Canceled,
            TaskState::Unknown,
        ] {
            let history = legacy_history(
                LegacyTaskAttemptClassification::LegacyReleased,
                terminal_state,
                if terminal_state == TaskState::Unknown {
                    SprintState::Unknown
                } else {
                    SprintState::Running
                },
                false,
            );
            assert_eq!(history.validate_for_task(&sprint, &task), Ok(()));
        }
        for attempted_state in [TaskState::Verifying, TaskState::Candidate] {
            let open = legacy_history(
                LegacyTaskAttemptClassification::LegacyOpen,
                attempted_state,
                SprintState::Running,
                true,
            );
            assert_eq!(
                open.validate_for_task(&sprint, &task),
                Ok(()),
                "legacy open does not fabricate v15 boundaries"
            );
            let released = legacy_history(
                LegacyTaskAttemptClassification::LegacyReleasedActiveState,
                attempted_state,
                SprintState::Running,
                false,
            );
            assert_eq!(
                released.validate_for_task(&sprint, &task),
                Ok(()),
                "released active-state backfill remains diagnostic"
            );
        }

        let mut crossed = legacy_history(
            LegacyTaskAttemptClassification::LegacyOpen,
            TaskState::Leased,
            SprintState::Running,
            true,
        );
        crossed.attempts[0].lease_state = TaskAttemptLeaseState::Released {
            release_id: "forged".into(),
            released_at_unix_ms: 2_000,
        };
        assert!(crossed.validate_for_task(&sprint, &task).is_err());
    }

    #[test]
    fn multiple_legacy_acquisitions_and_over_budget_history_remain_diagnostic() {
        let mut sprint = sprint();
        sprint.budget.max_attempts_per_task = 2;
        let task = task("task-1", &[]);
        let mut history = legacy_history(
            LegacyTaskAttemptClassification::LegacyReleased,
            TaskState::Ready,
            SprintState::Running,
            false,
        );
        history.attempts.push(legacy_entry(
            2,
            LegacyTaskAttemptClassification::LegacyReleased,
            false,
        ));
        assert_eq!(history.validate_for_task(&sprint, &task), Ok(()));

        history.attempts.push(legacy_entry(
            3,
            LegacyTaskAttemptClassification::LegacyReleased,
            false,
        ));
        history.budget_classification = TaskAttemptBudgetClassification::OverBudget;
        assert_eq!(history.validate_for_task(&sprint, &task), Ok(()));
        history.budget_classification = TaskAttemptBudgetClassification::WithinBudget;
        assert!(history.validate_for_task(&sprint, &task).is_err());
    }

    #[test]
    fn unknown_cleaned_requires_pending_or_completed_sprint_unknown() {
        let sprint = sprint();
        let task = task("task-1", &[]);
        let attempt = test_attempt(1, 1);
        let cleanup_receipt = WorkerCleanupReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "cleanup-1".into(),
            sprint_id: "sprint-1".into(),
            launch_id: "launch-1".into(),
            effect_id: "cleanup-effect-1".into(),
            observation_id: "cleanup-observation-1".into(),
            session_id: "session-1".into(),
            worker_lease: Some(attempt.worker_lease.clone()),
            policy_hash: digest('1'),
            grant_hash: digest('2'),
            policy_version: 1,
            platform_backend: WorkerCleanupBackend::LinuxCgroupV2,
            os_evidence_digest: digest('3'),
            surviving_processes: 0,
            cleaned_at_unix_ms: 2_000,
        };
        let cleanup_release = TaskAttemptCleanupRelease {
            contract_version: CONTRACT_VERSION,
            release_id: "release-1".into(),
            attempt: attempt.clone(),
            released_at_unix_ms: cleanup_receipt.cleaned_at_unix_ms,
            cleanup_receipt,
        };
        let metadata = TaskAttemptDispositionMetadata {
            from_state: TaskState::Running,
            disposed_at_unix_ms: cleanup_release.released_at_unix_ms + 1,
            ..disposition_metadata(&attempt)
        };
        let disposition_id = metadata.disposition_id.clone();
        let disposition =
            TaskAttemptDisposition::UnknownCleaned(TaskAttemptUnknownCleanedDisposition {
                metadata,
                unknown_evidence: TaskAttemptUnknownEvidence {
                    effect_id: "effect-unknown".into(),
                    observation_id: "observation-unknown".into(),
                    evidence: test_attempt_evidence(
                        TaskAttemptEvidenceKind::UnknownTerminalEffect,
                        "unknown-1",
                    ),
                },
                cleanup_release: cleanup_release.clone(),
            });
        let mut history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state: TaskState::Unknown,
            sprint_state: SprintState::Running,
            attempts: vec![TaskAttemptHistoryEntry {
                attempt: attempt.clone(),
                running_boundary: Some(test_running_boundary(&attempt)),
                verification_boundary: None,
                formal_checks: Vec::new(),
                candidate_boundary: None,
                disposition: Some(disposition),
                legacy_classification: None,
                lease_state: TaskAttemptLeaseState::Released {
                    release_id: cleanup_release.release_id,
                    released_at_unix_ms: cleanup_release.released_at_unix_ms,
                },
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        };
        assert!(history.validate_for_task(&sprint, &task).is_err());
        history.unknown_terminalization_pending = Some(SprintUnknownTerminalizationPending {
            contract_version: CONTRACT_VERSION,
            marker_id: "pending-1".into(),
            sprint_id: "sprint-1".into(),
            first_attempt_id: attempt.attempt_id,
            first_disposition_id: disposition_id,
            created_at_unix_ms: 2_001,
        });
        assert_eq!(history.validate_for_task(&sprint, &task), Ok(()));
        history.unknown_terminalization_pending = None;
        history.sprint_state = SprintState::Unknown;
        assert_eq!(history.validate_for_task(&sprint, &task), Ok(()));
    }

    #[test]
    fn disposed_verifying_cause_resolves_exact_failed_formal_check() {
        let sprint = sprint();
        let task = task("task-1", &[]);
        let attempt = test_attempt(1, 1);
        let boundary = test_verification_boundary(&attempt);
        let failed_check = test_formal_check(&attempt, &boundary, false);
        let cleanup = cleanup_release(&attempt);
        let mut metadata = disposition_metadata(&attempt);
        metadata.from_state = TaskState::Verifying;
        let disposition = TaskAttemptDisposition::Retryable(TaskAttemptRetryableDisposition {
            metadata,
            cause: TaskAttemptRetryableCause::FormalVerificationFailed {
                formal_check_id: failed_check.formal_check_id.clone(),
                evidence: test_attempt_evidence(
                    TaskAttemptEvidenceKind::FormalVerificationFailed,
                    "formal-failure-1",
                ),
            },
            release_proof: TaskAttemptReleaseProof::Cleanup(cleanup.clone()),
        });
        let mut history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state: TaskState::Ready,
            sprint_state: SprintState::Running,
            attempts: vec![TaskAttemptHistoryEntry {
                running_boundary: Some(test_running_boundary(&attempt)),
                attempt,
                verification_boundary: Some(boundary),
                formal_checks: vec![failed_check],
                candidate_boundary: None,
                disposition: Some(disposition),
                legacy_classification: None,
                lease_state: TaskAttemptLeaseState::Released {
                    release_id: cleanup.release_id,
                    released_at_unix_ms: cleanup.released_at_unix_ms,
                },
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        };
        assert_eq!(history.validate_for_task(&sprint, &task), Ok(()));

        history.attempts[0].formal_checks[0]
            .verification_receipt
            .exit_status = Some(0);
        history.attempts[0].formal_checks[0]
            .verification_receipt
            .termination = Some(CommandTerminationV1::Exited { code: 0 });
        assert!(
            history
                .validate_for_task(&sprint, &task)
                .expect_err("passing receipt cannot prove formal failure")
                .message()
                .contains("exact failed")
        );
        history.attempts[0].formal_checks.clear();
        assert!(history.validate_for_task(&sprint, &task).is_err());
        history.attempts[0].verification_boundary = None;
        assert!(history.validate_for_task(&sprint, &task).is_err());
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn disposed_candidate_and_integrated_evidence_match_exact_history_boundary() {
        let mut sprint = sprint();
        sprint.acceptance_criteria[0].kind = AcceptanceKind::HumanJudgment;
        let task = task("task-1", &[]);
        let attempt = test_attempt(1, 1);
        let verification = test_verification_boundary(&attempt);
        let candidate = TaskAttemptCandidateBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: "candidate-1".into(),
            attempt: attempt.clone(),
            verification_boundary_id: verification.boundary_id.clone(),
            change_set_id: verification.change_set_id.clone(),
            sealed_snapshot: verification.sealed_snapshot.clone(),
            formal_check_ids: Vec::new(),
            verification_receipt_ids: Vec::new(),
            transition_event_id: "to-candidate-1".into(),
            admitted_at_unix_ms: attempt.opened_at_unix_ms + 2,
        };
        let cleanup = cleanup_release(&attempt);
        let mut retry_metadata = disposition_metadata(&attempt);
        retry_metadata.from_state = TaskState::Candidate;
        let retry = TaskAttemptDisposition::Retryable(TaskAttemptRetryableDisposition {
            metadata: retry_metadata,
            cause: TaskAttemptRetryableCause::CandidateRejectedKnown {
                candidate_boundary_id: candidate.boundary_id.clone(),
                evidence: test_attempt_evidence(
                    TaskAttemptEvidenceKind::CandidateRejectedKnown,
                    "candidate-rejection-1",
                ),
            },
            release_proof: TaskAttemptReleaseProof::Cleanup(cleanup.clone()),
        });
        let mut retry_history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state: TaskState::Ready,
            sprint_state: SprintState::Running,
            attempts: vec![TaskAttemptHistoryEntry {
                attempt: attempt.clone(),
                running_boundary: Some(test_running_boundary(&attempt)),
                verification_boundary: Some(verification.clone()),
                formal_checks: Vec::new(),
                candidate_boundary: Some(candidate.clone()),
                disposition: Some(retry),
                legacy_classification: None,
                lease_state: TaskAttemptLeaseState::Released {
                    release_id: cleanup.release_id,
                    released_at_unix_ms: cleanup.released_at_unix_ms,
                },
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        };
        assert_eq!(retry_history.validate_for_task(&sprint, &task), Ok(()));
        retry_history.attempts[0].candidate_boundary = None;
        assert!(retry_history.validate_for_task(&sprint, &task).is_err());

        let integration_receipt = TaskIntegrationReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "integration-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            worker_id: "worker-1".into(),
            worker_lease: Some(attempt.worker_lease.clone()),
            worker_launch_id: "launch-1".into(),
            worker_session_id: "session-1".into(),
            worker_policy_hash: digest('7'),
            effect_id: "integration-effect-1".into(),
            observation_id: "integration-observation-1".into(),
            change_set_id: candidate.change_set_id.clone(),
            input_snapshot: digest('8'),
            result_snapshot: candidate.sealed_snapshot.clone(),
            task_verification_receipt_ids: Vec::new(),
            integration_ordinal: 0,
            integrated_at_unix_ms: attempt.opened_at_unix_ms + 3,
        };
        let mut integrated_metadata = disposition_metadata(&attempt);
        integrated_metadata.from_state = TaskState::Candidate;
        integrated_metadata.disposed_at_unix_ms = attempt.opened_at_unix_ms + 3;
        let integrated = TaskAttemptDisposition::Integrated(TaskAttemptIntegratedDisposition {
            metadata: integrated_metadata,
            candidate_boundary: candidate.clone(),
            integration_receipt,
            evidence: test_attempt_evidence(TaskAttemptEvidenceKind::Integrated, "integrated-1"),
        });
        let mut integrated_history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state: TaskState::Integrated,
            sprint_state: SprintState::Running,
            attempts: vec![TaskAttemptHistoryEntry {
                running_boundary: Some(test_running_boundary(&attempt)),
                attempt,
                verification_boundary: Some(verification),
                formal_checks: Vec::new(),
                candidate_boundary: Some(candidate),
                disposition: Some(integrated),
                legacy_classification: None,
                lease_state: TaskAttemptLeaseState::Active,
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        };
        assert_eq!(integrated_history.validate_for_task(&sprint, &task), Ok(()));
        let TaskAttemptDisposition::Integrated(disposition) = integrated_history.attempts[0]
            .disposition
            .as_mut()
            .expect("integrated")
        else {
            unreachable!();
        };
        disposition.candidate_boundary.boundary_id = "crossed-candidate".into();
        assert!(
            integrated_history
                .validate_for_task(&sprint, &task)
                .expect_err("embedded candidate must equal history boundary")
                .message()
                .contains("exact history candidate")
        );
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn recovery_projection_covers_every_closed_decision_and_rejects_crossed_facts() {
        let sprint = sprint();
        let task = task("task-1", &[]);
        let attempt = test_attempt(1, 1);
        let open_history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state: TaskState::Running,
            sprint_state: SprintState::Running,
            attempts: vec![TaskAttemptHistoryEntry {
                attempt: attempt.clone(),
                running_boundary: Some(test_running_boundary(&attempt)),
                verification_boundary: None,
                formal_checks: Vec::new(),
                candidate_boundary: None,
                disposition: None,
                legacy_classification: None,
                lease_state: TaskAttemptLeaseState::Active,
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        };
        let current = TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id: "launch-1".into(),
            session_id: Some("session-1".into()),
        };
        assert_eq!(
            open_history.project_recovery_decision(&sprint, &task, &attempt.attempt_id, &current,),
            Ok(TaskAttemptRecoveryDecision::ContinueActive)
        );
        let mut never_launched_history = open_history.clone();
        never_launched_history.task_state = TaskState::Leased;
        never_launched_history.attempts[0].running_boundary = None;
        assert!(
            open_history
                .project_recovery_decision(
                    &sprint,
                    &task,
                    &attempt.attempt_id,
                    &TaskAttemptRecoveryFacts::NeverLaunched,
                )
                .expect_err("Running authority contradicts NeverLaunched")
                .message()
                .contains("contradicts the durable Running boundary")
        );
        assert_eq!(
            never_launched_history.project_recovery_decision(
                &sprint,
                &task,
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::NeverLaunched,
            ),
            Ok(TaskAttemptRecoveryDecision::CloseNeverLaunchedThenRetry)
        );
        let cleanup_facts = TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id: "launch-1".into(),
            session_id: Some("session-1".into()),
            outcome: TaskAttemptKnownCleanupOutcome::Retryable(
                TaskAttemptRetryableCause::KnownWorkerExit {
                    launch_id: "launch-1".into(),
                    session_id: "session-1".into(),
                    evidence: test_attempt_evidence(
                        TaskAttemptEvidenceKind::KnownWorkerExit,
                        "known-exit-1",
                    ),
                },
            ),
        };
        assert_eq!(
            open_history.project_recovery_decision(
                &sprint,
                &task,
                &attempt.attempt_id,
                &cleanup_facts,
            ),
            Ok(TaskAttemptRecoveryDecision::CleanupThenRetry)
        );
        let permanent_cleanup = TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id: "launch-1".into(),
            session_id: Some("session-1".into()),
            outcome: TaskAttemptKnownCleanupOutcome::PermanentFailure(
                TaskAttemptPermanentFailureCause::PermanentContractViolation {
                    violation_id: "violation-1".into(),
                    evidence: test_attempt_evidence(
                        TaskAttemptEvidenceKind::PermanentContractViolation,
                        "violation-evidence-1",
                    ),
                },
            ),
        };
        assert_eq!(
            open_history.project_recovery_decision(
                &sprint,
                &task,
                &attempt.attempt_id,
                &permanent_cleanup,
            ),
            Ok(TaskAttemptRecoveryDecision::CleanupThenFail),
            "non-retryable cause cannot become retryable merely because budget remains"
        );
        assert_eq!(
            open_history.project_recovery_decision(
                &sprint,
                &task,
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::UncertainAuthority {
                    evidence_id: "uncertain-1".into(),
                },
            ),
            Ok(TaskAttemptRecoveryDecision::TerminalizeUnknown)
        );

        let mut final_attempt_sprint = sprint.clone();
        final_attempt_sprint.budget.max_attempts_per_task = 1;
        assert_eq!(
            never_launched_history.project_recovery_decision(
                &final_attempt_sprint,
                &task,
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::NeverLaunched,
            ),
            Ok(TaskAttemptRecoveryDecision::CloseNeverLaunchedThenFail)
        );
        assert_eq!(
            open_history.project_recovery_decision(
                &final_attempt_sprint,
                &task,
                &attempt.attempt_id,
                &cleanup_facts,
            ),
            Ok(TaskAttemptRecoveryDecision::CleanupThenFail)
        );

        let legacy_open = legacy_history(
            LegacyTaskAttemptClassification::LegacyOpen,
            TaskState::Running,
            SprintState::Running,
            true,
        );
        assert_eq!(
            legacy_open.project_recovery_decision(
                &sprint,
                &task,
                &legacy_open.attempts[0].attempt.attempt_id,
                &TaskAttemptRecoveryFacts::DurableHistoryOnly,
            ),
            Ok(TaskAttemptRecoveryDecision::RecoverPreV15Open)
        );
        let legacy_integration = legacy_history(
            LegacyTaskAttemptClassification::LegacyIntegratedCleanupPending,
            TaskState::Integrated,
            SprintState::Running,
            true,
        );
        assert_eq!(
            legacy_integration.project_recovery_decision(
                &sprint,
                &task,
                &legacy_integration.attempts[0].attempt.attempt_id,
                &TaskAttemptRecoveryFacts::DurableHistoryOnly,
            ),
            Ok(TaskAttemptRecoveryDecision::IntegratedCleanupPending)
        );
        let legacy_released = legacy_history(
            LegacyTaskAttemptClassification::LegacyReleased,
            TaskState::Ready,
            SprintState::Running,
            false,
        );
        assert_eq!(
            legacy_released.project_recovery_decision(
                &sprint,
                &task,
                &legacy_released.attempts[0].attempt.attempt_id,
                &TaskAttemptRecoveryFacts::DurableHistoryOnly,
            ),
            Ok(TaskAttemptRecoveryDecision::AlreadyDisposed)
        );

        let uncertain_attempt = test_attempt(1, 1);
        let uncertain_metadata = TaskAttemptDispositionMetadata {
            contract_version: CONTRACT_VERSION,
            disposition_id: "unknown-disposition-1".into(),
            attempt: uncertain_attempt.clone(),
            from_state: TaskState::Running,
            state_transition_event_id: "to-unknown-1".into(),
            disposed_at_unix_ms: uncertain_attempt.opened_at_unix_ms + 1,
        };
        let marker = SprintUnknownTerminalizationPending {
            contract_version: CONTRACT_VERSION,
            marker_id: "pending-unknown-1".into(),
            sprint_id: "sprint-1".into(),
            first_attempt_id: uncertain_attempt.attempt_id.clone(),
            first_disposition_id: uncertain_metadata.disposition_id.clone(),
            created_at_unix_ms: uncertain_attempt.opened_at_unix_ms + 2,
        };
        let unknown_history = TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            task_state: TaskState::Unknown,
            sprint_state: SprintState::Running,
            attempts: vec![TaskAttemptHistoryEntry {
                attempt: uncertain_attempt.clone(),
                running_boundary: Some(test_running_boundary(&uncertain_attempt)),
                verification_boundary: None,
                formal_checks: Vec::new(),
                candidate_boundary: None,
                disposition: Some(TaskAttemptDisposition::UnknownQuarantined(
                    TaskAttemptUnknownQuarantinedDisposition {
                        metadata: uncertain_metadata,
                        uncertain_evidence: TaskAttemptUncertainEvidence {
                            uncertainty_id: "uncertainty-1".into(),
                            authority_reference_ids: vec!["session-1".into()],
                            evidence: test_attempt_evidence(
                                TaskAttemptEvidenceKind::UncertainAuthority,
                                "uncertain-evidence-1",
                            ),
                        },
                    },
                )),
                legacy_classification: None,
                lease_state: TaskAttemptLeaseState::Active,
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: Some(marker.clone()),
        };
        assert_eq!(
            unknown_history.project_recovery_decision(
                &sprint,
                &task,
                &uncertain_attempt.attempt_id,
                &TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady {
                    marker_id: marker.marker_id.clone(),
                    evidence_id: "all-domains-ready-1".into(),
                },
            ),
            Ok(TaskAttemptRecoveryDecision::TerminalizeSprintUnknown)
        );
        assert_eq!(
            unknown_history.project_recovery_decision(
                &sprint,
                &task,
                &uncertain_attempt.attempt_id,
                &TaskAttemptRecoveryFacts::DurableHistoryOnly,
            ),
            Ok(TaskAttemptRecoveryDecision::AlreadyDisposed),
            "one task-local history cannot itself prove sprint terminal readiness"
        );
        assert!(
            unknown_history
                .project_recovery_decision(
                    &sprint,
                    &task,
                    &uncertain_attempt.attempt_id,
                    &TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady {
                        marker_id: "crossed-marker".into(),
                        evidence_id: "all-domains-ready-1".into(),
                    },
                )
                .is_err()
        );

        let mut frozen_open = open_history.clone();
        frozen_open.unknown_terminalization_pending = Some(marker);
        assert!(
            frozen_open
                .project_recovery_decision(&sprint, &task, &attempt.attempt_id, &current)
                .expect_err("pending marker prohibits continuing exact live authority")
                .message()
                .contains("requires known cleanup")
        );
        assert_eq!(
            {
                let mut frozen_never_launched = never_launched_history.clone();
                frozen_never_launched.unknown_terminalization_pending =
                    frozen_open.unknown_terminalization_pending.clone();
                frozen_never_launched
            }
            .project_recovery_decision(
                &sprint,
                &task,
                &attempt.attempt_id,
                &TaskAttemptRecoveryFacts::NeverLaunched,
            ),
            Ok(TaskAttemptRecoveryDecision::CloseNeverLaunchedThenRetry)
        );
        assert_eq!(
            frozen_open.project_recovery_decision(
                &sprint,
                &task,
                &attempt.attempt_id,
                &cleanup_facts,
            ),
            Ok(TaskAttemptRecoveryDecision::CleanupThenRetry),
            "known evidence remains exact while the scheduler stays frozen"
        );

        let crossed_current = TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id: "crossed-launch".into(),
            session_id: Some("session-1".into()),
        };
        assert!(
            open_history
                .project_recovery_decision(&sprint, &task, &attempt.attempt_id, &crossed_current,)
                .expect_err("current authority must match the Running boundary")
                .message()
                .contains("exact Running-boundary launch and session")
        );
        let missing_session = TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id: "launch-1".into(),
            session_id: None,
        };
        assert!(
            open_history
                .project_recovery_decision(&sprint, &task, &attempt.attempt_id, &missing_session,)
                .expect_err("Running boundary includes an initialized session")
                .message()
                .contains("exact Running-boundary launch and session")
        );
        let crossed_permanent_cleanup = TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id: "crossed-launch".into(),
            session_id: Some("session-1".into()),
            outcome: TaskAttemptKnownCleanupOutcome::PermanentFailure(
                TaskAttemptPermanentFailureCause::PermanentContractViolation {
                    violation_id: "violation-2".into(),
                    evidence: test_attempt_evidence(
                        TaskAttemptEvidenceKind::PermanentContractViolation,
                        "violation-evidence-2",
                    ),
                },
            ),
        };
        assert!(
            open_history
                .project_recovery_decision(
                    &sprint,
                    &task,
                    &attempt.attempt_id,
                    &crossed_permanent_cleanup,
                )
                .expect_err("cleanup authority must match the Running boundary")
                .message()
                .contains("exact Running-boundary launch and session")
        );

        let mut crossed_cleanup = cleanup_facts.clone();
        let TaskAttemptRecoveryFacts::KnownCleanupRequired { launch_id, .. } = &mut crossed_cleanup
        else {
            unreachable!();
        };
        *launch_id = "crossed-launch".into();
        assert!(
            open_history
                .project_recovery_decision(&sprint, &task, &attempt.attempt_id, &crossed_cleanup,)
                .expect_err("cause and cleanup launch must match")
                .message()
                .contains("exact cleanup launch and session")
        );

        assert!(
            open_history
                .project_recovery_decision(
                    &sprint,
                    &task,
                    &attempt.attempt_id,
                    &TaskAttemptRecoveryFacts::DurableHistoryOnly,
                )
                .is_err()
        );
        assert!(
            legacy_released
                .project_recovery_decision(
                    &sprint,
                    &task,
                    &legacy_released.attempts[0].attempt.attempt_id,
                    &current,
                )
                .is_err()
        );
        assert!(
            open_history
                .project_recovery_decision(&sprint, &task, "missing", &current)
                .is_err()
        );
    }
