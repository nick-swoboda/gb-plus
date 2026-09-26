    #[test]
    fn contained_timeout_uses_backend_domain_kill() {
        let limits = ResourceLimits {
            wall_time_ms: 1,
            max_output_bytes: 1024,
            max_processes: 1,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("timeout-domain", limits);
        let prepared = prepare_contained(grant, policy, &paths, &command).expect("prepare command");
        let running = DomainObservation {
            stdout: Vec::new(),
            stderr: Vec::new(),
            leader: None,
            stdout_closed: false,
            stderr_closed: false,
            domain_empty: false,
        };
        let (mut backend, state) = FakeContainedBackend::ready_for(&prepared, [running]);
        backend.controls = contained_boundary::required_controls(limits);
        let evidence = contained_boundary::execute(backend, prepared, &CancellationToken::new())
            .expect("timeout and reconcile domain");
        assert_eq!(evidence.termination(), CommandTermination::TimedOut);
        evidence
            .cleanup_proof()
            .validate()
            .expect("timeout cleanup retains native proof");
        assert_eq!(
            *state
                .terminations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [DomainTerminationRequest::TimedOut]
        );
    }

    #[test]
    fn complete_hashes_survive_bounded_retention() {
        let stdout = StreamCapture {
            retained: b"abcdef".to_vec(),
            complete_digest: hash_bytes(b"abcdef"),
            complete_length: 6,
        };
        let stderr = StreamCapture {
            retained: b"xyz".to_vec(),
            complete_digest: hash_bytes(b"xyz"),
            complete_length: 3,
        };
        let (stdout, stderr) = bound_retained_output(stdout, stderr, 7);
        assert_eq!(stdout.bytes(), b"abcdef");
        assert_eq!(stderr.bytes(), b"x");
        assert_eq!(stdout.bytes().len() + stderr.bytes().len(), 7);
        assert!(!stdout.truncated());
        assert!(stderr.truncated());
        assert_eq!(stderr.complete_digest(), &hash_bytes(b"xyz"));
        assert_ne!(
            combined_output_digest(&stdout, &stderr),
            hash_bytes(b"abcdefxyz")
        );
    }

    #[test]
    fn shells_and_host_channels_are_rejected() {
        assert!(reject_explicit_shell("/bin/sh").is_err());
        assert!(reject_explicit_shell("bash").is_err());
        assert!(reject_explicit_shell("cargo").is_ok());
        assert!(is_reserved_policy_environment("HOME"));
        assert!(is_reserved_policy_environment("dbus_session_bus_address"));
        assert!(!is_reserved_policy_environment("LANG"));
    }

    #[test]
    fn finite_unproven_resource_limits_fail_closed() {
        assert!(
            validate_resource_limits(ResourceLimits {
                wall_time_ms: 1,
                max_output_bytes: 1,
                max_processes: 2,
                max_memory_bytes: None,
            })
            .is_err()
        );
        assert!(
            validate_resource_limits(ResourceLimits {
                wall_time_ms: 1,
                max_output_bytes: 1,
                max_processes: 1,
                max_memory_bytes: Some(1),
            })
            .is_err()
        );
    }

    #[test]
    fn linux_plan_has_namespaces_and_never_authorizes() {
        let workspace = TestDirectory::new("linux-workspace");
        let private = TestDirectory::new("linux-private");
        let shadow = private.0.join("shadow");
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&shadow).expect("create shadow");
        let (grant, policy) = authority(&workspace.0, ExecutionNetwork::None, 1024);
        let plan = plan_linux_bubblewrap(
            &grant,
            &policy,
            &SupervisorPaths::shadow(&private.0, &shadow),
            &CommandSpec {
                program: "/usr/bin/true".into(),
                arguments: vec![],
                working_directory: PathBuf::new(),
            },
        )
        .expect("generate blocked plan");
        assert!(!plan.permits_execution());
        assert!(plan.arguments().contains(&OsString::from("--unshare-user")));
        assert!(plan.arguments().contains(&OsString::from("--unshare-pid")));
        assert!(plan.arguments().contains(&OsString::from("--unshare-net")));
        assert!(plan.blocked_reason().contains("Landlock"));
        assert!(plan.blocked_reason().contains("seccomp"));
    }

    #[cfg(unix)]
    #[test]
    fn process_group_ids_reach_the_signal_utility_as_operands() {
        let directory = TestDirectory::new("signal-operands");
        let program = directory.0.join("kill");
        fs::write(&program, b"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\n")
            .expect("write recording signal utility");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700))
            .expect("make signal utility executable");
        let utility = ExecutableIdentity::capture(&program).expect("signal utility identity");
        let recorded = directory.0.join("kill.args");

        for group in [12_345, 23_456] {
            signal_process_group(group, &utility, "-KILL").expect("send group signal");
            assert_eq!(
                fs::read_to_string(&recorded).expect("recorded signal arguments"),
                format!("-KILL\n--\n-{group}\n")
            );
            assert!(process_group_exists(group, &utility).expect("probe group"));
            assert_eq!(
                fs::read_to_string(&recorded).expect("recorded probe arguments"),
                format!("-0\n--\n-{group}\n")
            );
        }
    }

    #[test]
    fn timeout_kills_direct_process_group() {
        let kill = ExecutableIdentity::capture(Path::new(KILL_PROGRAM)).expect("kill identity");
        let mut command = Command::new("/bin/sleep");
        command.arg("10").env_clear();
        let result = spawn_monitored(
            &mut command,
            ResourceLimits {
                wall_time_ms: 50,
                max_output_bytes: 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
            &CancellationToken::new(),
            &kill,
            || Ok(()),
        )
        .expect("supervise sleep");
        assert_eq!(result.termination, CommandTermination::TimedOut);
    }

    #[test]
    fn output_overflow_terminates_and_hashes_complete_observed_stream() {
        let kill = ExecutableIdentity::capture(Path::new(KILL_PROGRAM)).expect("kill identity");
        let mut command = Command::new("/usr/bin/yes");
        command.env_clear();
        let result = spawn_monitored(
            &mut command,
            ResourceLimits {
                wall_time_ms: 2_000,
                max_output_bytes: 256,
                max_processes: 1,
                max_memory_bytes: None,
            },
            &CancellationToken::new(),
            &kill,
            || Ok(()),
        )
        .expect("supervise output overflow");
        assert_eq!(result.termination, CommandTermination::OutputLimitExceeded);
        assert!(result.stdout.complete_length > 256);
        assert_eq!(result.stdout.retained.len(), 256);
    }

    #[test]
    #[expect(
        clippy::zombie_processes,
        reason = "the orphan branch intentionally exercises supervisor cleanup after parent exit"
    )]
    fn descendant_helper() {
        let pid_file = std::env::var_os("GROK_RUNNER_DESCENDANT_PID_FILE")
            .or_else(|| std::env::var_os("GROK_RUNNER_ORPHAN_PID_FILE"));
        let Some(pid_file) = pid_file else {
            return;
        };
        let mut descendant = Command::new("/bin/sleep")
            .arg("30")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn descendant");
        fs::write(pid_file, descendant.id().to_string()).expect("record descendant pid");
        if std::env::var_os("GROK_RUNNER_ORPHAN_PID_FILE").is_some() {
            return;
        }
        let _ = descendant.wait();
    }

    #[test]
    fn timeout_kills_descendant_process_group() {
        let directory = TestDirectory::new("descendant");
        let pid_file = directory.0.join("pid");
        let executable = std::env::current_exe().expect("current test executable");
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "command::tests::descendant_helper",
                "--nocapture",
            ])
            .env_clear()
            .env("GROK_RUNNER_DESCENDANT_PID_FILE", &pid_file);
        let kill = ExecutableIdentity::capture(Path::new(KILL_PROGRAM)).expect("kill identity");
        let result = spawn_monitored(
            &mut command,
            ResourceLimits {
                wall_time_ms: 500,
                max_output_bytes: 64 * 1024,
                max_processes: 2,
                max_memory_bytes: None,
            },
            &CancellationToken::new(),
            &kill,
            || Ok(()),
        )
        .expect("supervise process tree");
        assert_eq!(result.termination, CommandTermination::TimedOut);
        let pid = fs::read_to_string(&pid_file).expect("descendant pid");
        for _ in 0..100 {
            let status = Command::new(KILL_PROGRAM)
                .args(["-0", pid.trim()])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("probe descendant");
            if !status.success() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("descendant remained alive after process-group timeout");
    }

    #[test]
    fn normal_parent_exit_still_cleans_orphaned_group_member() {
        let directory = TestDirectory::new("orphan");
        let pid_file = directory.0.join("pid");
        let executable = std::env::current_exe().expect("current test executable");
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "command::tests::descendant_helper",
                "--nocapture",
            ])
            .env_clear()
            .env("GROK_RUNNER_ORPHAN_PID_FILE", &pid_file);
        let kill = ExecutableIdentity::capture(Path::new(KILL_PROGRAM)).expect("kill identity");
        let result = spawn_monitored(
            &mut command,
            ResourceLimits {
                wall_time_ms: 5_000,
                max_output_bytes: 64 * 1024,
                max_processes: 2,
                max_memory_bytes: None,
            },
            &CancellationToken::new(),
            &kill,
            || Ok(()),
        )
        .expect("reconcile orphaned group member");
        assert_eq!(result.termination, CommandTermination::Exited(0));
        let pid = fs::read_to_string(&pid_file).expect("orphan pid");
        let status = Command::new(KILL_PROGRAM)
            .args(["-0", pid.trim()])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("probe orphan");
        assert!(!status.success());
    }

    #[test]
    fn git_working_directory_aliases_are_rejected_lexically() {
        for path in [".git", ".GIT/config", "nested/.Git/objects"] {
            assert!(contains_git_component(Path::new(path)));
        }
        assert!(!contains_git_component(Path::new("src/git_support")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_quoting_resists_rule_injection() {
        let malicious = Path::new("/tmp/project\") (allow default) (\"");
        let quoted = seatbelt_quote(malicious).expect("quote path");
        assert_eq!(quoted, "\"/tmp/project\\\") (allow default) (\\\"\"");
        assert!(seatbelt_quote(Path::new("/tmp/project\nallow default")).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn active_canaries_fail_closed_on_inherited_descriptor_gap() {
        let workspace = TestDirectory::new("active-workspace");
        let private = TestDirectory::new("active-private");
        fs::create_dir(workspace.0.join("src")).expect("workspace src");
        let shadow = private.0.join("shadow");
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&shadow).expect("shadow root");
        fs::create_dir(shadow.join("src")).expect("shadow src");
        let (grant, policy) = authority(&workspace.0, ExecutionNetwork::None, 1024);
        let paths = SupervisorPaths::shadow(&private.0, &shadow);
        let error = CommandSupervisor::authorize(grant, policy, &paths)
            .err()
            .expect("inherited descriptor gap must block authorization");
        assert!(
            error.to_string().contains("closefrom"),
            "unexpected inherited-descriptor authorization error: {error}"
        );
    }

    /// A deny root that is a symlink denies its target too.
    ///
    /// Seatbelt matches the resolved vnode path, so denying only the logical
    /// name of a symlinked `.git` left the content readable at its real
    /// location. The credential set already added the twin; the `.git` denies
    /// did not. The arm drives a real symlink rather than asserting on the
    /// helper, because the property that matters is what reaches the profile.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_symlinked_deny_root_denies_its_target_as_well_as_its_name() {
        let directory = TestDirectory::new("symlink-deny");
        let real = directory.0.join("real-git");
        std::fs::create_dir(&real).expect("the real directory");
        let link = directory.0.join("workspace-git");
        std::os::unix::fs::symlink(&real, &link).expect("the symlink");

        let mut denied = Vec::new();
        push_denied_root(&mut denied, link.clone());

        assert!(
            denied.contains(&link),
            "the logical name must still be denied: {denied:?}"
        );
        let canonical = std::fs::canonicalize(&real).expect("canonicalize the target");
        assert!(
            denied.contains(&canonical),
            "the resolved target must be denied too, or the content stays readable \
             at its real location: {denied:?}"
        );

        // A root that is not a link contributes exactly one entry, so the twin
        // rule does not quietly double every ordinary deny.
        let mut plain = Vec::new();
        push_denied_root(&mut plain, real.clone());
        assert_eq!(
            plain,
            vec![std::fs::canonicalize(&real).expect("canonicalize")],
            "a non-symlink deny root should contribute one path"
        );
    }

    /// Class #4 is not closed by a helper `Vec` alone: Seatbelt matches the
    /// resolved vnode path, so the rendered profile must name both locations
    /// when the parent is a symlink and the `.git` leaf is absent.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_symlinked_parent_with_absent_git_denies_both_paths_in_the_rendered_profile() {
        let directory = TestDirectory::new("symlink-parent-absent-git");
        let real = directory.0.join("real-workspace");
        std::fs::create_dir(&real).expect("the real parent");
        let link = directory.0.join("logical-workspace");
        std::os::unix::fs::symlink(&real, &link).expect("the parent symlink");
        let logical_git = link.join(".git");
        assert!(
            !logical_git.exists(),
            "the leaf must be absent so canonicalize(parent/.git) cannot succeed"
        );

        let mut denied = Vec::new();
        push_denied_root(&mut denied, logical_git.clone());
        let canonical_git = std::fs::canonicalize(&real)
            .expect("canonicalize the parent")
            .join(".git");
        assert_ne!(
            logical_git, canonical_git,
            "the logical and resolved .git paths must differ"
        );

        let profile = render_seatbelt_profile(
            &BTreeSet::from([PathBuf::from("/usr/bin/true")]),
            std::slice::from_ref(&link),
            &[],
            &denied,
            &link,
            false,
        )
        .expect("render profile");
        let logical_text = logical_git.to_str().expect("logical utf-8");
        let canonical_text = canonical_git.to_str().expect("canonical utf-8");
        assert!(
            profile.contains(logical_text),
            "the rendered profile must deny the logical <parent>/.git: {profile}"
        );
        assert!(
            profile.contains(canonical_text),
            "the rendered profile must deny the canonical <target>/.git: {profile}"
        );

        let mut plain = Vec::new();
        let ordinary = real.join(".git");
        push_denied_root(&mut plain, ordinary.clone());
        assert_eq!(
            plain,
            vec![ordinary],
            "a non-symlink parent still contributes one path when the leaf is absent"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rendered_profile_has_live_git_credential_and_network_denials() {
        let executables = BTreeSet::from([PathBuf::from("/usr/bin/true")]);
        let profile = render_seatbelt_profile(
            &executables,
            &[PathBuf::from("/Users/test/project")],
            &[PathBuf::from("/private/tmp/shadow/src")],
            &[PathBuf::from("/Users/test/.ssh")],
            Path::new("/Users/test/project"),
            false,
        )
        .expect("render profile");
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("/Users/test/project"));
        assert!(profile.contains("/Users/test/.ssh"));
        assert!(profile.contains("/\\.git(/|$)"));
    }

    /// The production command-job path composes this host's contained backend
    /// and stops at that backend's own refusal.
    ///
    /// This is the seam's measurable outcome, and it is deliberately asserted
    /// against `crate::service`'s production function rather than against
    /// `execute_classified` directly: the point is not that the backend refuses
    /// -- its own tests already prove that -- but that the runner's dispatch
    /// path now *reaches* it. Before the seam carried session custody the arc
    /// stopped at a type-level `None` with both factory arguments unused, so no
    /// backend was ever composed and no refusal string existed to read.
    ///
    /// Nothing here is loosened to get further: the refusal must still name
    /// every control `required_controls` demands, which is exactly what
    /// `validate_preflight`'s set equality would refuse on next.
    #[test]
    fn the_production_command_job_path_stops_at_the_backends_own_refusal() {
        let limits = ResourceLimits {
            wall_time_ms: 60_000,
            max_output_bytes: 4 * 1024 * 1024,
            max_processes: 4,
            max_memory_bytes: None,
        };
        let (_workspace, _private, paths, grant, policy, command) =
            contained_fixture("production-job-path", limits);
        let prepared = prepare_contained(grant.clone(), policy.clone(), &paths, &command)
            .expect("prepare the contained command the production job would prepare");

        let run = crate::service::execute_prepared_contained_command(
            prepared,
            grant,
            policy,
            &paths,
            None,
            &CancellationToken::new(),
        );
        let crate::service::ContainedCommandRun::Executed(
            ContainedExecutionOutcome::RefusedBeforeLaunch(error),
        ) = run
        else {
            panic!("the production job path must compose a backend and reach its refusal: {run:?}");
        };
        let message = error.to_string();
        #[cfg(target_os = "linux")]
        let expected = linux_backend::LINUX_CGROUP_V2_SERVICE_UNAVAILABLE;
        #[cfg(target_os = "macos")]
        let expected = macos_backend::MACOS_DEDICATED_IDENTITY_TRANSPORT_UNAVAILABLE;
        assert!(
            message.contains(expected),
            "the stop must be the backend's own service/transport-unavailable refusal: {message}"
        );
        for control in contained_boundary::required_controls(limits) {
            assert!(
                message.contains(&format!("{control:?}")),
                "the refusal must name every unenforceable control, missing {control:?}: {message}"
            );
        }
    }

    /// The control half of the test above: a bare program name never reaches a
    /// containment backend at all.
    ///
    /// Same fixture, same limits, one input varied, the command's program,
    /// and the two stops are different gates, not two wordings of one gate.
    /// `resolve_executable` refuses a bare name before any backend is composed,
    /// so its messages name a `PATH` and **no** control, while the absolute
    /// program above reaches `active_preflight` and its message names every one
    /// of the twelve.
    ///
    /// Both bare-name refusals are pinned because which one fires depends on
    /// the compiled policy, not on the command: a policy that declares no
    /// environment, which is exactly what the walking skeleton's spine
    /// compiles, has no controlled `PATH` to search, and the fixture policy
    /// that declares `PATH=/usr/bin:/bin` searches it and finds nothing. Both
    /// are `SupervisorError::InvalidCommand`, which
    /// `contained_command_failure_code` maps to `InvalidAuthority` rather than
    /// the `ContainmentUnavailable` that route 2's evidence attachment
    /// requires. That is why the walking skeleton's fourth tool now commands an
    /// absolute executable.
    #[test]
    fn a_bare_program_name_stops_before_any_backend_is_composed() {
        let limits = ResourceLimits {
            wall_time_ms: 60_000,
            max_output_bytes: 4 * 1024 * 1024,
            max_processes: 4,
            max_memory_bytes: None,
        };
        // A capture reservation is keyed by the exact command, so each half
        // gets its own private root rather than sharing one.
        for (label, declare_path, expected) in [
            (
                "bare-name-without-path",
                false,
                "invalid command: a bare executable name requires an explicit controlled PATH",
            ),
            (
                "bare-name-with-path",
                true,
                "invalid command: executable `cargo` was not found on the controlled PATH",
            ),
        ] {
            let (_workspace, _private, paths, grant, path_policy, absolute) =
                contained_fixture(label, limits);
            let bare = CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into(), "--offline".into(), "--locked".into()],
                working_directory: absolute.working_directory.clone(),
            };
            // The spine's own policy shape declares no environment at all, so
            // the contained environment carries no PATH to search.
            let policy = if declare_path {
                path_policy
            } else {
                ExecutionPolicyCompiler::compile(
                    &grant,
                    ExecutionPolicyRequest {
                        policy_id: "policy-command-test-no-environment".into(),
                        read_scopes: vec![PathScope::Workspace],
                        write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                        environment: Vec::new(),
                        network: ExecutionNetwork::None,
                        mutation_mode: MutationMode::ShadowWorkspace,
                        resource_limits: limits,
                        approval_id: None,
                    },
                )
                .expect("compile a policy that declares no environment")
            };

            let error = prepare_contained(grant, policy, &paths, &bare)
                .expect_err("a bare program name must be refused before preparation completes");
            let message = error.to_string();
            assert_eq!(message, expected, "unexpected bare-name refusal");
            for control in contained_boundary::required_controls(limits) {
                assert!(
                    !message.contains(&format!("{control:?}")),
                    "a stop this early cannot name containment control {control:?}: {message}"
                );
            }
        }

        // And the varied half really is only the program: the same fixture
        // shape with an absolute executable prepares, which is what lets the
        // run reach a backend at all.
        let (_workspace, _private, paths, grant, policy, absolute) =
            contained_fixture("bare-name-absolute-control", limits);
        prepare_contained(grant, policy, &paths, &absolute)
            .expect("the same fixture with an absolute program prepares");
    }
