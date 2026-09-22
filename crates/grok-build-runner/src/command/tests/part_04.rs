    /// Exercises development canaries in a delegated cgroup-v2 root supplied
    /// through `GROK_BUILD_CGROUP_ROOT`. It does not qualify the production service.
    #[cfg(target_os = "linux")]
    mod linux_cgroup_v2_contained_backend {
        #[allow(
            clippy::wildcard_imports,
            reason = "the Linux backend tests reuse the same production-shape command fixtures as the rest of this module"
        )]
        use super::*;
        use crate::linux_dev_domain::{
            LinuxDelegatedCanaryDomain, delegation_root_from_environment, sealed_self_image,
        };

        fn linux_limits(max_processes: u32) -> ResourceLimits {
            ResourceLimits {
                wall_time_ms: 60_000,
                max_output_bytes: 4 * 1024 * 1024,
                max_processes,
                max_memory_bytes: None,
            }
        }

        /// The production arm holds no delegation, claims nothing, and says so.
        #[test]
        fn the_production_linux_backend_claims_no_control_and_refuses_before_launch() {
            let limits = linux_limits(4);
            let (_workspace, _private, paths, grant, policy, command) =
                contained_fixture("linux-production-backend", limits);
            let prepared = prepare_contained(grant.clone(), policy.clone(), &paths, &command)
                .expect("prepare the contained command for the Linux production backend");
            let backend = linux_backend::LinuxCgroupV2Backend::new(grant, policy, &paths)
                .expect("compose the production Linux cgroup-v2 backend");
            assert!(!backend.development_mode());
            assert_eq!(
                backend.backend_id(),
                linux_backend::LINUX_CGROUP_V2_BACKEND_ID
            );
            assert!(
                backend.enforced_controls().is_empty(),
                "a backend with no delegated domain must claim nothing"
            );
            let identity = contained_boundary::ContainedCommandBackend::identity(&backend)
                .expect("the production Linux backend has a stable identity");
            assert_eq!(
                identity.command_domain_backend(),
                CommandDomainCleanupBackend::LinuxCgroupV2
            );

            let outcome = contained_boundary::execute_classified(
                backend,
                prepared,
                &CancellationToken::new(),
            );
            let ContainedExecutionOutcome::RefusedBeforeLaunch(error) = outcome else {
                panic!(
                    "the production Linux backend must refuse before any native launch boundary"
                );
            };
            let message = error.to_string();
            assert!(
                message.contains(linux_backend::LINUX_CGROUP_V2_SERVICE_UNAVAILABLE),
                "the refusal must carry the exact service-unavailable reason: {message}"
            );
            for control in contained_boundary::required_controls(limits) {
                assert!(
                    message.contains(&format!("{control:?}")),
                    "the refusal must name every unenforceable control, missing {control:?}: {message}"
                );
            }
        }

        /// A root that is not cgroup-v2 can never become a canary domain.
        #[test]
        fn a_canary_domain_refuses_a_root_that_is_not_cgroup_v2() {
            let directory = TestDirectory::new("linux-canary-not-cgroup2");
            let image = sealed_self_image().expect("seal the runner image into a memfd");
            let error = LinuxDelegatedCanaryDomain::reserve(&directory.0, image, Some(4), None)
                .expect_err("an ordinary directory is not a delegated cgroup-v2 root");
            let message = error.to_string();
            assert!(
                message.contains("is not a cgroup-v2 filesystem"),
                "the refusal must name the exact reason: {message}"
            );
        }

        /// Adopting a leaf never creates one, and never removes one.
        ///
        /// This is the ownership change the production canary episode rests
        /// on, asserted where it is cheapest to assert: `adopt` performs no
        /// `mkdirat` at all, so a refused adoption leaves the filesystem
        /// exactly as it found it. A suite that could create the leaf it runs
        /// in could create a cgroup domain no durable generation describes,
        /// which is the door the probe journal exists to keep shut.
        #[test]
        fn adopting_a_canary_leaf_never_creates_the_leaf_it_runs_in() {
            let directory = TestDirectory::new("linux-canary-adopt-no-create");
            let image = sealed_self_image().expect("seal the runner image into a memfd");
            let root = fs::File::open(&directory.0).expect("open the candidate delegation");
            let leaf_name = format!(".gb-probe-{}", "b".repeat(32));
            let error = LinuxDelegatedCanaryDomain::adopt(
                std::os::fd::AsFd::as_fd(&root),
                &leaf_name,
                (1, 2),
                image,
                Some(4),
                None,
            )
            .expect_err("an ordinary directory is not a delegated cgroup-v2 root");
            let message = error.to_string();
            assert!(
                message.contains("is not a cgroup-v2 filesystem"),
                "the refusal must name the exact reason: {message}"
            );
            assert!(
                !directory.0.join(&leaf_name).exists(),
                "adopting must never create the leaf it was asked to adopt"
            );
        }

        /// The complete development suite against a real delegated cgroup.
        ///
        /// Without a delegation this asserts the exact typed refusal that names
        /// the variable a trusted launcher must supply. With one it asserts the
        /// measurements behind every verdict rather than the verdicts alone.
        #[test]
        #[allow(
            clippy::too_many_lines,
            reason = "each control's measurement is asserted next to the verdict it produced"
        )]
        fn the_development_linux_backend_proves_its_controls_in_a_delegated_cgroup_domain() {
            let limits = linux_limits(4);
            let (_workspace, _private, paths, grant, policy, command) =
                contained_fixture("linux-development-backend", limits);
            let prepared = prepare_contained(grant.clone(), policy.clone(), &paths, &command)
                .expect("prepare the contained command for the Linux development backend");
            let Some(delegation_root) = delegation_root_from_environment() else {
                let error = linux_backend::LinuxCgroupV2Backend::development(
                    grant,
                    policy,
                    &paths,
                )
                .expect_err("no delegation means no development backend");
                assert!(
                    error.to_string().contains("GROK_BUILD_CGROUP_ROOT"),
                    "the refusal must name the variable a trusted launcher supplies: {error}"
                );
                return;
            };

            let mut backend = linux_backend::LinuxCgroupV2Backend::development_with_delegation(
                grant,
                policy,
                &paths,
                &delegation_root,
            )
            .expect("compose the development Linux cgroup-v2 backend");
            assert!(backend.development_mode());
            assert_eq!(
                backend.backend_id(),
                linux_backend::LINUX_CGROUP_V2_DEV_BACKEND_ID
            );
            assert!(
                backend.enforced_controls().is_empty(),
                "no control may be claimed before the canary suite has run"
            );

            // The suite runs here. With the Landlock path layer and the
            // seccomp syscall layer applied after fork and before exec, every
            // control `required_controls` demands is established, so the
            // preflight succeeds rather than refusing.
            if let Err(error) = contained_boundary::ContainedCommandBackend::active_preflight(
                &mut backend,
                &prepared,
            ) {
                panic!(
                    "the delegated cgroup domain with both containment layers must prove every \
                     required control: {error}; refusals were {:?}",
                    backend.development_refusals()
                );
            }

            let proven = backend.enforced_controls();
            for control in contained_boundary::required_controls(limits) {
                assert!(
                    proven.contains(&control),
                    "the delegated cgroup domain must prove {control:?}; refusals were {:?}",
                    backend.development_refusals()
                );
            }
            assert_eq!(
                proven.len(),
                12,
                "exactly the twelve required controls are proven, not more: {proven:?}"
            );
            assert!(
                backend.development_refusals().is_empty(),
                "a complete generation records no refusal: {:?}",
                backend.development_refusals()
            );

            // The three layers, exactly as negotiated: Landlock, network
            // seccomp, and the namespace filter. A partially enforced
            // ruleset never reaches this point: the child refuses before exec.
            let containment = backend
                .development_containment()
                .expect("the suite retains what it negotiated")
                .clone();
            assert!(
                containment.landlock_installed
                    && containment.seccomp_installed
                    && containment.namespace_seccomp_installed
            );
            assert_eq!(containment.landlock_required_abi, 4);
            assert!(
                containment.landlock_observed_abi >= containment.landlock_required_abi,
                "a kernel below the required ABI is a typed refusal, never a downgrade: \
                 {containment:?}"
            );
            assert!(
                containment
                    .landlock_write_roots
                    .iter()
                    .any(|root| root.ends_with("/shadow/src")),
                "the compiled write scope must be the only writable root: {:?}",
                containment.landlock_write_roots
            );
            assert!(
                containment
                    .seccomp_denied_syscalls
                    .iter()
                    .any(|name| name == "socket"),
                "the syscall layer must deny endpoint creation: {:?}",
                containment.seccomp_denied_syscalls
            );
            assert!(containment.seccomp_instructions > 0);
            assert_eq!(containment.seccomp_denied_errno, 1);

            // DescendantLimit: the same argument vector under two ceilings.
            let domain = backend
                .development_descendant_domain()
                .expect("the suite retains its descendant measurements")
                .clone();
            assert_eq!(domain.configured_max_processes, 4);
            assert_eq!(domain.read_back_pids_max.trim(), "4");
            assert_eq!(
                domain.control_spawned, 6,
                "an unbounded leaf must run the whole forking vector"
            );
            assert_eq!(
                domain.restricted_spawned, 3,
                "a ceiling of 4 charges the leader and admits exactly 3 descendants"
            );
            assert_eq!(domain.restricted_spawn_errno, Some(11));
            assert!(
                domain.restricted_pids_events.contains("max "),
                "the kernel must record the ceiling event: {:?}",
                domain.restricted_pids_events
            );

            // DescendantDomainKill: a descendant that left both the process
            // group and the session stayed charged to the cgroup, and one write
            // emptied the domain.
            assert_ne!(domain.descendant_process_group, domain.leader_process_group);
            assert_ne!(domain.descendant_session, domain.leader_session);
            assert_eq!(domain.descendant_process_group, domain.descendant_pid);
            assert_eq!(domain.descendant_session, domain.descendant_pid);
            assert!(
                domain.membership_before_kill.contains(&domain.leader_pid)
                    && domain
                        .membership_before_kill
                        .contains(&domain.descendant_pid),
                "both processes must be charged to the leaf: {:?}",
                domain.membership_before_kill
            );
            let kill = domain.kill.clone().expect("the probe performed one kill");
            assert_eq!(kill.kill_value, b"1\n".to_vec());
            assert!(kill.populated_zero, "cgroup.events must report populated 0");
            assert_eq!(kill.stable_empty_reads, 2);
            assert_eq!(kill.surviving_processes, 0);
            assert_eq!(
                domain.settled_pids_current.trim(),
                "0",
                "the kernel's own task charge must settle to zero once the killed \
                 processes are collected"
            );
            assert!(
                domain.host_wide_survivors.is_empty(),
                "no reported process may still be running: {:?}",
                domain.host_wide_survivors
            );

            // ClosedInheritedDescriptors and DescriptorExec.
            let closure = backend
                .development_descriptor_closure()
                .expect("the suite retains its descriptor measurements");
            assert_eq!(closure.target_table, vec![0, 1, 2]);
            assert!(
                closure.controller_descriptors > 3,
                "a table of exactly three is only a shed from a larger one: {}",
                closure.controller_descriptors
            );
            let exec = backend
                .development_exec_source()
                .expect("the suite retains its exec-source measurements");
            assert!(
                exec.sealed_image_link.contains("memfd:"),
                "a sealed image has no pathname anywhere: {}",
                exec.sealed_image_link
            );
            assert!(
                !exec.named_image_link.contains("memfd:")
                    && exec.named_image_link.starts_with('/'),
                "the control image must execute from a real pathname: {}",
                exec.named_image_link
            );

            // FilesystemPolicy and NetworkPolicy: each an A/B pair whose two
            // halves differ in exactly one containment layer. Both halves are
            // asserted, because a refusal observed only under containment
            // says nothing unless the identical run without that one layer
            // succeeded.
            let surface = backend
                .development_unconfined_surface()
                .expect("the suite retains both halves of each pair");
            assert!(!surface.network_mode_allows);

            // Control half: the path layer removed, everything else identical.
            assert_eq!(
                surface.escape_write_succeeded,
                Some(true),
                "without the Landlock layer the canary must still reach the escape path"
            );
            assert!(surface.escape_file_created);
            // Restricted half: the compiled path policy installed.
            assert!(surface.confined_escape_landlock_installed);
            assert_eq!(
                surface.confined_escape_write_succeeded,
                Some(false),
                "with the Landlock layer the same write must be refused"
            );
            assert!(
                matches!(surface.confined_escape_write_errno, Some(1 | 13 | 30)),
                "the refusal must carry a policy-shaped errno, not any failure: {:?}",
                surface.confined_escape_write_errno
            );
            assert!(
                !surface.confined_escape_file_created,
                "a refused write must leave nothing behind"
            );

            // Control half: the syscall layer removed, everything else identical.
            assert!(surface.confined_loopback_seccomp_installed);
            assert_eq!(
                surface.loopback_connect_succeeded,
                Some(true),
                "without the seccomp layer the canary must still reach the listener, errno {:?}",
                surface.loopback_connect_errno
            );
            assert!(
                surface.loopback_listener_accepted,
                "a completed connection must have reached the controller's listener"
            );
            // Restricted half: the compiled network mode is `None`.
            assert_eq!(
                surface.confined_loopback_connect_succeeded,
                Some(false),
                "with the seccomp layer the same connection must be refused"
            );
            assert_eq!(
                surface.confined_loopback_connect_errno,
                Some(1),
                "the filter is compiled to return EPERM, which is deliberately not the EACCES a \
                 denied path produces"
            );
            assert!(
                !surface.confined_loopback_listener_accepted,
                "a refused connection must never have reached the listener"
            );

            // The suite's own evidence, printed under `--nocapture` so a run
            // on a new host reports what it measured rather than only that it
            // passed. Every value here is one the assertions above pinned.
            println!("GBD12 proven={proven:?}");
            println!(
                "GBD12 ActiveCanaries refusals={:?} landlock_abi={}/{} seccomp_instructions={} \
                 seccomp_errno={}",
                backend.development_refusals(),
                containment.landlock_observed_abi,
                containment.landlock_required_abi,
                containment.seccomp_instructions,
                containment.seccomp_denied_errno,
            );
            println!(
                "GBD12 DescendantLimit configured={} pids_max_readback={:?} control_spawned={} \
                 restricted_spawned={} restricted_errno={:?} pids_events={:?}",
                domain.configured_max_processes,
                domain.read_back_pids_max.trim(),
                domain.control_spawned,
                domain.restricted_spawned,
                domain.restricted_spawn_errno,
                domain.restricted_pids_events.trim(),
            );
            println!(
                "GBD12 DescendantDomainKill leader_pid={} leader_pgid={} leader_sid={} \
                 descendant_pid={} descendant_pgid={} descendant_sid={} membership_before={:?} \
                 kill_value={:?} populated_zero={} stable_empty_reads={} survivors={} \
                 settled_pids_current={:?} host_wide_survivors={:?}",
                domain.leader_pid,
                domain.leader_process_group,
                domain.leader_session,
                domain.descendant_pid,
                domain.descendant_process_group,
                domain.descendant_session,
                domain.membership_before_kill,
                String::from_utf8_lossy(&kill.kill_value),
                kill.populated_zero,
                kill.stable_empty_reads,
                kill.surviving_processes,
                domain.settled_pids_current.trim(),
                domain.host_wide_survivors,
            );
            println!(
                "GBD12 ClosedInheritedDescriptors controller_descriptors={} target_table={:?}",
                closure.controller_descriptors, closure.target_table,
            );
            println!(
                "GBD12 DescriptorExec sealed_image_link={:?} named_image_link={:?}",
                exec.sealed_image_link, exec.named_image_link,
            );
            println!(
                "GBD12 FilesystemPolicy control_write={:?} control_file_created={} \
                 confined_landlock_installed={} confined_write={:?} confined_errno={:?} \
                 confined_file_created={} write_roots={:?}",
                surface.escape_write_succeeded,
                surface.escape_file_created,
                surface.confined_escape_landlock_installed,
                surface.confined_escape_write_succeeded,
                surface.confined_escape_write_errno,
                surface.confined_escape_file_created,
                containment.landlock_write_roots,
            );
            println!(
                "GBD12 NetworkPolicy control_connect={:?} control_accepted={} \
                 confined_seccomp_installed={} confined_connect={:?} confined_errno={:?} \
                 confined_accepted={} denied_syscalls={}",
                surface.loopback_connect_succeeded,
                surface.loopback_listener_accepted,
                surface.confined_loopback_seccomp_installed,
                surface.confined_loopback_connect_succeeded,
                surface.confined_loopback_connect_errno,
                surface.confined_loopback_listener_accepted,
                containment.seccomp_denied_syscalls.len(),
            );
            println!(
                "GBD12 remaining_controls_proven_by_membership \
                 ActiveCanaries/ExactArgv/ReplacedEnvironment/DescriptorWorkingDirectory/\
                 ExternalWallClock/CompleteBoundedOutput={}",
                [
                    BackendControl::ActiveCanaries,
                    BackendControl::ExactArgv,
                    BackendControl::ReplacedEnvironment,
                    BackendControl::DescriptorWorkingDirectory,
                    BackendControl::ExternalWallClock,
                    BackendControl::CompleteBoundedOutput,
                ]
                .iter()
                .all(|control| proven.contains(control)),
            );
        }

        /// The descendant verdict tracks the configured ceiling, not a constant.
        ///
        /// Two complete suites differ in exactly one input. If the ceiling were
        /// not kernel enforced the two runs could not differ at all.
        #[test]
        fn the_descendant_ceiling_measurement_tracks_the_configured_value() {
            let Some(delegation_root) = delegation_root_from_environment() else {
                return;
            };
            let mut measurements = Vec::new();
            for max_processes in [1_u32, 3_u32] {
                let limits = linux_limits(max_processes);
                let (_workspace, _private, paths, grant, policy, command) = contained_fixture(
                    &format!("linux-ceiling-{max_processes}"),
                    limits,
                );
                let prepared = prepare_contained(grant.clone(), policy.clone(), &paths, &command)
                    .expect("prepare the contained command for the ceiling comparison");
                let mut backend =
                    linux_backend::LinuxCgroupV2Backend::development_with_delegation(
                        grant,
                        policy,
                        &paths,
                        &delegation_root,
                    )
                    .expect("compose the development Linux cgroup-v2 backend");
                let _refusal = contained_boundary::ContainedCommandBackend::active_preflight(
                    &mut backend,
                    &prepared,
                );
                let domain = backend
                    .development_descendant_domain()
                    .expect("the suite retains its descendant measurements")
                    .clone();
                assert!(
                    backend
                        .enforced_controls()
                        .contains(&BackendControl::DescendantLimit),
                    "a delegated cgroup enforces any finite ceiling; refusals were {:?}",
                    backend.development_refusals()
                );
                measurements.push((max_processes, domain));
            }
            let [(first_ceiling, first), (second_ceiling, second)] = measurements.as_slice() else {
                panic!("the comparison runs exactly two complete suites");
            };
            assert_eq!(*first_ceiling, 1);
            assert_eq!(*second_ceiling, 3);
            assert_eq!(first.read_back_pids_max.trim(), "1");
            assert_eq!(second.read_back_pids_max.trim(), "3");
            assert_eq!(
                first.restricted_spawned, 0,
                "a ceiling of one admits no descendant at all"
            );
            assert_eq!(
                second.restricted_spawned, 2,
                "a ceiling of three admits exactly two descendants"
            );
            assert_eq!(first.restricted_spawn_errno, Some(11));
            assert_eq!(second.restricted_spawn_errno, Some(11));
            assert_eq!(
                first.control_spawned, second.control_spawned,
                "the unbounded control run must be identical in both suites"
            );
        }
    }
