use super::{
    ColimaStartFacts, PLUS_1212_NOT_MAC_NATIVE, PLUS_1212_NOT_NESTED_DOCKER, PLUS_1212_PHASE1_BAR,
    PLUS_GUEST_ACTION_REPAIR_HINTS, PLUS_GUEST_ACTION_START_COLIMA,
    PLUS_GUEST_ACTION_VERIFY_INSTALL, PLUS_GUEST_STATUS_DOWN, PLUS_GUEST_STATUS_READY,
    PLUS_GUEST_STATUS_SERVICE_MISSING, PLUS_PLAN_VALID_PROBE_NAME, Plus1212HostFacts,
    Plus1212HostKind, PlusGuestFacts, PlusGuestLifecycleKind, classify_plus_1212_host,
    classify_plus_guest_lifecycle, colima_start_is_safe, plus_1212_record_from_terminal,
    plus_invalid_dynamic_command, plus_plan_valid_probe_command,
    plus_presentation_is_known_good_terminal, present_install_root_report,
    present_plus_1212_record, present_plus_guest_contained_result,
    present_plus_guest_lifecycle_kind, present_plus_guest_repair_hints,
    present_plus_guest_unavailable_outcome_with_kind, probe_plus_guest_lifecycle,
    verify_install_root,
};

fn plus_contained_path_marker(text: &str) -> bool {
    crate::plus_outcome_is_real_command_terminal(text)
        || text.contains(&containment_reason())
        || text.contains(PLUS_PLAN_VALID_PROBE_NAME)
        || text.contains("/usr/bin/true")
        || text.contains("WorkerRunCommand")
        || text.contains("launch")
        || text.contains("unavailable")
        || text.contains(PLUS_GUEST_STATUS_DOWN)
        || text.contains(PLUS_GUEST_STATUS_SERVICE_MISSING)
        || text.contains(PLUS_GUEST_STATUS_READY)
}

#[test]
fn plus_plan_valid_probe_is_absolute_and_not_dynamic_true() {
    let command = plus_plan_valid_probe_command().expect("build plan-valid probe");
    assert!(
        command.program.ends_with(PLUS_PLAN_VALID_PROBE_NAME)
            && std::path::Path::new(&command.program).is_absolute()
            && std::path::Path::new(&command.program).is_file(),
        "plan-valid probe must be an absolute file, got {}",
        command.program
    );
    assert_ne!(
        command.program, "/usr/bin/true",
        "plan-valid probe must not be dynamic /usr/bin/true"
    );
    #[cfg(target_os = "linux")]
    {
        grok_build_runner::measure_static_elf_linkage_v1(std::path::Path::new(&command.program))
            .expect("plan-valid probe must measure as a static ELF");
    }
}

#[test]
fn immutable_prebuilt_probe_is_verified_without_source_write_and_tampering_refuses() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = unique_folder();
    let probe = root.join(PLUS_PLAN_VALID_PROBE_NAME);
    let bytes = b"immutable contained probe fixture";
    fs::write(&probe, bytes).expect("write prebuilt fixture");
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o555)).expect("lock fixture mode");
    let digest = grok_build_core::Digest::sha256(bytes);
    super::plus_probe::validate_prebuilt_probe(
        &probe,
        bytes.len() as u64,
        digest.as_str(),
        false,
    )
    .expect("accept exact immutable prebuilt probe");
    assert!(!root.join("plus-contained-probe.rs").exists());

    let wrong_digest = "0000000000000000000000000000000000000000000000000000000000000000";
    assert!(
        super::plus_probe::validate_prebuilt_probe(
            &probe,
            bytes.len() as u64,
            wrong_digest,
            false,
        )
        .unwrap_err()
        .contains("checksum changed")
    );
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).expect("weaken fixture mode");
    assert!(
        super::plus_probe::validate_prebuilt_probe(
            &probe,
            bytes.len() as u64,
            digest.as_str(),
            false,
        )
        .unwrap_err()
        .contains("mode must be 0555")
    );
    let alias = root.join("probe-alias");
    symlink(&probe, &alias).expect("create probe symlink");
    assert!(
        super::plus_probe::validate_prebuilt_probe(
            &alias,
            bytes.len() as u64,
            digest.as_str(),
            false,
        )
        .unwrap_err()
        .contains("absolute and canonical")
    );
}

#[test]
fn plus_invalid_dynamic_command_stays_usr_bin_true() {
    let command = plus_invalid_dynamic_command();
    assert_eq!(command.program, "/usr/bin/true");
    assert!(
        command
            .arguments
            .iter()
            .any(|arg| arg == "--grok-build-plus")
    );
}

#[test]
fn known_good_and_invalid_presentations_are_distinct() {
    let succeeded = present_command_termination(CommandTerminationV1::Exited { code: 0 });
    let timed_out = present_command_termination(CommandTerminationV1::TimedOut);
    assert!(
        plus_presentation_is_known_good_terminal(&succeeded)
            && succeeded.contains("Command succeeded"),
        "exit 0 must present Command succeeded: {succeeded}"
    );
    assert!(
        plus_presentation_is_known_good_terminal(&timed_out)
            && timed_out.contains("Command timed out"),
        "TimedOut must present Command timed out: {timed_out}"
    );
    let failed = "Command failed (BeforeEffect)\nworker command: /usr/bin/true --grok-build-plus";
    assert!(
        crate::plus_outcome_is_real_command_terminal(failed)
            && !plus_presentation_is_known_good_terminal(failed)
            && !failed.contains("Command succeeded"),
        "invalid-target BeforeEffect must stay an honest failure: {failed}"
    );
}

#[test]
fn plus_gui_contained_entries_drive_plan_valid_or_honest_failure() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let run = plus_gui_contained_command(&bound);
    let checks = plus_run_checks_after_accept(&bound);
    for (label, text) in [("Run", &run), ("checks", &checks)] {
        assert!(
            plus_contained_path_marker(text),
            "{label} must stay on the shipped contained entry: {text}"
        );
        assert!(
            !text.contains("FakeProvider"),
            "{label} must not use FakeProvider as exec: {text}"
        );
        assert!(
            !text.contains("12/12 achieved") && !text.contains("this is 12/12"),
            "{label} must not claim 12/12: {text}"
        );
        if plus_presentation_is_known_good_terminal(text) {
            assert!(
                text.contains(PLUS_GUEST_STATUS_READY),
                "{label} known-good guest must say ready: {text}"
            );
        } else {
            assert!(
                (text.contains(PLUS_GUEST_STATUS_DOWN)
                    || text.contains(PLUS_GUEST_STATUS_SERVICE_MISSING))
                    && !text.contains("Command succeeded"),
                "{label} refusal must preserve its own captured guest state and stay non-success: {text}"
            );
        }
        assert!(
            !(text.contains(PLUS_GUEST_STATUS_READY)
                && text.contains("/usr/bin/true")
                && text.contains("BeforeEffect")
                && !text.contains(PLUS_PLAN_VALID_PROBE_NAME)),
            "{label} ready guest must not be only BeforeEffect on /usr/bin/true: {text}"
        );
    }
}

#[test]
fn classify_guest_lifecycle_uses_the_three_status_words() {
    let down = classify_plus_guest_lifecycle(&PlusGuestFacts {
        on_linux: false,
        colima_present: false,
        colima_running: false,
        install_root_has_handoff: false,
        runner_present: false,
        helper_present: false,
        harness_cgroup_usable: false,
    });
    assert_eq!(down, PlusGuestLifecycleKind::GuestDown);
    assert_eq!(
        present_plus_guest_lifecycle_kind(down),
        PLUS_GUEST_STATUS_DOWN
    );
    let missing = classify_plus_guest_lifecycle(&PlusGuestFacts {
        on_linux: false,
        colima_present: true,
        colima_running: true,
        install_root_has_handoff: false,
        runner_present: true,
        helper_present: true,
        harness_cgroup_usable: true,
    });
    assert_eq!(missing, PlusGuestLifecycleKind::ServiceMissing);
    assert_eq!(
        present_plus_guest_lifecycle_kind(missing),
        PLUS_GUEST_STATUS_SERVICE_MISSING
    );
    let linux_without_harness = classify_plus_guest_lifecycle(&PlusGuestFacts {
        on_linux: true,
        colima_present: false,
        colima_running: false,
        install_root_has_handoff: true,
        runner_present: true,
        helper_present: false,
        harness_cgroup_usable: false,
    });
    assert_eq!(
        linux_without_harness,
        PlusGuestLifecycleKind::ServiceMissing,
        "install+runner without a usable sibling harness is not ready"
    );
    let ready = classify_plus_guest_lifecycle(&PlusGuestFacts {
        on_linux: true,
        colima_present: false,
        colima_running: false,
        install_root_has_handoff: true,
        runner_present: true,
        helper_present: false,
        harness_cgroup_usable: true,
    });
    assert_eq!(ready, PlusGuestLifecycleKind::Ready);
    assert_eq!(
        present_plus_guest_lifecycle_kind(ready),
        PLUS_GUEST_STATUS_READY
    );
}

#[test]
fn installed_service_launch_sets_probe_compatible_umask() {
    let source = include_str!("../lib.rs");
    assert!(
        source.contains("plus_set_probe_compatible_umask")
            && source.contains("Mode::WGRP")
            && source.contains("plus_set_probe_compatible_umask();"),
        "installed-service launch must set umask 0022 so probe children are 0755"
    );
}

#[test]
fn harness_cgroup_join_is_the_shipped_function() {
    let can = super::plus_harness_cgroup_can_be_joined();
    #[cfg(target_os = "macos")]
    assert!(!can, "this Mac process has no /sys/fs/cgroup harness");
    let _ = super::plus_process_is_in_harness_cgroup();
    let joined = super::plus_join_sibling_harness_cgroup();
    #[cfg(target_os = "macos")]
    assert!(
        joined.is_err(),
        "Mac must not fake a Linux harness join: {joined:?}"
    );
    #[cfg(target_os = "linux")]
    if joined.is_ok() {
        assert!(
            super::plus_process_is_in_harness_cgroup(),
            "A successful join must have observable membership (preflight={can})"
        );
    }
}

#[test]
fn contained_result_stamps_ready_only_on_known_good() {
    let succeeded = "Command succeeded: Exited { code: 0 }\nworker command: plus-contained-probe --grok-build-plus";
    let ready = present_plus_guest_contained_result(super::PlusGuestKind::Local, succeeded);
    assert!(
        ready.contains(PLUS_GUEST_STATUS_READY) && plus_presentation_is_known_good_terminal(&ready),
        "known-good must be labeled ready: {ready}"
    );
    let failed = "Command failed (BeforeEffect/ContainmentUnavailable)\nworker command: plus-contained-probe --grok-build-plus";
    let missing = present_plus_guest_contained_result(super::PlusGuestKind::Local, failed);
    assert!(
        missing.contains(PLUS_GUEST_STATUS_SERVICE_MISSING),
        "containment failure must say service missing: {missing}"
    );
    assert!(
        missing.contains("Command failed"),
        "containment failure must keep the honest Command failed: {missing}"
    );
    assert!(
        !plus_presentation_is_known_good_terminal(&missing),
        "containment failure must not look known-good: {missing}"
    );
    assert!(
        !missing.lines().any(|line| line == PLUS_GUEST_STATUS_READY),
        "containment failure must not stamp the ready status word: {missing}"
    );
}

#[test]
fn unavailable_backend_does_not_present_fake_green() {
    let presented = present_plus_guest_unavailable_outcome_with_kind(
        PlusGuestLifecycleKind::GuestDown,
        "Command succeeded: Exited { code: 0 }",
        &PlusGuestUnavailable {
            reasons: vec!["colima is not running (`colima start`)".into()],
        },
    );
    assert!(
        presented.contains(PLUS_GUEST_STATUS_DOWN),
        "down copy must say guest down: {presented}"
    );
    assert!(
        !plus_presentation_is_known_good_terminal(&presented),
        "guest down must not present a fake success terminal: {presented}"
    );
    assert!(
        presented.contains(PLUS_GUEST_ACTION_START_COLIMA)
            && presented.contains(PLUS_GUEST_ACTION_VERIFY_INSTALL)
            && presented.contains(PLUS_GUEST_ACTION_REPAIR_HINTS),
        "down copy must name the three actions: {presented}"
    );
}

#[test]
fn start_colima_if_safe_refuses_missing_running_and_unconfigured() {
    assert!(
        colima_start_is_safe(&ColimaStartFacts {
            colima_present: false,
            colima_running: false,
            colima_home_set: true,
            colima_home_exists: true,
            foreign_profile_conflict: false,
        })
        .is_err(),
        "missing colima must be unsafe"
    );
    assert!(
        colima_start_is_safe(&ColimaStartFacts {
            colima_present: true,
            colima_running: true,
            colima_home_set: true,
            colima_home_exists: true,
            foreign_profile_conflict: false,
        })
        .is_err(),
        "already running must be unsafe"
    );
    assert!(
        colima_start_is_safe(&ColimaStartFacts {
            colima_present: true,
            colima_running: false,
            colima_home_set: false,
            colima_home_exists: false,
            foreign_profile_conflict: false,
        })
        .is_err(),
        "unset COLIMA_HOME must be unsafe"
    );
    assert!(
        colima_start_is_safe(&ColimaStartFacts {
            colima_present: true,
            colima_running: false,
            colima_home_set: true,
            colima_home_exists: true,
            foreign_profile_conflict: true,
        })
        .is_err(),
        "foreign profile must be unsafe"
    );
    assert!(
        colima_start_is_safe(&ColimaStartFacts {
            colima_present: true,
            colima_running: false,
            colima_home_set: true,
            colima_home_exists: true,
            foreign_profile_conflict: false,
        })
        .is_ok(),
        "opted-in stopped profile must be safe"
    );
}

#[test]
fn colima_children_use_an_exact_nonsecret_environment() {
    let mut command = std::process::Command::new("/usr/bin/true");
    command.env("XAI_API_KEY", "must-not-survive");
    crate::plus_lifecycle::apply_colima_child_environment(&mut command);
    let keys = command
        .get_envs()
        .filter_map(|(name, value)| value.map(|_| name.to_string_lossy().into_owned()))
        .collect::<Vec<_>>();

    for forbidden in ["XAI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
        assert!(!keys.iter().any(|name| name == forbidden));
    }
    assert!(keys.iter().all(|name| matches!(
        name.as_str(),
        "COLIMA_HOME" | "HOME" | "LANG" | "LC_ALL" | "LC_CTYPE" | "LOGNAME"
            | "PATH" | "SHELL" | "TMPDIR" | "USER" | "XDG_CONFIG_HOME"
    )));
    let path = command
        .get_envs()
        .find(|(name, _)| *name == "PATH")
        .and_then(|(_, value)| value);
    assert_eq!(
        path,
        Some(std::ffi::OsStr::new(
            crate::plus_lifecycle::COLIMA_BASE_PATH
        ))
    );
}

#[test]
fn managed_colima_uses_only_the_exact_lima_path_and_app_profile() {
    let managed = crate::managed_container_runtime_root().join(crate::PLUS_MANAGED_COLIMA_RELATIVE);
    let mut command = std::process::Command::new(&managed);
    command.env("XAI_API_KEY", "must-not-survive");
    crate::plus_lifecycle::apply_colima_child_environment(&mut command);
    let environment = command
        .get_envs()
        .filter_map(|(name, value)| {
            value.map(|value| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    assert!(!environment.contains_key("XAI_API_KEY"));
    let expected_home = crate::managed_colima_home().to_string_lossy().into_owned();
    assert_eq!(
        environment.get("COLIMA_HOME").map(String::as_str),
        Some(expected_home.as_str())
    );
    let first_path = environment
        .get("PATH")
        .and_then(|path| std::env::split_paths(path).next());
    let expected_lima = crate::managed_container_runtime_root().join("lima/bin");
    assert_eq!(first_path.as_deref(), Some(expected_lima.as_path()));
    assert!(environment["PATH"].ends_with(crate::plus_lifecycle::COLIMA_BASE_PATH));
}

#[test]
fn verify_install_root_reports_missing_handoff_honestly() {
    let folder = unique_folder();
    let report = verify_install_root(&folder);
    assert!(!report.handoff_present, "empty folder has no handoff");
    let presented = present_install_root_report(&report);
    assert!(
        presented.contains(PLUS_GUEST_ACTION_VERIFY_INSTALL)
            && presented.contains("missing handoff"),
        "missing handoff must be named: {presented}"
    );
}

#[test]
fn repair_hints_name_actions_when_not_ready() {
    let down = present_plus_guest_repair_hints(PlusGuestLifecycleKind::GuestDown);
    assert!(
        down.contains(PLUS_GUEST_ACTION_REPAIR_HINTS) && down.contains(PLUS_GUEST_STATUS_DOWN),
        "guest-down hints: {down}"
    );
    let missing = present_plus_guest_repair_hints(PlusGuestLifecycleKind::ServiceMissing);
    assert!(
        missing.contains("Set up container")
            && missing.contains(PLUS_GUEST_STATUS_SERVICE_MISSING),
        "service-missing hints: {missing}"
    );
}

#[test]
fn plus_1212_record_never_claims_mac_native_or_nested_docker() {
    let mac = plus_1212_record_from_terminal(
        Plus1212HostKind::MacNative,
        "Command succeeded\npermit minted\npreflight_digest=aa\nlaunch_digest=bb",
    );
    assert!(!mac.claimed_12_12, "Mac native must not claim 12/12");
    let presented = present_plus_1212_record(&mac);
    assert!(
        presented.contains(PLUS_1212_NOT_MAC_NATIVE)
            && presented.contains(PLUS_1212_NOT_NESTED_DOCKER)
            && presented.contains(PLUS_1212_PHASE1_BAR)
            && presented.contains("12/12 not claimed"),
        "Mac record must cite the bar and refuse 12/12: {presented}"
    );
    let docker = plus_1212_record_from_terminal(
        Plus1212HostKind::NestedDocker,
        "CommandCompleted TimedOut permit minted preflight_digest=aa launch_digest=bb",
    );
    assert!(!docker.claimed_12_12, "nested Docker must not claim 12/12");
    let sibling = plus_1212_record_from_terminal(
        Plus1212HostKind::SiblingLayout,
        "Command timed out: TimedOut\npermit minted\npreflight_digest=aa\nlaunch_digest=bb",
    );
    assert!(
        sibling.claimed_12_12 && sibling.minted_permit,
        "sibling-layout minted TimedOut may record 12/12"
    );
    assert_eq!(
        classify_plus_1212_host(&Plus1212HostFacts {
            on_macos: true,
            nested_docker: false,
            install_root_has_handoff: true,
            cgroup_v2: true,
            installer_uid_differs: true,
            parent_cgroup_procs_delegated: true,
        }),
        Plus1212HostKind::MacNative
    );
}

#[test]
fn plus_1212_helper_and_probe_sources_stay_off_1_05_authority() {
    for source in [
        include_str!("../lib.rs"),
        include_str!("../plus_guest.rs"),
        include_str!("../plus_probe.rs"),
        include_str!("../plus_proof.rs"),
        include_str!("../plus_lifecycle.rs"),
        include_str!("../../../grok-build-desktop/src/plus_window.rs"),
        include_str!("../../../grok-build-desktop/src/main.rs"),
    ] {
        assert!(
            !source.contains("PermissionClassifier") && !source.contains("SandboxManager"),
            "plus 33-37 sources must not treat 1.05 apply types as authority"
        );
        assert!(
            !source.contains("ValidatedBackendPermit") && !source.contains("validate_preflight"),
            "plus must not mint the runner permit on the desktop"
        );
        assert!(
            !source.contains("launch_with_native_service"),
            "plus must not call the held-child native launch client"
        );
    }
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    for needle in [
        PLUS_GUEST_STATUS_DOWN,
        PLUS_GUEST_STATUS_SERVICE_MISSING,
        PLUS_GUEST_STATUS_READY,
        PLUS_GUEST_ACTION_START_COLIMA,
        PLUS_GUEST_ACTION_VERIFY_INSTALL,
        PLUS_GUEST_ACTION_REPAIR_HINTS,
    ] {
        assert!(
            window.contains(needle),
            "window source must contain {needle}"
        );
    }
    let main = include_str!("../../../grok-build-desktop/src/main.rs");
    assert!(
        main.contains("--plus-1212-proof"),
        "one-click 12/12 helper must be the grok-build flag"
    );
}

#[test]
fn ready_copy_still_names_colima_and_installed_session() {
    let terminal = "Command succeeded: Exited { code: 0 }\npermit minted";
    let remote = present_plus_guest_available_outcome(PlusGuestKind::Remote, terminal);
    assert!(
        remote.contains(PLUS_GUEST_STATUS_READY) && remote.contains("colima ssh"),
        "ready remote copy: {remote}"
    );
    assert!(
        plus_presentation_is_known_good_terminal(&remote) || remote.contains("Command succeeded")
    );
}
