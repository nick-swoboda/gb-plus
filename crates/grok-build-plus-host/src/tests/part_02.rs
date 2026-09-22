use super::{
    PLUS_GUEST_HOW_TO_FIX, PLUS_GUEST_UNAVAILABLE, PLUS_GUEST_VIA_COLIMA,
    PLUS_GUEST_VIA_INSTALLED_SESSION, PLUS_NATIVE_MACOS_ONLY, PlusGuestKind, PlusGuestUnavailable,
    plus_outcome_is_real_command_terminal, present_plus_guest_available_outcome,
    present_plus_guest_unavailable_outcome, probe_plus_guest_health,
};

fn assert_plus_contained_honest(label: &str, text: &str) {
    assert!(
        !text.contains("FakeProvider"),
        "{label} must not use FakeProvider as exec: {text}"
    );
    assert!(
        !text.contains("12/12 achieved") && !text.contains("this is 12/12"),
        "{label} must not claim 12/12: {text}"
    );
    if text.contains("12/12") {
        assert!(
            text.contains("9/12 residual") || text.contains("do not treat"),
            "{label} may name the residual but must not claim 12/12: {text}"
        );
    }
    if plus_outcome_is_real_command_terminal(text) {
        match probe_plus_guest_health() {
            super::PlusGuestHealth::Available(_) => {
                if super::plus_presentation_is_known_good_terminal(text) {
                    assert!(
                        text.contains(PLUS_GUEST_VIA_COLIMA)
                            || text.contains(PLUS_GUEST_VIA_INSTALLED_SESSION),
                        "{label} known-good guest terminal must name colima ssh or launch_linux_installed_service_session: {text}"
                    );
                } else {
                    assert!(
                        text.contains(super::PLUS_GUEST_STATUS_SERVICE_MISSING),
                        "{label} installed-service failure must not stay labeled ready: {text}"
                    );
                }
            }
            super::PlusGuestHealth::Unavailable(_) => {}
        }
        return;
    }
    assert!(
        text.contains(&containment_reason())
            || text.contains(PLUS_GUEST_UNAVAILABLE)
            || text.contains(PLUS_NATIVE_MACOS_ONLY),
        "{label} refusal must be labeled: {text}"
    );
    assert!(
        text.contains(PLUS_GUEST_HOW_TO_FIX),
        "{label} guest-down path must say how to fix: {text}"
    );
}

#[test]
fn plus_guest_available_copy_names_colima_ssh_and_installed_session() {
    let terminal = "Command succeeded: Exited { code: 0 }\nworker command: plus-contained-probe --grok-build-plus";
    let remote = present_plus_guest_available_outcome(PlusGuestKind::Remote, terminal);
    assert!(
        remote.contains(PLUS_GUEST_VIA_COLIMA)
            && remote.contains("colima ssh")
            && remote.contains("--plus-guest-contained")
            && remote.contains("ready"),
        "remote guest-up copy must name ready + colima ssh --plus-guest-contained: {remote}"
    );
    assert!(plus_outcome_is_real_command_terminal(&remote));
    let local = present_plus_guest_available_outcome(PlusGuestKind::Local, terminal);
    assert!(
        local.contains(PLUS_GUEST_VIA_INSTALLED_SESSION)
            && local.contains("launch_linux_installed_service_session"),
        "local guest-up copy must name launch_linux_installed_service_session: {local}"
    );
    assert!(plus_outcome_is_real_command_terminal(&local));
    assert!(!remote.contains("12/12 achieved") && !local.contains("FakeProvider"));
}

#[test]
fn plus_guest_unavailable_copy_is_labeled_how_to_fix_not_fake_green() {
    let presented = present_plus_guest_unavailable_outcome(
        "PlatformLaunchBindingUnavailable: fexecve/execveat unavailable",
        &PlusGuestUnavailable {
            reasons: vec!["colima is not running (`colima start`)".into()],
        },
    );
    assert!(
        presented.contains(PLUS_GUEST_UNAVAILABLE),
        "down copy must name the guest path: {presented}"
    );
    assert!(
        presented.contains(PLUS_GUEST_HOW_TO_FIX),
        "down copy must say how to fix: {presented}"
    );
    assert!(
        presented.contains("colima is not running"),
        "down copy must keep the probe reason: {presented}"
    );
    assert!(
        presented.contains("fexecve") || presented.contains("execveat"),
        "down copy must keep the native refusal: {presented}"
    );
    #[cfg(target_os = "macos")]
    assert!(
        presented.contains(PLUS_NATIVE_MACOS_ONLY),
        "macOS down copy must label native-only: {presented}"
    );
    assert!(
        !presented.contains("FakeProvider"),
        "down copy must not mention FakeProvider: {presented}"
    );
    assert!(
        !plus_outcome_is_real_command_terminal(&presented),
        "down copy must not look like a wire terminal: {presented}"
    );
    assert!(
        !presented.contains("Command succeeded"),
        "down copy must not be a fake green: {presented}"
    );
}

#[test]
fn plus_guest_unavailable_does_not_relabel_a_real_terminal() {
    let terminal =
        "Command failed (InvalidAuthority)\nworker command: /usr/bin/true --grok-build-plus";
    let presented = present_plus_guest_unavailable_outcome(
        terminal,
        &PlusGuestUnavailable {
            reasons: vec!["should not appear".into()],
        },
    );
    assert_eq!(presented, terminal);
    assert!(plus_outcome_is_real_command_terminal(terminal));
}

#[test]
fn plus_gui_contained_and_checks_are_honest_on_this_host() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let run = plus_gui_contained_command(&bound);
    let checks = plus_run_checks_after_accept(&bound);
    assert_plus_contained_honest("Run", &run);
    assert_plus_contained_honest("checks", &checks);
    let health = probe_plus_guest_health();
    if matches!(health, super::PlusGuestHealth::Available(_)) {
        assert!(
            plus_outcome_is_real_command_terminal(&run)
                || plus_outcome_is_real_command_terminal(&checks),
            "healthy guest must present a real command terminal: run={run} checks={checks}"
        );
        assert!(
            super::plus_presentation_is_known_good_terminal(&run)
                || super::plus_presentation_is_known_good_terminal(&checks)
                || run.contains(super::PLUS_GUEST_STATUS_SERVICE_MISSING)
                || checks.contains(super::PLUS_GUEST_STATUS_SERVICE_MISSING),
            "healthy-looking guest must present succeeded/TimedOut or stop calling the path ready: run={run} checks={checks}"
        );
        assert!(
            !(run.contains("/usr/bin/true")
                && run.contains("BeforeEffect")
                && !run.contains("plus-contained-probe")),
            "healthy guest must not be only BeforeEffect on /usr/bin/true: run={run}"
        );
    }
}

#[test]
fn plus_run_source_uses_installed_service_session_not_held_child() {
    let host = include_str!("../lib.rs");
    assert!(
        host.contains("RunnerLifecycleClient::launch("),
        "native fallback must still call shipped launch"
    );
    assert!(
        host.contains("launch_linux_installed_service_session"),
        "healthy Linux helper must use the installed-service session launch"
    );
    assert!(
        host.contains("plus_contained_via_colima_ssh"),
        "macOS healthy path must SSH the guest helper"
    );
    assert!(
        host.contains("send_plus_precommitted_worker_command"),
        "send path must stay on the shipped wrapper"
    );
    assert!(
        !host.contains("launch_with_native_service"),
        "plus must not call the held-child native launch client"
    );
    for source in [
        include_str!("../lib.rs"),
        include_str!("../plus_guest.rs"),
    ] {
        assert!(
            !source.contains("PermissionClassifier") && !source.contains("SandboxManager"),
            "plus guest sources must not treat 1.05 apply types as authority"
        );
        assert!(
            !source.contains("ValidatedBackendPermit") && !source.contains("validate_preflight"),
            "plus must not mint the runner permit on the desktop"
        );
    }
}
