use super::{
    PLUS_COMMAND_SECURITY, PLUS_COMMAND_SECURITY_LEGEND, PLUS_COMMAND_SECURITY_NEEDS_ATTENTION,
    PLUS_COMMAND_SECURITY_OFF, PLUS_COMMAND_SECURITY_ON, PLUS_COMMAND_SECURITY_SETTING_UP,
    PLUS_EXTRA_SECURITY, PLUS_NOT_NOW, PLUS_TURN_ON_EXTRA_SECURITY, PlusCommandSecurityKind,
    PlusCommandSecurityPreference, PlusGuestLifecycle, classify_command_security,
    parse_command_security_preference, plus_contained_command_with_security,
    plus_gui_contained_command_and_remember, present_command_security_contained_outcome,
    present_command_security_panel, present_command_security_status,
};

fn guest_down_lifecycle() -> PlusGuestLifecycle {
    PlusGuestLifecycle::GuestDown {
        reasons: vec!["stack absent for fixture".into()],
    }
}

fn service_missing_lifecycle() -> PlusGuestLifecycle {
    PlusGuestLifecycle::ServiceMissing {
        reasons: vec!["install root missing for fixture".into()],
    }
}

#[test]
fn plus_command_security_classifies_off_setting_up_on_needs_attention() {
    assert_eq!(
        classify_command_security(
            PlusCommandSecurityPreference::Off,
            PlusGuestLifecycleKind::GuestDown,
            false
        ),
        PlusCommandSecurityKind::Off
    );
    assert_eq!(
        classify_command_security(
            PlusCommandSecurityPreference::Off,
            PlusGuestLifecycleKind::Ready,
            false
        ),
        PlusCommandSecurityKind::Off,
        "a present stack does not turn Off into On"
    );
    assert_eq!(
        classify_command_security(
            PlusCommandSecurityPreference::Extra,
            PlusGuestLifecycleKind::GuestDown,
            true
        ),
        PlusCommandSecurityKind::SettingUp
    );
    assert_eq!(
        classify_command_security(
            PlusCommandSecurityPreference::Extra,
            PlusGuestLifecycleKind::Ready,
            false
        ),
        PlusCommandSecurityKind::On
    );
    assert_eq!(
        classify_command_security(
            PlusCommandSecurityPreference::Extra,
            PlusGuestLifecycleKind::ServiceMissing,
            false
        ),
        PlusCommandSecurityKind::NeedsAttention
    );
    assert_eq!(
        parse_command_security_preference(""),
        PlusCommandSecurityPreference::Off
    );
    assert_eq!(
        parse_command_security_preference("extra\n"),
        PlusCommandSecurityPreference::Extra
    );
}

#[test]
fn plus_command_security_presenters_use_locked_phrases() {
    for (kind, word) in [
        (PlusCommandSecurityKind::Off, PLUS_COMMAND_SECURITY_OFF),
        (
            PlusCommandSecurityKind::SettingUp,
            PLUS_COMMAND_SECURITY_SETTING_UP,
        ),
        (PlusCommandSecurityKind::On, PLUS_COMMAND_SECURITY_ON),
        (
            PlusCommandSecurityKind::NeedsAttention,
            PLUS_COMMAND_SECURITY_NEEDS_ATTENTION,
        ),
    ] {
        let status = present_command_security_status(kind);
        assert_eq!(
            status,
            format!("{PLUS_COMMAND_SECURITY}: {word}"),
            "status must be the locked phrase, got {status}"
        );
        let panel = present_command_security_panel(kind);
        assert!(
            panel.contains(&status) && panel.contains(PLUS_EXTRA_SECURITY),
            "panel must name the status and extra security: {panel}"
        );
    }
    assert_eq!(
        PLUS_COMMAND_SECURITY_LEGEND,
        "Command security: Off | Setting up | On | Needs attention"
    );
    let window = include_str!("../../../grok-build-desktop/src/plus_window.rs");
    assert!(
        window.contains(PLUS_TURN_ON_EXTRA_SECURITY)
            && window.contains(PLUS_NOT_NOW)
            && window.contains(PLUS_COMMAND_SECURITY_LEGEND)
            && window.contains("turn-on-extra-security")
            && window.contains("not-now"),
        "window must offer Turn on extra security vs Not now"
    );
}

#[test]
fn plus_command_security_off_and_broken_run_never_look_secured() {
    let poisoned = "Command succeeded (Exited { code: 0 })\npermit minted";
    let off = present_command_security_contained_outcome(PlusCommandSecurityKind::Off, poisoned);
    assert!(
        off.contains("Command security: Off")
            && off.contains(PLUS_EXTRA_SECURITY)
            && off.contains("not fully isolated")
            && off.contains(PLUS_REFUSAL_NOT_SUCCESS)
            && off.contains(PLUS_TURN_ON_EXTRA_SECURITY)
            && !off.contains("Command succeeded")
            && !off.contains("Command security: On"),
        "Off must refuse a poisoned success: {off}"
    );

    let setting_up = present_command_security_contained_outcome(
        PlusCommandSecurityKind::SettingUp,
        poisoned,
    );
    assert!(
        setting_up.contains("Command security: Setting up")
            && setting_up.contains(PLUS_REFUSAL_NOT_SUCCESS)
            && !setting_up.contains("Command succeeded")
            && !setting_up.contains("Command security: On"),
        "Setting up must refuse a poisoned success: {setting_up}"
    );

    let broken = present_command_security_contained_outcome(
        PlusCommandSecurityKind::NeedsAttention,
        poisoned,
    );
    assert!(
        broken.contains("Command security: Needs attention")
            && broken.contains(PLUS_REFUSAL_NOT_SUCCESS)
            && !broken.contains("Command succeeded")
            && !broken.contains("Command security: On"),
        "Needs attention must refuse a poisoned success: {broken}"
    );

    let on = present_command_security_contained_outcome(PlusCommandSecurityKind::On, poisoned);
    assert!(
        on.contains("Command security: On") && on.contains("Command succeeded"),
        "On may present a real stack success: {on}"
    );
}

#[test]
fn plus_contained_command_with_security_off_does_not_use_the_stack() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let off = plus_contained_command_with_security(
        &bound,
        PlusCommandSecurityPreference::Off,
        false,
        &guest_down_lifecycle(),
    );
    assert!(
        off.contains("Command security: Off")
            && off.contains("not fully isolated")
            && !off.contains("Command succeeded")
            && !off.contains("Command security: On"),
        "Off contained path must refuse: {off}"
    );

    let setting_up = plus_contained_command_with_security(
        &bound,
        PlusCommandSecurityPreference::Extra,
        true,
        &guest_down_lifecycle(),
    );
    assert!(
        setting_up.contains("Command security: Setting up")
            && !setting_up.contains("Command succeeded")
            && !setting_up.contains("Command security: On"),
        "Setting up contained path must refuse: {setting_up}"
    );

    let broken = plus_contained_command_with_security(
        &bound,
        PlusCommandSecurityPreference::Extra,
        false,
        &service_missing_lifecycle(),
    );
    assert!(
        broken.contains("Command security: Needs attention")
            && !broken.contains("Command succeeded")
            && !broken.contains("Command security: On"),
        "Needs attention contained path must refuse: {broken}"
    );
}

#[test]
fn plus_accept_writes_without_command_security_on() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let store = PlusSessionStore::from_state_root(unique_state_root());
    assert_eq!(
        store.command_security_preference(),
        PlusCommandSecurityPreference::Off
    );
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let relative = std::path::PathBuf::from(format!("accept-off-{unique}.txt"));
    let after = format!("accepted-without-on-{unique}\n");
    let proposal =
        propose_pending_file(&bound, &relative, after.clone().into_bytes()).expect("propose");
    assert!(
        !folder.join(&relative).exists(),
        "propose must not write before Accept"
    );
    accept_pending_file_proposal(&bound, &proposal).expect("accept");
    assert_eq!(
        fs::read_to_string(folder.join(&relative)).expect("accepted bytes"),
        after,
        "Accept must write the proposed after bytes with Command security Off"
    );
    store
        .remember_command_security_preference(PlusCommandSecurityPreference::Off)
        .expect("persist Off");
    assert_eq!(
        store.command_security_preference(),
        PlusCommandSecurityPreference::Off
    );
    store
        .remember_command_security_preference(PlusCommandSecurityPreference::Extra)
        .expect("persist Extra");
    assert_eq!(
        PlusSessionStore::from_state_root(store.state_root()).command_security_preference(),
        PlusCommandSecurityPreference::Extra
    );
}

#[test]
fn plus_gui_contained_command_and_remember_defaults_to_off() {
    let folder = unique_folder();
    let bound = bind_project_folder(&folder).expect("bind");
    let store = PlusSessionStore::from_state_root(unique_state_root());
    let outcome = plus_gui_contained_command_and_remember(&store, &bound);
    assert!(
        outcome.contains("Command security: Off")
            && outcome.contains("not fully isolated")
            && !outcome.contains("Command succeeded")
            && !outcome.contains("Command security: On"),
        "remembered Run with no first-run choice must be Off: {outcome}"
    );
}
