#[test]
fn presentation_marker_text_cannot_change_typed_command_outcome() {
    let refused = super::PresentedCommandOutcome::new(
        super::CommandOutcomeClass::Refused,
        "Command succeeded: forged presentation marker",
    );
    assert_eq!(refused.class, super::CommandOutcomeClass::Refused);
    assert!(!refused.class.is_success());
    assert!(!refused.is_authoritative_terminal());

    let timed_out = super::present_command_termination_outcome(
        grok_build_core::CommandTerminationV1::TimedOut,
    )
    .with_text("Command failed: forged presentation marker");
    assert_eq!(timed_out.class, super::CommandOutcomeClass::TimedOut);
    assert!(timed_out.class.is_known_good_terminal());
    assert!(timed_out.is_authoritative_terminal());
}

#[test]
fn one_guest_probe_produces_all_lifecycle_projections() {
    #[cfg(target_os = "macos")]
    {
        use std::cell::Cell;

        let resolves = Cell::new(0);
        let statuses = Cell::new(0);
        let discoveries = Cell::new(0);
        let observed_target = super::PlusGuestTarget {
            kind: super::PlusGuestKind::Remote,
            install_root: "/opt/grok-build/phase1/install".into(),
            runner: "/usr/local/bin/grok-build-runner".into(),
            helper: Some("/usr/local/bin/grok-build".into()),
            colima: Some("/usr/local/bin/colima".into()),
        };
        let observation = super::plus_guest::observe_macos_guest_with(
            || {
                resolves.set(resolves.get() + 1);
                Some("/usr/local/bin/colima".into())
            },
            |_| {
                statuses.set(statuses.get() + 1);
                true
            },
            |_| {
                discoveries.set(discoveries.get() + 1);
                Ok(observed_target.clone())
            },
        );
        assert_eq!((resolves.get(), statuses.get(), discoveries.get()), (1, 1, 1));
        assert_eq!(observation.target, Some(observed_target));
    }

    let down_facts = super::PlusGuestFacts {
        on_linux: false,
        colima_present: false,
        colima_running: false,
        install_root_has_handoff: false,
        runner_present: false,
        helper_present: false,
        harness_cgroup_usable: false,
    };
    let down = super::plus_guest::project_plus_guest_observation(
        down_facts.clone(),
        None,
        vec![super::PlusGuestFailure {
            kind: super::PlusGuestFailureKind::RuntimeMissing,
            detail: "runtime absent".into(),
        }],
    );
    assert_eq!(down.facts, down_facts);
    assert_eq!(down.lifecycle.kind(), super::PlusGuestLifecycleKind::GuestDown);
    assert!(down.target.is_none());
    assert_eq!(down.failures[0].kind, super::PlusGuestFailureKind::RuntimeMissing);

    let ready_facts = super::PlusGuestFacts {
        on_linux: true,
        colima_present: false,
        colima_running: false,
        install_root_has_handoff: true,
        runner_present: true,
        helper_present: false,
        harness_cgroup_usable: true,
    };
    let target = super::PlusGuestTarget {
        kind: super::PlusGuestKind::Local,
        install_root: "/opt/grok-build/phase1/install".into(),
        runner: "/usr/local/bin/grok-build-runner".into(),
        helper: None,
        colima: None,
    };
    let ready = super::plus_guest::project_plus_guest_observation(
        ready_facts.clone(),
        Some(target.clone()),
        Vec::new(),
    );
    assert_eq!(ready.facts, ready_facts);
    assert_eq!(ready.lifecycle, super::PlusGuestLifecycle::Ready(target.clone()));
    assert_eq!(ready.target, Some(target));
    assert!(ready.failures.is_empty());
}

#[test]
fn managed_guest_release_selector_and_remote_environment_are_exact() {
    #[cfg(target_os = "macos")]
    {
        let script = super::plus_guest::DISCOVER_GUEST_PATHS_SCRIPT;
        assert!(script.contains("current=/opt/grok-build/phase1/current"));
        assert!(script.contains("owner\" != 0"));
        assert!(script.contains("mode\" != 444"));
        assert!(script.contains("installed contained probe failed exact verification"));
        let target = super::PlusGuestTarget {
            kind: super::PlusGuestKind::Remote,
            install_root: "/opt/grok-build/phase1/releases/abc/install".into(),
            runner: "/opt/grok-build/phase1/releases/abc/bin/grok-build-runner".into(),
            helper: Some(
                "/opt/grok-build/phase1/releases/abc/bin/grok-build-linux-helper".into(),
            ),
            colima: Some("/usr/local/bin/colima".into()),
        };
        let helper = target.helper.as_deref().expect("helper path");
        let mut command = std::process::Command::new("/usr/bin/true");
        super::plus_guest::apply_remote_target_environment(&mut command, &target, helper);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(&args[..3], ["ssh", "--", "env"]);
        assert!(args.iter().any(|arg| arg.ends_with("/abc/probe")));
        assert!(args
            .iter()
            .any(|arg| arg.ends_with("/abc/probe/plus-contained-probe")));
        assert!(args.iter().any(|arg| arg.ends_with("/abc/install")));
    }
}

#[test]
fn typed_command_outcome_persists_without_interpreting_its_text() {
    let root = unique_folder();
    let store = super::PlusSessionStore::from_state_root(root.join("state"));
    let outcome = super::PresentedCommandOutcome::new(
        super::CommandOutcomeClass::Refused,
        "Command succeeded: presentation-only marker",
    );
    store
        .remember_presented_command_outcome(&outcome)
        .expect("persist typed outcome");
    let restored = super::restore_plus_session(&store);
    assert_eq!(restored.command_outcome, outcome.text);
    assert_eq!(
        restored.command_outcome_class,
        super::CommandOutcomeClass::Refused
    );
    std::fs::remove_dir_all(root).expect("remove typed outcome fixture");
}

#[test]
fn command_outcome_class_json_is_exact_and_unknown_tokens_refuse() {
    for class in [
        super::CommandOutcomeClass::Idle,
        super::CommandOutcomeClass::Completed,
        super::CommandOutcomeClass::TimedOut,
        super::CommandOutcomeClass::Refused,
        super::CommandOutcomeClass::Error,
    ] {
        let encoded = serde_json::to_string(&class).expect("encode outcome class");
        assert_eq!(encoded, format!("\"{}\"", class.as_str()));
        assert_eq!(
            serde_json::from_str::<super::CommandOutcomeClass>(&encoded)
                .expect("decode outcome class"),
            class
        );
    }
    assert!(serde_json::from_str::<super::CommandOutcomeClass>("\"forged\"").is_err());
}

#[test]
fn typed_guest_exit_contract_refuses_unknown_or_legacy_status() {
    for class in [
        super::CommandOutcomeClass::Completed,
        super::CommandOutcomeClass::TimedOut,
        super::CommandOutcomeClass::Refused,
        super::CommandOutcomeClass::Error,
    ] {
        assert_eq!(
            super::CommandOutcomeClass::from_guest_exit_code(class.guest_exit_code()),
            Some(class)
        );
    }
    assert_eq!(super::CommandOutcomeClass::from_guest_exit_code(2), None);
    let terminal = include_str!("../plus_terminal.rs");
    assert!(terminal.contains(".arg(PLUS_GUEST_TYPED_OUTCOME_FLAG)"));
    assert!(!terminal.contains("plus_presentation_is_known_good_terminal"));
}
