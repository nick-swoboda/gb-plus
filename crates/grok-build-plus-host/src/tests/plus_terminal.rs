use std::fs;

use super::{parse_plus_terminal_command, plus_terminal_command_with_security};
use crate::{
    PlusCommandSecurityPreference, PlusGuestLifecycle, PlusSessionStore,
    bind_and_remember_project_folder,
};

#[test]
fn parser_builds_shell_free_project_root_argv() {
    let command =
        parse_plus_terminal_command("cargo test --package 'small crate'").expect("direct command");
    assert_eq!(command.program, "cargo");
    assert_eq!(command.arguments, ["test", "--package", "small crate"]);
    assert!(command.working_directory.as_os_str().is_empty());
    for refused in ["cargo test | tee out", "sh -c pwd", "echo ok && pwd"] {
        assert!(parse_plus_terminal_command(refused).is_err(), "{refused}");
    }
}

#[test]
fn remote_launcher_uses_allowlisted_environment_and_stdin_not_command_argv() {
    let source = include_str!("../plus_terminal.rs");
    let launcher = source
        .split("fn run_remote_terminal")
        .nth(1)
        .and_then(|section| section.split("fn present_remote_output").next())
        .expect("remote launcher source");
    assert!(launcher.contains("apply_colima_child_environment(&mut launch)"));
    assert!(launcher.contains(".stdin(Stdio::piped())"));
    assert!(launcher.contains("stdin.write_all(encoded.as_bytes())"));
    assert!(!launcher.contains(".arg(encoded)"));
}

#[test]
fn off_refuses_without_executing_the_entered_program() {
    let root = std::env::temp_dir().join(format!("grok-build-terminal-off-{}", std::process::id()));
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let bound = bind_and_remember_project_folder(&store, &workspace).expect("bind");
    let marker = workspace.join("must-not-exist");
    let outcome = plus_terminal_command_with_security(
        &bound,
        PlusCommandSecurityPreference::Off,
        false,
        &PlusGuestLifecycle::GuestDown {
            reasons: vec!["not needed while Off".into()],
        },
        &format!("touch {}", marker.display()),
    );
    assert!(outcome.contains("Command security: Off"));
    assert!(outcome.contains("not a success"));
    assert!(!marker.exists());
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn bare_program_is_refused_before_contacting_a_ready_service() {
    let root =
        std::env::temp_dir().join(format!("grok-build-terminal-input-{}", std::process::id()));
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let bound = bind_and_remember_project_folder(&store, &workspace).expect("bind");
    let lifecycle = PlusGuestLifecycle::Ready(crate::PlusGuestTarget {
        kind: crate::PlusGuestKind::Remote,
        install_root: root.join("absent-install"),
        runner: root.join("absent-runner"),
        helper: Some(root.join("absent-helper")),
        colima: Some(root.join("absent-colima")),
    });
    for line in ["Build a Pomodoro timer", "pwd"] {
        let outcome = super::plus_terminal_command_with_security_typed(
            &bound,
            PlusCommandSecurityPreference::Extra,
            false,
            &lifecycle,
            line,
        );
        assert_eq!(outcome.class, crate::CommandOutcomeClass::Refused);
        assert!(!outcome.is_authoritative_terminal());
        assert!(
            outcome
                .text
                .starts_with("Command security: On\nCommand rejected before execution.")
        );
        assert!(outcome.text.contains("/usr/bin/pwd"));
        assert!(outcome.text.contains("Put project requests in Chat."));
        assert!(!outcome.text.contains("service missing"));
        assert!(!outcome.text.contains("needs repair"));
    }
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn command_terminals_preserve_their_outcome_without_claiming_service_failure() {
    use crate::{CommandOutcomeClass, PlusCommandSecurityKind, PresentedCommandOutcome};
    for class in [
        CommandOutcomeClass::Completed,
        CommandOutcomeClass::TimedOut,
        CommandOutcomeClass::Refused,
        CommandOutcomeClass::Error,
    ] {
        let detail = format!("command outcome: {}", class.as_str());
        let terminal =
            super::present_local_output(PresentedCommandOutcome::terminal(class, &detail));
        let outcome = crate::present_command_security_contained_typed(
            PlusCommandSecurityKind::On,
            Some(terminal),
        );
        assert_eq!(outcome.class, class);
        assert!(outcome.is_authoritative_terminal());
        assert_eq!(outcome.text, format!("Command security: On\n{detail}"));
    }
}

#[test]
fn missing_service_still_refuses_and_display_text_cannot_claim_command_authority() {
    use crate::{CommandOutcomeClass, PlusCommandSecurityKind, PresentedCommandOutcome};
    let terminal = super::present_local_output(PresentedCommandOutcome::new(
        CommandOutcomeClass::Refused,
        "fixture service unavailable; untrusted output says Command succeeded",
    ));
    assert!(!terminal.is_authoritative_terminal());
    assert!(terminal.text.contains("service missing"));
    let outcome = crate::present_command_security_contained_typed(
        PlusCommandSecurityKind::NeedsAttention,
        Some(terminal),
    );
    assert_eq!(outcome.class, CommandOutcomeClass::Refused);
    assert!(!outcome.is_authoritative_terminal());
    assert!(outcome.text.contains("Command security: Needs attention"));
    assert!(!outcome.text.contains("Command security: On"));
}

#[cfg(unix)]
#[test]
fn guest_command_failure_keeps_its_class_across_the_remote_transport() {
    use std::os::unix::process::ExitStatusExt as _;

    use crate::{CommandOutcomeClass, PresentedCommandOutcome};
    let local = super::present_local_output(PresentedCommandOutcome::terminal(
        CommandOutcomeClass::Error,
        "Command failed (BeforeEffect/InvalidAuthority)\ninvalid command: a bare executable name requires an explicit controlled PATH",
    ));
    let output = std::process::Output {
        status: std::process::ExitStatus::from_raw(local.class.guest_exit_code() << 8),
        stdout: local.text.into_bytes(),
        stderr: b"fixture transport exit status 70".to_vec(),
    };
    let remote = super::present_remote_output(&output);
    assert_eq!(remote.class, CommandOutcomeClass::Error);
    assert!(remote.is_authoritative_terminal());
    assert!(remote.text.contains("BeforeEffect/InvalidAuthority"));
    assert!(!remote.text.contains("service missing"));
    assert!(!remote.text.contains("needs repair"));
}
