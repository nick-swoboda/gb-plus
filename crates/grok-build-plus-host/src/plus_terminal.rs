//! Project-root terminal commands through the existing contained runner spine.
//!
//! Input is parsed as a direct executable plus argv. It is never passed to a
//! shell, and Off / Setting up / Needs attention never launch a process.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use grok_build_core::{CommandSpec, validate_current_direct_exec_command_v1};

use super::plus_command_security::{
    PlusCommandSecurityKind, PlusCommandSecurityPreference, classify_command_security,
    plus_contained_command_with_security_typed, present_command_security_contained_typed,
};
use super::plus_guest::{
    PLUS_GUEST_TYPED_OUTCOME_FLAG, PlusGuestKind, PlusGuestLifecycle, PlusGuestTarget,
    PlusGuestUnavailable, present_plus_guest_contained_typed,
    present_plus_guest_unavailable_outcome_with_kind,
};
use super::plus_lifecycle::{PlusGuestLifecycleKind, apply_colima_child_environment};
use super::plus_refusals::PLUS_REFUSAL_NOT_SUCCESS;
use super::{BoundProject, CommandOutcomeClass, PresentedCommandOutcome};

/// Internal Linux-helper entry used by the macOS Colima transport.
pub const PLUS_GUEST_COMMAND_FLAG: &str = "--plus-guest-command";

/// Parse one UI command line into the core's shell-free direct-exec contract.
///
/// Quotes and backslash escaping group argv. Shell operators are rejected
/// rather than interpreted, and the working directory is always the bound
/// project root.
///
/// # Errors
///
/// Returns a user-actionable refusal for empty input, unclosed quotes,
/// unsupported shell syntax, or a command outside the core direct-exec subset.
pub fn parse_plus_terminal_command(line: &str) -> Result<CommandSpec, String> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = Quote::None;
    let mut characters = line.trim().chars().peekable();
    while let Some(character) = characters.next() {
        match quote {
            Quote::Single => {
                if character == '\'' {
                    quote = Quote::None;
                } else {
                    word.push(character);
                }
            }
            Quote::Double => match character {
                '"' => quote = Quote::None,
                '\\' => {
                    let escaped = characters
                        .next()
                        .ok_or_else(|| "a trailing backslash has nothing to escape".to_owned())?;
                    word.push(escaped);
                }
                _ => word.push(character),
            },
            Quote::None => match character {
                character if character.is_whitespace() => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                '\'' => {
                    quote = Quote::Single;
                    started = true;
                }
                '"' => {
                    quote = Quote::Double;
                    started = true;
                }
                '\\' => {
                    let escaped = characters
                        .next()
                        .ok_or_else(|| "a trailing backslash has nothing to escape".to_owned())?;
                    word.push(escaped);
                    started = true;
                }
                '|' | '&' | ';' | '<' | '>' | '`' => {
                    return Err(format!(
                        "shell operator `{character}` is unavailable; enter one direct command"
                    ));
                }
                _ => {
                    word.push(character);
                    started = true;
                }
            },
        }
    }
    if quote != Quote::None {
        return Err("a quoted argument is not closed".into());
    }
    if started {
        words.push(word);
    }
    if words.is_empty() {
        return Err("enter a command to run".into());
    }
    let command = CommandSpec {
        program: words.remove(0),
        arguments: words,
        working_directory: PathBuf::new(),
    };
    validate_current_direct_exec_command_v1(&command).map_err(|error| error.to_string())?;
    Ok(command)
}

/// Run one project-root command only when the existing Command security
/// classifier proves the contained service is On.
#[must_use]
pub fn plus_terminal_command_with_security(
    bound: &BoundProject,
    preference: PlusCommandSecurityPreference,
    setup_in_progress: bool,
    lifecycle: &PlusGuestLifecycle,
    line: &str,
) -> String {
    plus_terminal_command_with_security_typed(bound, preference, setup_in_progress, lifecycle, line)
        .text
}

/// Typed shell-free terminal command path.
#[must_use]
pub fn plus_terminal_command_with_security_typed(
    bound: &BoundProject,
    preference: PlusCommandSecurityPreference,
    setup_in_progress: bool,
    lifecycle: &PlusGuestLifecycle,
    line: &str,
) -> PresentedCommandOutcome {
    let command = match parse_plus_terminal_command(line) {
        Ok(command) => command,
        Err(detail) => {
            return PresentedCommandOutcome::new(
                CommandOutcomeClass::Refused,
                present_terminal_input_refusal(&detail),
            );
        }
    };
    let kind = classify_command_security(preference, lifecycle.kind(), setup_in_progress);
    if kind != PlusCommandSecurityKind::On {
        return plus_contained_command_with_security_typed(
            bound,
            preference,
            setup_in_progress,
            lifecycle,
        );
    }
    if !command.program.contains('/') {
        return present_command_security_contained_typed(
            kind,
            Some(PresentedCommandOutcome::new(
                CommandOutcomeClass::Refused,
                present_terminal_input_refusal(
                    "Use an executable path such as /usr/bin/pwd. Put project requests in Chat.",
                ),
            )),
        );
    }
    let PlusGuestLifecycle::Ready(target) = lifecycle else {
        return present_command_security_contained_typed(
            PlusCommandSecurityKind::NeedsAttention,
            Some(PresentedCommandOutcome::new(
                CommandOutcomeClass::Refused,
                "contained service was not ready after Command security classification",
            )),
        );
    };
    let terminal = match target.kind {
        PlusGuestKind::Local => run_local_terminal(bound, target, command),
        PlusGuestKind::Remote => run_remote_terminal(bound, target, &command),
    };
    if terminal.is_authoritative_terminal() {
        present_command_security_contained_typed(PlusCommandSecurityKind::On, Some(terminal))
    } else {
        present_command_security_contained_typed(
            PlusCommandSecurityKind::NeedsAttention,
            Some(terminal),
        )
    }
}

fn run_local_terminal(
    bound: &BoundProject,
    target: &PlusGuestTarget,
    command: CommandSpec,
) -> PresentedCommandOutcome {
    let outcome = super::plus_gui_contained_command_with_session_and_command_outcome(
        super::plus_try_launch_worker_installed(bound, &target.runner, &target.install_root)
            .and_then(super::plus_prepare_worker_shadow),
        Some(command),
    );
    present_local_output(outcome)
}

fn present_local_output(outcome: PresentedCommandOutcome) -> PresentedCommandOutcome {
    if outcome.is_authoritative_terminal() {
        outcome
    } else {
        present_plus_guest_contained_typed(PlusGuestKind::Local, outcome)
    }
}

fn run_remote_terminal(
    bound: &BoundProject,
    target: &PlusGuestTarget,
    command: &CommandSpec,
) -> PresentedCommandOutcome {
    let (Some(colima), Some(helper)) = (target.colima.as_ref(), target.helper.as_ref()) else {
        return PresentedCommandOutcome::new(
            CommandOutcomeClass::Refused,
            present_plus_guest_unavailable_outcome_with_kind(
                PlusGuestLifecycleKind::ServiceMissing,
                "remote guest target omitted colima or helper",
                &PlusGuestUnavailable {
                    reasons: vec!["Mac terminal commands require Colima and a Linux helper".into()],
                },
            ),
        );
    };
    let encoded = match serde_json::to_string(command) {
        Ok(encoded) => encoded,
        Err(error) => {
            return PresentedCommandOutcome::new(
                CommandOutcomeClass::Refused,
                present_terminal_input_refusal(&format!("cannot encode argv: {error}")),
            );
        }
    };
    let output = (|| {
        let mut launch = Command::new(colima);
        apply_colima_child_environment(&mut launch);
        super::plus_guest::apply_remote_target_environment(&mut launch, target, helper);
        launch
            .arg(helper)
            .arg(PLUS_GUEST_COMMAND_FLAG)
            .arg(bound.folder())
            .arg(PLUS_GUEST_TYPED_OUTCOME_FLAG)
            .env("LC_ALL", "C")
            .env("TMPDIR", "/tmp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = launch.spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            std::io::Error::other("contained terminal transport did not provide stdin")
        })?;
        stdin.write_all(encoded.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        drop(stdin);
        child.wait_with_output()
    })();
    match output {
        Ok(output) => present_remote_output(&output),
        Err(error) => PresentedCommandOutcome::new(
            CommandOutcomeClass::Error,
            present_plus_guest_unavailable_outcome_with_kind(
                PlusGuestLifecycleKind::GuestDown,
                &format!("colima ssh failed: {error}"),
                &PlusGuestUnavailable {
                    reasons: vec!["could not start the contained terminal transport".into()],
                },
            ),
        ),
    }
}

fn present_remote_output(output: &std::process::Output) -> PresentedCommandOutcome {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if let Some(class) = output
        .status
        .code()
        .and_then(CommandOutcomeClass::from_guest_exit_code)
    {
        return PresentedCommandOutcome::terminal(class, stdout);
    }
    let mut detail = stdout;
    if !stderr.is_empty() {
        if !detail.is_empty() {
            detail.push('\n');
        }
        detail.push_str(&stderr);
    }
    if detail.is_empty() {
        detail = format!(
            "guest terminal helper exited {} without a command terminal",
            output.status
        );
    }
    PresentedCommandOutcome::new(
        CommandOutcomeClass::Error,
        present_plus_guest_unavailable_outcome_with_kind(
            PlusGuestLifecycleKind::ServiceMissing,
            &detail,
            &PlusGuestUnavailable {
                reasons: vec![
                    "Linux helper did not return the typed command outcome contract; rebuild the guest helper"
                        .into(),
                ],
            },
        ),
    )
}

fn present_terminal_input_refusal(detail: &str) -> String {
    format!(
        "Command rejected before execution.\n{detail}\nDirect executable + argv only; shells, pipes, redirects, and command chaining are unavailable.\n{PLUS_REFUSAL_NOT_SUCCESS}"
    )
}

/// Linux helper for [`PLUS_GUEST_COMMAND_FLAG`]. The host already classified
/// Command security; this endpoint revalidates the exact command and binds the
/// exact project root before entering the installed-service runner path.
///
/// # Errors
///
/// Returns a precise setup error when invoked off Linux, with an invalid
/// workspace/command, or without a ready local installed service.
pub fn run_plus_guest_terminal(workspace: &Path, command_json: &str) -> Result<String, String> {
    run_plus_guest_terminal_typed(workspace, command_json).map(|outcome| outcome.text)
}

/// Linux helper entry retaining typed command authority for process status.
///
/// # Errors
///
/// Returns the same setup errors as [`run_plus_guest_terminal`].
pub fn run_plus_guest_terminal_typed(
    workspace: &Path,
    command_json: &str,
) -> Result<PresentedCommandOutcome, String> {
    #[cfg(target_os = "linux")]
    {
        let command: CommandSpec = serde_json::from_str(command_json)
            .map_err(|error| format!("invalid contained terminal command JSON: {error}"))?;
        validate_current_direct_exec_command_v1(&command).map_err(|error| error.to_string())?;
        let workspace = workspace
            .canonicalize()
            .map_err(|error| format!("cannot resolve contained terminal workspace: {error}"))?;
        let bound = super::bind_project_folder(workspace).map_err(|error| error.to_string())?;
        match super::probe_plus_guest_lifecycle() {
            PlusGuestLifecycle::Ready(target) if target.kind == PlusGuestKind::Local => {
                Ok(run_local_terminal(&bound, &target, command))
            }
            PlusGuestLifecycle::Ready(_) => {
                Err("contained terminal helper requires a local Linux installed service".into())
            }
            PlusGuestLifecycle::GuestDown { reasons }
            | PlusGuestLifecycle::ServiceMissing { reasons } => Err(reasons.join("\n")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (workspace, command_json);
        Err("contained terminal helper must run on the Linux guest".into())
    }
}

#[cfg(test)]
#[path = "tests/plus_terminal.rs"]
mod tests;
