//! Linux guest entry for the app-owned contained-command transport.
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::ExitCode;

use grok_build_plus_host::{
    PLUS_GUEST_COMMAND_FLAG, PLUS_GUEST_TYPED_OUTCOME_FLAG, PresentedCommandOutcome,
    run_plus_guest_contained_typed, run_plus_guest_terminal_typed,
};

const REFUSAL_EXIT: u8 = 78;
const MAX_COMMAND_BYTES: u64 = 64 * 1024;
fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--gb-contained-service-v1"))
        && grok_build_plus_host::plus_join_sibling_harness_cgroup().is_err()
    {
        eprintln!("Contained service cannot enter its managed guest service group.");
        return ExitCode::from(REFUSAL_EXIT);
    }
    if let Some(code) = runner_internal_mode() {
        return code;
    }
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--linux-native-service-install-root"))
    {
        return run_installed_service();
    }
    match run(std::env::args_os().skip(1)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Linux guest helper refused: {error}");
            ExitCode::from(REFUSAL_EXIT)
        }
    }
}
fn runner_internal_mode() -> Option<ExitCode> {
    grok_build_runner::run_contained_stdio_service_if_requested()
        .or_else(grok_build_runner::run_linux_held_launcher_if_requested)
        .or_else(grok_build_runner::run_linux_command_canary_helper_if_requested)
        .or_else(grok_build_runner::run_linux_native_service_installer_if_requested)
        .or_else(grok_build_runner::run_linux_native_service_open_if_requested)
        .or_else(grok_build_runner::run_linux_service_bootstrap_probe_if_requested)
        .or_else(grok_build_runner::run_linux_service_child_descriptor_probe_if_requested)
}
#[cfg(target_os = "linux")]
fn run_installed_service() -> ExitCode {
    grok_build_runner::run_stdio_runner_process()
}
#[cfg(not(target_os = "linux"))]
fn run_installed_service() -> ExitCode {
    ExitCode::from(REFUSAL_EXIT)
}

fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<ExitCode, String> {
    match arguments.next() {
        Some(flag) if flag == "--plus-guest-contained" => {
            require_typed_outcome_and_end(&mut arguments)?;
            finish(&run_plus_guest_contained_typed()?)
        }
        Some(flag) if flag == PLUS_GUEST_COMMAND_FLAG => {
            let workspace = arguments.next().ok_or_else(|| {
                format!("{PLUS_GUEST_COMMAND_FLAG} requires an absolute workspace")
            })?;
            require_typed_outcome_and_end(&mut arguments)?;
            let command = read_command()?;
            finish(&run_plus_guest_terminal_typed(
                Path::new(&workspace),
                command.trim_end_matches(['\r', '\n']),
            )?)
        }
        _ => Err(format!(
            "usage: grok-build-linux-helper --plus-guest-contained {PLUS_GUEST_TYPED_OUTCOME_FLAG} | {PLUS_GUEST_COMMAND_FLAG} <absolute-workspace> {PLUS_GUEST_TYPED_OUTCOME_FLAG}"
        )),
    }
}

fn require_typed_outcome_and_end(
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<(), String> {
    match arguments.next() {
        Some(flag) if flag == PLUS_GUEST_TYPED_OUTCOME_FLAG => {}
        _ => return Err(format!("missing {PLUS_GUEST_TYPED_OUTCOME_FLAG}")),
    }
    if arguments.next().is_some() {
        return Err("unexpected trailing guest-helper argument".into());
    }
    Ok(())
}

fn read_command() -> Result<String, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_COMMAND_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read contained command: {error}"))?;
    if bytes.len() as u64 > MAX_COMMAND_BYTES {
        return Err("contained command exceeded 64 KiB".into());
    }
    String::from_utf8(bytes).map_err(|_| "contained command must be UTF-8".into())
}

fn finish(outcome: &PresentedCommandOutcome) -> Result<ExitCode, String> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{}", outcome.text)
        .map_err(|error| format!("cannot write contained outcome: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("cannot flush contained outcome: {error}"))?;
    let code =
        u8::try_from(outcome.class.guest_exit_code()).expect("guest exit codes fit one byte");
    Ok(ExitCode::from(code))
}

#[cfg(test)]
#[path = "tests/linux_helper.rs"]
mod tests;
