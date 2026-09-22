//! Process entry point for the sandbox runner.

use std::process::ExitCode;

fn main() -> ExitCode {
    if let Some(exit_code) = grok_build_runner::run_contained_stdio_service_if_requested() {
        return exit_code;
    }
    if let Some(exit_code) = grok_build_runner::run_linux_held_launcher_if_requested() {
        return exit_code;
    }
    if let Some(exit_code) = grok_build_runner::run_linux_command_canary_helper_if_requested() {
        return exit_code;
    }
    // The installer writes the external anchor; the runner authenticates it
    // under a distinct identity.
    if let Some(exit_code) = grok_build_runner::run_linux_native_service_installer_if_requested() {
        return exit_code;
    }
    if let Some(exit_code) = grok_build_runner::run_linux_native_service_open_if_requested() {
        return exit_code;
    }
    // The probe runs no command and grants no authority. Non-Linux builds
    // recognize the mode so it cannot fall through to an ordinary session.
    if let Some(exit_code) = grok_build_runner::run_linux_service_bootstrap_probe_if_requested() {
        return exit_code;
    }
    // The stopped-child descriptor-table probe. It receives descriptors its
    // parent already held, places them, and stops so the parent can read the
    // table out of procfs; it runs no command and grants no authority.
    if let Some(exit_code) =
        grok_build_runner::run_linux_service_child_descriptor_probe_if_requested()
    {
        return exit_code;
    }
    #[cfg(all(target_os = "macos", feature = "future-contracts"))]
    if let Some(exit_code) = grok_build_runner::run_macos_vz_guest_if_requested() {
        return exit_code;
    }
    #[cfg(all(target_os = "macos", feature = "future-contracts"))]
    if let Some(exit_code) = grok_build_runner::run_macos_vz_lifecycle_probe_if_requested() {
        return exit_code;
    }
    grok_build_runner::run_stdio_runner_process()
}
