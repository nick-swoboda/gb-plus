//! The separately named macOS development dedicated-identity helper.
//!
//! Uses a separate identity pool, state root and code requirement.
//!
//! It is never registered through `SMAppService`, is never Developer ID signed
//! or notarized, and cannot publish a production helper session. Its green
//! results are development evidence and are explicitly not Hard Gate 1
//! evidence.

use std::process::ExitCode;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match grok_build_runner::run_macos_development_helper(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(refusal) => {
            eprintln!("grok-build-dev-helper: {refusal}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    eprintln!("grok-build-dev-helper: the development helper is macOS only");
    ExitCode::FAILURE
}
