//! Fail-closed entry point for the native Hard Gate 1 fixture.
//!
//! The executable exists before the production fixture is wired so exact-host
//! preflight jobs can always upload a truthful diagnostic. It never converts a
//! static capability probe, a partial fixture, or a malformed evidence bundle
//! into a passing gate.

mod evidence;
mod native_admission;

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use evidence::{lint_gate1_evidence_candidate_structure, write_not_completed_diagnostic};

const USAGE: &str = "usage:\n  grok-build-gate-1 --evidence-directory <directory>\n  grok-build-gate-1 --validate-evidence-directory <directory>";

fn main() -> ExitCode {
    match run() {
        Ok(outcome) => {
            eprintln!("GATE 1 NOT COMPLETED: {}", outcome.reason());
            Outcome::exit_code()
        }
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

enum Outcome {
    NotCompleted(String),
}

impl Outcome {
    fn reason(&self) -> &str {
        match self {
            Self::NotCompleted(reason) => reason,
        }
    }

    fn exit_code() -> ExitCode {
        ExitCode::from(3)
    }
}

fn run() -> Result<Outcome, String> {
    run_with_arguments(env::args_os().skip(1))
}

fn run_with_arguments(arguments: impl IntoIterator<Item = OsString>) -> Result<Outcome, String> {
    let mut arguments = arguments.into_iter();
    let operation = arguments
        .next()
        .ok_or_else(|| "missing operation".to_owned())?;
    let directory = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| "missing evidence directory".to_owned())?,
    );
    if arguments.next().is_some() {
        return Err("unexpected trailing argument".into());
    }

    if operation == "--validate-evidence-directory" {
        lint_gate1_evidence_candidate_structure(&directory)
            .map_err(|error| format!("Gate 1 evidence is invalid: {error}"))?;
        return Ok(Outcome::NotCompleted(
            "candidate structure is internally valid, but no independent source, host, SQLite, or native-receipt verifier is connected"
                .into(),
        ));
    }

    if operation == "--evidence-directory" {
        let diagnostic_path = write_not_completed_diagnostic(&directory)
            .map_err(|error| format!("cannot write Gate 1 diagnostic: {error}"))?;
        return Ok(Outcome::NotCompleted(format!(
            "the production native fixture is not connected; diagnostic={}",
            diagnostic_path.display()
        )));
    }

    Err(format!(
        "unknown operation: {}",
        operation.to_string_lossy()
    ))
}
