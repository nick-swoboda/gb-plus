//! Non-authoritative Gate-case registry checker and projection renderer.
//!
//! This utility cannot run a fixture, validate native evidence, or promote a
//! gate. It only checks a canonical Gate 1, Gate 2, or Gate 3 JSON projection against
//! the still-normative manifest-v2 case set and renders review material.

mod registry;

use std::env;
use std::io::{self, Write as _};
use std::process::ExitCode;

const USAGE: &str =
    "usage: grok-build-gate-registry <check|render-json|render-markdown> [--gate <1|2|3>]";

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(arguments: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut arguments = arguments.into_iter();
    let operation = arguments
        .next()
        .ok_or_else(|| "missing operation".to_owned())?;
    let gate = match arguments.next() {
        None => registry::RegistryGateSelectionV1::Gate1,
        Some(flag) if flag == "--gate" => match arguments.next().as_deref() {
            Some("1") => registry::RegistryGateSelectionV1::Gate1,
            Some("2") => registry::RegistryGateSelectionV1::Gate2,
            Some("3") => registry::RegistryGateSelectionV1::Gate3,
            Some(value) => return Err(format!("unknown gate {value:?}")),
            None => return Err("missing gate after --gate".into()),
        },
        Some(argument) => return Err(format!("unexpected argument {argument:?}")),
    };
    if arguments.next().is_some() {
        return Err("unexpected trailing argument".into());
    }

    match operation.as_str() {
        "check" => {
            let registry =
                registry::checked_in_registry(gate).map_err(|error| error.to_string())?;
            println!(
                "non-authoritative {} projection: specifications={}; sha256={}",
                gate.label(),
                registry.specifications.len(),
                registry.digest().map_err(|error| error.to_string())?
            );
            Ok(())
        }
        "render-json" => {
            let projected = registry::manifest_v2_projection(gate);
            projected.validate().map_err(|error| error.to_string())?;
            let bytes = serde_json::to_vec(&projected)
                .map_err(|error| format!("cannot encode registry projection: {error}"))?;
            io::stdout()
                .lock()
                .write_all(&bytes)
                .map_err(|error| format!("cannot write registry projection: {error}"))
        }
        "render-markdown" => {
            let registry =
                registry::checked_in_registry(gate).map_err(|error| error.to_string())?;
            print!("{}", registry.render_markdown());
            Ok(())
        }
        _ => Err(format!("unknown operation {operation:?}")),
    }
}
