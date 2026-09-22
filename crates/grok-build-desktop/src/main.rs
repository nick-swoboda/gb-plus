//! Process entry point for GB Plus (native window) and the contract self-test.

use std::env;
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use grok_build_desktop::{
    PLUS_PRODUCT_VERSION, run_contract_self_test, run_plus_1212_proof, run_plus_window,
    smoke_plus_window,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    match arguments.next() {
        Some(flag) if flag == "--version" || flag == "-V" => {
            if arguments.next().is_some() {
                return Err("usage: grok-build --version".into());
            }
            println!("GB Plus {PLUS_PRODUCT_VERSION}");
            Ok(())
        }
        Some(flag) if flag == "--contract-self-test" => {
            let workspace = match arguments.next() {
                Some(path) => PathBuf::from(path),
                None => env::current_dir()
                    .map_err(|error| format!("cannot resolve current directory: {error}"))?,
            };
            if arguments.next().is_some() {
                return Err("usage: grok-build --contract-self-test [absolute-workspace]".into());
            }
            let report = run_contract_self_test(workspace)
                .map_err(|error| format!("contract self-test failed: {error}"))?;
            println!(
                "CONTRACT SELF-TEST PASSED: sprint={} graph={} tasks={} events={}; commands_executed=0; secure execution was not tested",
                report.sprint_id, report.graph_id, report.task_count, report.event_count
            );
            Ok(())
        }
        Some(flag) if flag == "--plus-smoke" => {
            if arguments.next().is_some() {
                return Err("usage: grok-build --plus-smoke".into());
            }
            let report = smoke_plus_window()?;
            println!("{report}");
            Ok(())
        }
        Some(flag) if flag == "--plus-guest-contained" => run_guest_contained(&mut arguments),
        Some(flag) if flag == grok_build_desktop::PLUS_GUEST_COMMAND_FLAG => {
            run_guest_command(&mut arguments)
        }
        Some(flag) if flag == "--plus-1212-proof" => {
            if arguments.next().is_some() {
                return Err("usage: grok-build --plus-1212-proof".into());
            }
            println!("{}", run_plus_1212_proof());
            Ok(())
        }
        Some(flag) if flag == "--plus-prepare-guest" => {
            if arguments.next().is_some() {
                return Err("usage: grok-build --plus-prepare-guest".into());
            }
            println!("{}", grok_build_desktop::prepare_plus_guest());
            Ok(())
        }
        None => run_plus_window(),
        Some(_) => Err(
            "usage: grok-build [--version | --plus-smoke | --plus-guest-contained | --plus-guest-command <absolute-workspace> <command-json> | --plus-prepare-guest | --plus-1212-proof | --contract-self-test [absolute-workspace]]".into(),
        ),
    }
}

fn run_guest_contained(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), String> {
    let typed = match arguments.next() {
        None => false,
        Some(value) if value == grok_build_desktop::PLUS_GUEST_TYPED_OUTCOME_FLAG => true,
        Some(_) => return Err("usage: grok-build --plus-guest-contained".into()),
    };
    if arguments.next().is_some() {
        return Err("usage: grok-build --plus-guest-contained".into());
    }
    if typed {
        let outcome = grok_build_desktop::run_plus_guest_contained_typed()?;
        finish_typed_guest_outcome(&outcome)
    } else {
        println!("{}", grok_build_desktop::run_plus_guest_contained()?);
        Ok(())
    }
}

fn run_guest_command(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), String> {
    let usage =
        "usage: grok-build --plus-guest-command <absolute-workspace> (command JSON on stdin)";
    let workspace = arguments.next().ok_or_else(|| usage.to_owned())?;
    let typed = match arguments.next() {
        None => false,
        Some(value) if value == grok_build_desktop::PLUS_GUEST_TYPED_OUTCOME_FLAG => true,
        Some(_) => return Err(usage.into()),
    };
    if arguments.next().is_some() {
        return Err(usage.into());
    }
    let mut command_bytes = Vec::new();
    std::io::stdin()
        .take(64 * 1024 + 1)
        .read_to_end(&mut command_bytes)
        .map_err(|error| format!("cannot read contained terminal command stdin: {error}"))?;
    if command_bytes.len() > 64 * 1024 {
        return Err("contained terminal command JSON exceeded 64 KiB".into());
    }
    let command_json = std::str::from_utf8(&command_bytes)
        .map_err(|_| "contained terminal command JSON must be UTF-8".to_owned())?
        .trim_end_matches(['\r', '\n']);
    if typed {
        let outcome = grok_build_desktop::run_plus_guest_terminal_typed(
            std::path::Path::new(&workspace),
            command_json,
        )?;
        finish_typed_guest_outcome(&outcome)
    } else {
        println!(
            "{}",
            grok_build_desktop::run_plus_guest_terminal(
                std::path::Path::new(&workspace),
                command_json,
            )?
        );
        Ok(())
    }
}

fn finish_typed_guest_outcome(
    outcome: &grok_build_desktop::PresentedCommandOutcome,
) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{}", outcome.text)
        .map_err(|error| format!("cannot write typed guest outcome: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("cannot flush typed guest outcome: {error}"))?;
    let code = outcome.class.guest_exit_code();
    if code == 0 {
        Ok(())
    } else {
        std::process::exit(code)
    }
}
