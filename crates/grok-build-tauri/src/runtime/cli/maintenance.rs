//! User-invoked maintenance of the official managed CLI.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde::Serialize;

use super::{MAX_MAINTENANCE_OUTPUT_BYTES, MAX_VERSION_BYTES, operation_guard};
use crate::bounded_process::{Limits, collect};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CliMaintenance {
    pub(crate) version: String,
    pub(crate) detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Version,
    Update,
    Check,
}

fn command(home: &Path, operation: Operation) -> Command {
    let mut command = Command::new(home.join(".grok/bin/grok"));
    command
        .current_dir(home)
        .env("HOME", home)
        .env("GROK_HOME", home.join(".grok"))
        .args(match operation {
            Operation::Version => &["--version"][..],
            Operation::Update => &["update"],
            Operation::Check => &["update", "--check", "--json"],
        });
    command
}

fn run(home: &Path, operation: Operation) -> Result<Vec<u8>, String> {
    let output = collect(
        command(home, operation),
        &[],
        &Limits {
            input: 0,
            output: MAX_MAINTENANCE_OUTPUT_BYTES,
            error: MAX_MAINTENANCE_OUTPUT_BYTES,
            timeout: match operation {
                Operation::Version => Duration::from_secs(5),
                Operation::Check => Duration::from_secs(15),
                Operation::Update => Duration::from_mins(5),
            },
        },
    )?;
    if !output.status.success() {
        return Err(format!(
            "Grok CLI maintenance exited {}. Try Update again when ready.",
            output.status
        ));
    }
    Ok(output.stdout)
}

fn version(bytes: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Cannot read the Grok CLI version.")?;
    let mut words = text.split_whitespace();
    let identity = words.next();
    let version = words.next().unwrap_or_default();
    if bytes.len() > MAX_VERSION_BYTES
        || identity != Some("grok")
        || version.is_empty()
        || version.len() > 80
        || !version.starts_with(|c: char| c.is_ascii_digit())
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
    {
        return Err("The signed CLI returned an unrecognized version; Chat capabilities are checked separately.".into());
    }
    Ok(version.into())
}

pub(crate) fn inspect_managed_cli() -> Result<CliMaintenance, String> {
    let _operation = operation_guard()?;
    let home = crate::runtime::engine::managed_home()?;
    super::verify_standard_publisher(&home.join(".grok/bin/grok"))?;
    Ok(CliMaintenance {
        version: version(&run(&home, Operation::Version)?)?,
        detail: "Updates Grok and its built-in features.".into(),
    })
}

pub(crate) fn update_cli() -> Result<CliMaintenance, String> {
    let _operation = operation_guard()?;
    let home = crate::runtime::engine::managed_home()?;
    perform_update(
        || super::verify_standard_publisher(&home.join(".grok/bin/grok")),
        |operation| run(&home, operation),
    )
}

fn perform_update(
    mut verify: impl FnMut() -> Result<(), String>,
    mut run: impl FnMut(Operation) -> Result<Vec<u8>, String>,
) -> Result<CliMaintenance, String> {
    verify()?;
    let before = version(&run(Operation::Version)?)?;
    run(Operation::Update)?;
    verify()?;
    let after = version(&run(Operation::Version)?)?;
    let detail = if before != after {
        format!("Updated from {before} to {after}. New CLI connections use this version.")
    } else if run(Operation::Check).is_ok_and(|bytes| is_current(&bytes, &after)) {
        "Grok CLI is up to date.".into()
    } else {
        "Update finished with no version change. The latest release could not be confirmed.".into()
    };
    Ok(CliMaintenance {
        version: after,
        detail,
    })
}

fn is_current(bytes: &[u8], version: &str) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|status| {
        status.get("error").is_some_and(serde_json::Value::is_null)
            && status
                .get("updateAvailable")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
            && status
                .get("currentVersion")
                .and_then(serde_json::Value::as_str)
                == Some(version)
            && status
                .get("latestVersion")
                .and_then(serde_json::Value::as_str)
                == Some(version)
    })
}

#[cfg(test)]
#[path = "tests/maintenance.rs"]
mod tests;
