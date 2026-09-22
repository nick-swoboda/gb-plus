//! CLI maintenance and contained-engine release compatibility.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::child_environment::ChildEnvironmentProfile;

pub(crate) const CLI_TARGET_VERSION: &str = "1.0.25";
const MAX_VERSION_BYTES: usize = 4_096;
const MAX_MAINTENANCE_OUTPUT_BYTES: usize = 64 * 1_024;
static CLI_OPERATION: Mutex<()> = Mutex::new(());

mod maintenance;
pub(crate) use maintenance::{CliMaintenance, inspect_managed_cli, update_cli};

#[cfg(target_os = "macos")]
mod admission;

pub(crate) fn verify_standard_publisher(cli: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    admission::verify_publisher(cli)?;
    Ok(())
}

pub(crate) fn operation_guard() -> Result<MutexGuard<'static, ()>, String> {
    CLI_OPERATION
        .lock()
        .map_err(|_| "Grok CLI maintenance lock is unavailable.".into())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CliCompatibility {
    pub(crate) version: Option<String>,
    /// Version admission only. A successful ACP capability/live probe is still required.
    pub(crate) supported: bool,
    pub(crate) target_version: &'static str,
    pub(crate) detail: String,
}

pub(crate) fn parse_cli_version(bytes: &[u8]) -> Result<CliCompatibility, String> {
    if bytes.len() > MAX_VERSION_BYTES {
        return Err("Grok CLI version output exceeded its bound.".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "Grok CLI version is not UTF-8.")?;
    let mut words = text.split_whitespace();
    if words.next() != Some("grok") {
        return Err("The selected executable did not identify itself as Grok CLI.".into());
    }
    let version = words.next().ok_or("Grok CLI did not report a version.")?;
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty() || part.len() > 5 || !part.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err("Grok CLI did not report a bounded stable release version.".into());
    }
    let supported = version == CLI_TARGET_VERSION;
    Ok(CliCompatibility {
        version: Some(version.into()),
        supported,
        target_version: CLI_TARGET_VERSION,
        detail: if supported {
            format!(
                "Grok CLI {version}; ACP capability verification is required before Chat connects."
            )
        } else {
            format!(
                "Contained mode requires its admitted CLI {CLI_TARGET_VERSION}. Select Grok CLI standard to use Grok CLI {version}; other app features remain available."
            )
        },
    })
}

pub(crate) fn inspect_cli(cli: &Path) -> Result<CliCompatibility, String> {
    #[cfg(target_os = "macos")]
    admission::verify_publisher(cli)?;
    let result = inspect_version(cli)?;
    #[cfg(target_os = "macos")]
    if result.supported {
        admission::verify_target_digest(cli)?;
    }
    Ok(result)
}

pub(super) fn inspect_version(cli: &Path) -> Result<CliCompatibility, String> {
    parse_cli_version(&run_fixed_cli(
        cli,
        &["--version"],
        Duration::from_secs(5),
        MAX_VERSION_BYTES,
    )?)
}

fn output_reader(
    reader: impl Read + Send + 'static,
    cap: usize,
) -> mpsc::Receiver<Result<Vec<u8>, String>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = reader
            .take((cap + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "Cannot read bounded Grok CLI output.".to_owned())
            .and_then(|_| {
                if bytes.len() <= cap {
                    Ok(bytes)
                } else {
                    Err("Grok CLI output exceeded its bound.".into())
                }
            });
        let _ = sender.send(result);
    });
    receiver
}

fn run_fixed_cli(
    cli: &Path,
    args: &[&str],
    timeout: Duration,
    cap: usize,
) -> Result<Vec<u8>, String> {
    let mut command = Command::new(cli);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    ChildEnvironmentProfile::OAuth.apply(&mut command);
    command.env("GROK_AUTH_PATH", super::auth_paths::cli_auth_path()?);
    let mut child = command
        .spawn()
        .map_err(|error| format!("Cannot start the selected Grok CLI: {error}"))?;
    let stdout = output_reader(
        child
            .stdout
            .take()
            .ok_or("Grok CLI stdout is unavailable.")?,
        cap,
    );
    let stderr = output_reader(
        child
            .stderr
            .take()
            .ok_or("Grok CLI stderr is unavailable.")?,
        cap,
    );
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(format!("The fixed Grok CLI operation exited {status}."));
                }
                let result = stdout
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| "Grok CLI output did not close.")??;
                // Never render updater output: it may contain account or network details.
                stderr
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|_| "Grok CLI error output did not close.")??;
                return Ok(result);
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(if result.is_err() {
                    "Cannot wait for the selected Grok CLI."
                } else {
                    "The fixed Grok CLI operation timed out and was stopped."
                }
                .into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_admission_is_explicit_and_never_admits_future_versions() {
        for (version, expected) in [
            ("1.0.13", false),
            ("1.0.23", false),
            ("1.0.24", false),
            ("1.0.25", true),
            ("1.0.26", false),
            ("2.0.0", false),
        ] {
            let value =
                parse_cli_version(format!("grok {version} (revision) [stable]\n").as_bytes())
                    .unwrap();
            assert_eq!(value.supported, expected, "{version}");
        }
    }

    #[test]
    fn malformed_or_prerelease_identity_does_not_gain_version_admission() {
        for value in [
            "",
            "other 1.0.25",
            "grok 1.0.25-beta",
            "grok 1.0",
            "grok 1.0.25.1",
            "grok 1.0.25;execute",
        ] {
            assert!(parse_cli_version(value.as_bytes()).is_err());
        }
        assert!(parse_cli_version(&vec![b'a'; MAX_VERSION_BYTES + 1]).is_err());
    }
}
