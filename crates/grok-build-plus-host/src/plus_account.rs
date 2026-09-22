//! Account status delegated to the installed `grok` CLI.
//!
//! GB Plus never reads or writes token material. The CLI owns
//! `$GROK_HOME/auth.json`, refresh, OAuth, and server validation.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const GROK_CLI_OVERRIDE_ENV: &str = "GROK_BUILD_GROK_CLI";
const ACCOUNT_PROBE_TIMEOUT: Duration = Duration::from_secs(12);
const ACCOUNT_OUTPUT_CAP: u64 = 64 * 1024;

/// Honest account connection state proven through the installed CLI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusAccountState {
    /// `true` only after `grok models` validates the stored CLI session.
    pub connected: bool,
    /// Whether an executable `grok` CLI was found.
    pub cli_available: bool,
    /// Plain status word for the Account page.
    pub status: &'static str,
    /// Human-actionable detail with no token material.
    pub detail: String,
    /// Executable path used for login and validation, when found.
    pub cli_path: Option<PathBuf>,
}

impl PlusAccountState {
    /// Deterministic disconnected state for tests and pre-probe UI.
    #[must_use]
    pub fn not_connected_for_test() -> Self {
        Self {
            connected: false,
            cli_available: false,
            status: "Not connected",
            detail: "Install the grok CLI, then run `grok login`.".into(),
            cli_path: None,
        }
    }
}

/// Finds the same `grok` executable a terminal session would use and asks it
/// to validate its own stored account by listing available models.
#[must_use]
pub fn probe_plus_grok_account() -> PlusAccountState {
    let Some(cli) = find_grok_cli() else {
        return PlusAccountState::not_connected_for_test();
    };
    probe_plus_grok_account_at(&cli)
}

/// Starts the CLI-owned `SpaceXAI` OAuth flow, then validates the resulting
/// session through the CLI. No credential bytes cross this API.
///
/// # Errors
///
/// Returns a process-launch error when the installed CLI cannot start.
pub fn connect_plus_grok_account() -> Result<PlusAccountState, String> {
    let Some(cli) = find_grok_cli() else {
        return Ok(PlusAccountState::not_connected_for_test());
    };
    let status = Command::new(&cli)
        .args(["login", "--oauth"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot start `grok login --oauth`: {error}"))?;
    if !status.success() {
        return Ok(PlusAccountState {
            connected: false,
            cli_available: true,
            status: "Not connected",
            detail: format!(
                "`grok login --oauth` exited {status}. Run `grok login` in Terminal for details."
            ),
            cli_path: Some(cli),
        });
    }
    Ok(probe_plus_grok_account_at(&cli))
}

fn probe_plus_grok_account_at(cli: &Path) -> PlusAccountState {
    match run_account_probe(cli) {
        Ok(true) => PlusAccountState {
            connected: true,
            cli_available: true,
            status: "Connected",
            detail: "Validated by `grok models` using the CLI-owned SpaceXAI session.".into(),
            cli_path: Some(cli.to_path_buf()),
        },
        Ok(false) => PlusAccountState {
            connected: false,
            cli_available: true,
            status: "Not connected",
            detail:
                "The grok CLI is installed, but it did not validate a session. Run `grok login`."
                    .into(),
            cli_path: Some(cli.to_path_buf()),
        },
        Err(detail) => PlusAccountState {
            connected: false,
            cli_available: true,
            status: "Not connected",
            detail,
            cli_path: Some(cli.to_path_buf()),
        },
    }
}

fn run_account_probe(cli: &Path) -> Result<bool, String> {
    let mut child = Command::new(cli)
        .arg("models")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start `grok models`: {error}"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < ACCOUNT_PROBE_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(
                    "The grok CLI account check timed out. Run `grok models` in Terminal.".into(),
                );
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot wait for `grok models`: {error}"));
            }
        }
    };
    let mut output = String::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout.take(ACCOUNT_OUTPUT_CAP).read_to_string(&mut output);
    }
    if let Some(stderr) = child.stderr.take() {
        let _ = stderr.take(ACCOUNT_OUTPUT_CAP).read_to_string(&mut output);
    }
    if !status.success() {
        return Ok(false);
    }
    Ok(output.contains("You are logged in with grok.com.") && output.contains("Available models:"))
}

fn find_grok_cli() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(configured) = std::env::var_os(GROK_CLI_OVERRIDE_ENV) {
        candidates.push(PathBuf::from(configured));
    }
    if let Some(grok_home) = std::env::var_os("GROK_HOME") {
        candidates.push(PathBuf::from(grok_home).join("bin/grok"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".grok/bin/grok"));
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(
            std::env::split_paths(&path)
                .filter(|directory| directory.is_absolute())
                .map(|directory| directory.join("grok")),
        );
    }
    candidates
        .into_iter()
        .find(|candidate| executable_file(candidate))
}

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::probe_plus_grok_account_at;

    #[cfg(unix)]
    fn fake_cli(root: &Path, body: &str) -> PathBuf {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        fs::create_dir_all(root).expect("create fake-cli root");
        let path = root.join("grok");
        let mut file = fs::File::create(&path).expect("create fake grok");
        writeln!(file, "#!/bin/sh\n{body}").expect("write fake grok");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make fake grok executable");
        path
    }

    #[cfg(unix)]
    #[test]
    fn account_is_connected_only_after_cli_validation_markers() {
        let root =
            std::env::temp_dir().join(format!("grok-build-account-test-{}", std::process::id()));
        let connected = fake_cli(
            &root,
            "printf 'You are logged in with grok.com.\\nAvailable models:\\n  * grok-4.6\\n'",
        );
        assert!(probe_plus_grok_account_at(&connected).connected);
        let disconnected = fake_cli(&root, "printf 'login required\\n'; exit 1");
        assert!(!probe_plus_grok_account_at(&disconnected).connected);
        fs::remove_dir_all(root).expect("remove fake-cli root");
    }
}
