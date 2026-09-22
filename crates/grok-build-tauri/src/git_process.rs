//! Fixed, bounded Git child-process boundary shared by user-only Git surfaces.

use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use crate::child_environment::ChildEnvironmentProfile;

pub(crate) const MAX_GIT_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_GIT_ERROR_BYTES: usize = 8 * 1024;
const GIT_EXECUTABLE: &str = "/usr/bin/git";
const GIT_PROCESS_TIMEOUT: Duration = Duration::from_mins(1);
const MAX_GIT_INPUT_BYTES: usize = 64 * 1024 * 1024;

pub(crate) struct GitOutput {
    status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl GitOutput {
    pub(crate) fn success(&self) -> bool {
        self.status.success()
    }

    pub(crate) fn code(&self) -> Option<i32> {
        self.status.code()
    }
}

pub(crate) fn git_command(root: &Path) -> Command {
    let mut command = Command::new(GIT_EXECUTABLE);
    ChildEnvironmentProfile::Git.apply(&mut command);
    command
        // Git inspection may refresh index stat data unless optional locks are
        // disabled. Required locks for user-requested mutations are unaffected.
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("credential.helper=")
        .arg("-c")
        .arg("commit.gpgSign=false")
        .arg("-C")
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

pub(crate) fn run_git(
    command: Command,
    stdin: Option<&[u8]>,
    limit: usize,
) -> Result<GitOutput, String> {
    let output = crate::bounded_process::collect(
        command,
        stdin.unwrap_or_default(),
        &crate::bounded_process::Limits {
            input: MAX_GIT_INPUT_BYTES,
            output: limit,
            error: MAX_GIT_ERROR_BYTES,
            timeout: GIT_PROCESS_TIMEOUT,
        },
    )?;
    Ok(GitOutput {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

pub(crate) fn require_git_success(output: GitOutput, action: &str) -> Result<Vec<u8>, String> {
    if output.status.success() {
        return Ok(output.stdout);
    }
    let detail = sanitized_git_error(&output.stderr);
    Err(format!(
        "Git could not {action} (exit {}). {detail}",
        output.status
    ))
}

pub(crate) fn require_git_difference(output: GitOutput, action: &str) -> Result<Vec<u8>, String> {
    if output.status.success() || output.status.code() == Some(1) {
        return Ok(output.stdout);
    }
    let detail = sanitized_git_error(&output.stderr);
    Err(format!(
        "Git could not {action} (exit {}). {detail}",
        output.status
    ))
}

fn sanitized_git_error(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut sanitized = String::with_capacity(text.len());
    for character in text.chars() {
        if character == '\n' || character == '\t' || !character.is_control() {
            sanitized.push(character);
        }
    }
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        "Git returned no additional detail.".into()
    } else {
        sanitized.to_owned()
    }
}

#[cfg(test)]
#[path = "git_process/tests.rs"]
mod tests;
