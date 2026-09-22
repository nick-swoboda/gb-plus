//! Official Grok CLI OAuth launch and bounded output sanitization.

use super::process::find_grok_cli;
use super::{
    ACP_OAUTH_LOG_CAP, ACP_OAUTH_OUTPUT_STREAM_CAP, ACP_OAUTH_TIMEOUT, ChildEnvironmentProfile,
    Command, Duration, Path, Read, Stdio,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GrokCliOAuthPhase {
    OpeningBrowser,
    WaitingForSignIn,
}

#[derive(Debug)]
pub(crate) struct GrokCliOAuthOutput {
    pub(crate) sanitized_log: String,
}

#[derive(Debug)]
pub(crate) struct GrokCliOAuthFailure {
    pub(crate) message: String,
    pub(crate) sanitized_log: String,
}

/// Runs the installed CLI-owned OAuth flow with a cleared, nonsecret child
/// environment. Success does not imply Connected; Account must still execute
/// the strict ACP live-path probe afterward.
pub(crate) fn run_grok_cli_oauth(
    phase: impl Fn(GrokCliOAuthPhase),
) -> Result<GrokCliOAuthOutput, GrokCliOAuthFailure> {
    let cli = find_grok_cli().ok_or_else(|| GrokCliOAuthFailure {
        message: "The grok CLI is not installed. Install it, then try Connect with Grok Subscription again."
            .to_owned(),
        sanitized_log: String::new(),
    })?;
    run_grok_cli_oauth_at(&cli, phase)
}

pub(super) fn run_grok_cli_oauth_at(
    cli: &Path,
    phase: impl Fn(GrokCliOAuthPhase),
) -> Result<GrokCliOAuthOutput, GrokCliOAuthFailure> {
    let _operation =
        crate::runtime::cli::operation_guard().map_err(|message| GrokCliOAuthFailure {
            message,
            sanitized_log: String::new(),
        })?;
    let mut command = Command::new(cli);
    command
        .args(["login", "--oauth"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    ChildEnvironmentProfile::OAuth.apply(&mut command);
    let auth_path =
        crate::runtime::auth_paths::cli_auth_path().map_err(|message| GrokCliOAuthFailure {
            message,
            sanitized_log: String::new(),
        })?;
    command.env("GROK_AUTH_PATH", auth_path);
    phase(GrokCliOAuthPhase::OpeningBrowser);
    let mut child = command.spawn().map_err(|error| GrokCliOAuthFailure {
        message: format!("Cannot start `grok login --oauth`: {error}"),
        sanitized_log: String::new(),
    })?;
    let stdout = child.stdout.take().map(spawn_oauth_output_reader);
    let stderr = child.stderr.take().map(spawn_oauth_output_reader);
    phase(GrokCliOAuthPhase::WaitingForSignIn);
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                return Ok(GrokCliOAuthOutput {
                    sanitized_log: collect_oauth_output(stdout, stderr),
                });
            }
            Ok(Some(status)) => {
                return Err(GrokCliOAuthFailure {
                    message: format!(
                        "`grok login --oauth` exited {status}. Expand Show details for sanitized CLI output."
                    ),
                    sanitized_log: collect_oauth_output(stdout, stderr),
                });
            }
            Ok(None) if started.elapsed() < ACP_OAUTH_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(GrokCliOAuthFailure {
                    message:
                        "`grok login --oauth` did not finish within five minutes; no connection was claimed."
                            .into(),
                    sanitized_log: collect_oauth_output(stdout, stderr),
                });
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(GrokCliOAuthFailure {
                    message: format!("Cannot wait for `grok login --oauth`: {error}"),
                    sanitized_log: collect_oauth_output(stdout, stderr),
                });
            }
        }
    }
}

pub(super) fn spawn_oauth_output_reader(
    mut reader: impl Read + Send + 'static,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::with_capacity(ACP_OAUTH_OUTPUT_STREAM_CAP + 1);
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let retained_limit = ACP_OAUTH_OUTPUT_STREAM_CAP + 1;
                    let remaining = retained_limit.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&buffer[..count.min(remaining)]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        bytes
    })
}

pub(super) fn collect_oauth_output(
    stdout: Option<std::thread::JoinHandle<Vec<u8>>>,
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
) -> String {
    let stdout = stdout
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    let stderr = stderr
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    sanitize_oauth_output(&stdout, &stderr)
}

pub(super) fn sanitize_oauth_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut sanitized = String::new();
    for (label, bytes) in [("stdout", stdout), ("stderr", stderr)] {
        if bytes.is_empty() {
            continue;
        }
        sanitized.push_str(label);
        sanitized.push_str(":\n");
        let truncated = bytes.len() > ACP_OAUTH_OUTPUT_STREAM_CAP;
        let bytes = &bytes[..bytes.len().min(ACP_OAUTH_OUTPUT_STREAM_CAP)];
        for line in String::from_utf8_lossy(bytes).lines() {
            if sanitized.len() >= ACP_OAUTH_LOG_CAP {
                break;
            }
            let line = sanitize_oauth_line(line);
            sanitized.push_str(&line);
            sanitized.push('\n');
        }
        if truncated {
            sanitized.push_str("[output truncated at 32 KiB]\n");
        }
    }
    if sanitized.is_empty() {
        "No CLI output was emitted. The live ACP connection check remains authoritative.".to_owned()
    } else {
        if sanitized.len() > ACP_OAUTH_LOG_CAP {
            let mut end = ACP_OAUTH_LOG_CAP;
            while !sanitized.is_char_boundary(end) {
                end -= 1;
            }
            sanitized.truncate(end);
        }
        sanitized
    }
}

pub(super) fn sanitize_oauth_line(line: &str) -> String {
    const MAX_LINE_BYTES: usize = 512;
    let mut line = line.replace(|character: char| character.is_control(), " ");
    while let Some(index) = line.find("https://").or_else(|| line.find("http://")) {
        let end = line[index..]
            .find(char::is_whitespace)
            .map_or(line.len(), |offset| index + offset);
        line.replace_range(index..end, "[URL withheld]");
    }
    let lowercase = line.to_ascii_lowercase();
    let sensitive = [
        "access_token",
        "refresh_token",
        "authorization",
        "bearer ",
        "api_key",
        "api key",
        "client_secret",
        "credential",
        "xai-",
        "code=",
        "code:",
        "verification code",
    ]
    .iter()
    .any(|marker| lowercase.contains(marker));
    if sensitive || line.split_whitespace().any(|part| part.len() > 128) {
        return "[redacted sensitive CLI line]".to_owned();
    }
    if line.len() > MAX_LINE_BYTES {
        let mut end = MAX_LINE_BYTES;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
        line.push('…');
    }
    line
}
