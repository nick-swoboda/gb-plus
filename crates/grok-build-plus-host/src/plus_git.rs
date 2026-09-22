//! Minimal git status / diffstat / commit of accepted paths only.
//! Thin GitHub/PR via `gh` on PATH; missing `gh` is a presented skip.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::plus_proposal::workspace_file;
use super::{BoundProject, PlusHostError};

/// Presented when `gh` is not on `PATH`.
pub const PLUS_GH_MISSING: &str = "gh not on PATH; skip GitHub/PR";

/// Window / presentation label for opening a PR with `gh`.
pub const PLUS_GH_OPEN_PR: &str = "open PR";

/// Window button label for GitHub status.
pub const PLUS_GH_STATUS: &str = "GitHub status";

/// Result of a thin GitHub/PR helper. Missing `gh` is a skip, not a hard error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusGithubReport {
    /// True when `gh` was not on PATH (or the supplied PATH).
    pub skipped: bool,
    /// Presentation for the window.
    pub text: String,
}

/// Combined short status and diffstat for the bound folder.
#[must_use]
pub fn plus_git_status_report(bound: &BoundProject) -> String {
    let status = plus_git_output(bound.folder(), &["status", "--short"]);
    let diffstat = plus_git_output(bound.folder(), &["diff", "--stat"]);
    format!("git status --short\n{status}\n\ngit diff --stat\n{diffstat}")
}

/// Commits only the given relative paths after an explicit user action.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when no paths were accepted, a path
/// escapes the workspace, or git fails.
pub fn plus_git_commit_accepted(
    bound: &BoundProject,
    relative_paths: &[PathBuf],
    message: &str,
) -> Result<String, PlusHostError> {
    if relative_paths.is_empty() {
        return Err(PlusHostError::Proposal(
            "commit refused: no accepted files".into(),
        ));
    }
    let message = message.trim();
    if message.is_empty() {
        return Err(PlusHostError::Proposal(
            "commit refused: message must not be empty".into(),
        ));
    }
    let mut args = vec!["add".into(), "--".into()];
    for relative in relative_paths {
        let _ = workspace_file(bound.folder(), relative)?;
        args.push(relative.display().to_string());
    }
    let added = plus_git_output(
        bound.folder(),
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    if added.contains("not a git repository") || added.contains("git failed") {
        return Err(PlusHostError::Proposal(added));
    }
    let mut commit_args = vec!["commit".into(), "-m".into(), message.into(), "--".into()];
    for relative in relative_paths {
        commit_args.push(relative.display().to_string());
    }
    let committed = plus_git_output(
        bound.folder(),
        &commit_args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    if committed.contains("git failed") || committed.contains("not a git repository") {
        return Err(PlusHostError::Proposal(committed));
    }
    Ok(format!("committed accepted files\n{committed}"))
}

/// GitHub PR status for the bound folder via `gh` on `PATH`.
#[must_use]
pub fn plus_github_status_report(bound: &BoundProject) -> PlusGithubReport {
    plus_github_status_on_path(bound, std::env::var_os("PATH").as_deref())
}

/// Same helper with an explicit `PATH` so tests can drive missing vs stub `gh`.
#[must_use]
pub fn plus_github_status_on_path(bound: &BoundProject, path: Option<&OsStr>) -> PlusGithubReport {
    plus_github_invoke(bound, path, &["pr", "status"], "GitHub status")
}

/// Opens (or views) a PR via `gh` on `PATH`.
#[must_use]
pub fn plus_github_open_pr(bound: &BoundProject) -> PlusGithubReport {
    plus_github_open_pr_on_path(bound, std::env::var_os("PATH").as_deref())
}

/// Same open-PR helper with an explicit `PATH`.
#[must_use]
pub fn plus_github_open_pr_on_path(bound: &BoundProject, path: Option<&OsStr>) -> PlusGithubReport {
    plus_github_invoke(bound, path, &["pr", "view", "--web"], PLUS_GH_OPEN_PR)
}

fn plus_github_invoke(
    bound: &BoundProject,
    path: Option<&OsStr>,
    args: &[&str],
    heading: &str,
) -> PlusGithubReport {
    let Some(gh) = gh_on_path(path) else {
        return PlusGithubReport {
            skipped: true,
            text: PLUS_GH_MISSING.to_owned(),
        };
    };
    match Command::new(&gh)
        .args(args)
        .current_dir(bound.folder())
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut body = stdout.trim_end().to_owned();
            if !stderr.trim().is_empty() {
                if !body.is_empty() {
                    body.push('\n');
                }
                body.push_str(stderr.trim_end());
            }
            if body.is_empty() {
                body = format!("{heading}: (empty gh output)");
            }
            let invoked = format!("gh {}", args.join(" "));
            PlusGithubReport {
                skipped: false,
                text: format!("{heading}\n{invoked}\n{body}"),
            }
        }
        Err(error) => PlusGithubReport {
            skipped: true,
            text: format!("{PLUS_GH_MISSING} ({error})"),
        },
    }
}

fn gh_on_path(path: Option<&OsStr>) -> Option<PathBuf> {
    let path = path?;
    for dir in std::env::split_paths(path) {
        let candidate = dir.join("gh");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn plus_git_output(folder: &Path, args: &[&str]) -> String {
    match Command::new("git")
        .arg("-C")
        .arg(folder)
        .args(args)
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut text = stdout.trim_end().to_owned();
            if !output.status.success() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(stderr.trim_end());
                if text.contains("not a git repository") {
                    return text;
                }
                if text.is_empty() {
                    text = format!("git failed ({})", output.status);
                }
            }
            if text.is_empty() {
                "(clean)".into()
            } else {
                text
            }
        }
        Err(error) => format!("git failed: {error}"),
    }
}
