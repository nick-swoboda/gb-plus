//! Open a project file next to chat and highlight a pending proposal.

use std::path::Path;

use super::plus_proposal::present_pending_file_diff;
use super::plus_tools::{PLUS_SEARCH_NO_MATCHES, PLUS_SEARCH_TRUNCATED, plus_tool_read_file};
use super::{BoundProject, PendingFileSet, PlusToolName, PlusToolStep};

/// Reads a relative file and, if it is pending, appends its unified diff.
#[must_use]
pub fn present_plus_file_pane(
    bound: &BoundProject,
    relative: impl AsRef<Path>,
    pending: &PendingFileSet,
) -> String {
    let relative = relative.as_ref();
    let body = plus_tool_read_file(bound, relative).unwrap_or_else(|error| error.to_string());
    let mut out = format!("file {}\n{body}", relative.display());
    if let Some(proposal) = pending
        .items
        .iter()
        .find(|item| item.relative_path == relative)
    {
        out.push_str("\nPending proposal:\n");
        out.push_str(&present_pending_file_diff(proposal));
    }
    out
}

/// First relative path from a `grep` result (`path:line:text`). I/O-free.
#[must_use]
pub fn plus_first_grep_hit_path(result: &str) -> Option<&str> {
    for line in result.lines() {
        if line.contains(PLUS_SEARCH_NO_MATCHES) || line.contains(PLUS_SEARCH_TRUNCATED) {
            continue;
        }
        let mut parts = line.splitn(3, ':');
        let path = parts.next().unwrap_or("");
        let lineno = parts.next().unwrap_or("");
        if path.is_empty() || !lineno.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if parts.next().is_some() {
            return Some(path);
        }
    }
    None
}

/// Last successful grep step's first hit, if any.
#[must_use]
pub fn plus_file_path_from_tool_steps(steps: &[PlusToolStep]) -> Option<&str> {
    steps.iter().rev().find_map(|step| {
        if step.name == PlusToolName::Grep && step.ok {
            plus_first_grep_hit_path(&step.result)
        } else {
            None
        }
    })
}
