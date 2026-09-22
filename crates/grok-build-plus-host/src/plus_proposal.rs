//! Pending file proposal for the GB Plus window.
//!
//! This is a desktop/core *model*, not a ledger event and not
//! `HumanAcceptancePresentationV1`. Accept writes the proposed bytes only
//! after the staged snapshot still matches. Reject never writes. In-file groups
//! are derived from the original before/after; decisions are stored on
//! the proposal so remaining groups are not recomputed from disk.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, Mode, OFlags, mkdirat, open, openat, unlinkat};

use serde::{Deserialize, Serialize};

use super::{BoundProject, PlusChatTurn, PlusHostError};

/// Sample relative path used by the window Propose button.
pub const PLUS_SAMPLE_PROPOSAL_PATH: &str = "gb-plus-proposed.txt";

/// Single-file relative path for an assistant response proposed as a change.
pub const PLUS_ASSISTANT_PROPOSAL_PATH: &str = "gb-plus-assistant.txt";

/// Inbox heading for still-pending Accept work.
pub const PLUS_NEEDS_ACCEPT: &str = "Needs Accept";

/// Window / presentation label for in-file group Accept.
pub const PLUS_ACCEPT_GROUP: &str = "Accept group";

/// Window / presentation label for in-file group Reject.
pub const PLUS_REJECT_GROUP: &str = "Reject group";

/// One or more relative workspace files waiting for accept or reject.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingFileSet {
    /// Pending files, in proposal order.
    #[serde(default)]
    pub items: Vec<PendingFileProposal>,
}

impl PendingFileSet {
    /// Replaces an existing path or appends a new proposal.
    pub fn upsert(&mut self, proposal: PendingFileProposal) {
        if let Some(existing) = self
            .items
            .iter_mut()
            .find(|item| item.relative_path == proposal.relative_path)
        {
            *existing = proposal;
        } else {
            self.items.push(proposal);
        }
    }
}

/// Accept or reject already applied to one named group.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingGroupDecision {
    /// Deterministic group id for this proposal (`1`, `2`, …).
    pub id: String,
    /// `true` when the group's `after` was written; `false` when rejected.
    pub accepted: bool,
}

/// One disjoint change group inside a pending file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingLineGroup {
    /// Deterministic id (`1`, `2`, …) for this proposal's groups.
    pub id: String,
    /// Original lines in this group (no trailing newlines).
    pub before: Vec<String>,
    /// Proposed lines in this group (no trailing newlines).
    pub after: Vec<String>,
}

/// Relative workspace file waiting for accept or reject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingFileProposal {
    /// Workspace-relative path shown in the diff.
    pub relative_path: PathBuf,
    /// Original bytes on disk when the proposal was staged (empty if absent).
    pub before: Vec<u8>,
    /// Whether the staged path existed. `None` identifies a legacy proposal
    /// that predates descriptor-bound snapshots and therefore cannot be
    /// accepted safely.
    #[serde(default)]
    pub before_existed: Option<bool>,
    /// Proposed replacement bytes.
    pub after: Vec<u8>,
    /// Group Accept/Reject decisions. Empty means every group is still pending.
    #[serde(default)]
    pub group_decisions: Vec<PendingGroupDecision>,
}

/// Builds a proposal from the file that is on disk now.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the path escapes the workspace.
pub fn propose_pending_file(
    bound: &BoundProject,
    relative_path: impl Into<PathBuf>,
    after: impl Into<Vec<u8>>,
) -> Result<PendingFileProposal, PlusHostError> {
    let relative_path = relative_path.into();
    let (before_existed, before) = snapshot_workspace_file(bound.folder(), &relative_path)?;
    Ok(PendingFileProposal {
        relative_path,
        before,
        before_existed: Some(before_existed),
        after: after.into(),
        group_decisions: Vec::new(),
    })
}

/// Stages several relative files without writing any of them.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when any path is invalid.
pub fn propose_pending_files(
    bound: &BoundProject,
    files: impl IntoIterator<Item = (PathBuf, Vec<u8>)>,
) -> Result<PendingFileSet, PlusHostError> {
    let mut set = PendingFileSet::default();
    for (relative_path, after) in files {
        set.upsert(propose_pending_file(bound, relative_path, after)?);
    }
    Ok(set)
}

/// Stages the window's sample file proposal without writing it.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the workspace path is invalid.
pub fn propose_sample_plus_file(
    bound: &BoundProject,
) -> Result<PendingFileProposal, PlusHostError> {
    propose_pending_file(
        bound,
        PLUS_SAMPLE_PROPOSAL_PATH,
        b"Proposed by GB Plus\n".to_vec(),
    )
}

/// Stages one assistant response as a pending file change. Does not write.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the assistant text is empty or
/// the workspace path is invalid.
pub fn propose_assistant_response_as_file(
    bound: &BoundProject,
    turn: &PlusChatTurn,
) -> Result<PendingFileProposal, PlusHostError> {
    propose_assistant_text_as_file(bound, &turn.assistant_text)
}

/// Stages assistant text as a pending file change. Does not write.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the text is empty or the
/// workspace path is invalid.
pub fn propose_assistant_text_as_file(
    bound: &BoundProject,
    assistant_text: &str,
) -> Result<PendingFileProposal, PlusHostError> {
    if assistant_text.trim().is_empty() {
        return Err(PlusHostError::Proposal(
            "assistant response is empty; cannot propose a file change".into(),
        ));
    }
    propose_pending_file(
        bound,
        PLUS_ASSISTANT_PROPOSAL_PATH,
        assistant_text.as_bytes().to_vec(),
    )
}

/// Disjoint change groups for a pending file, from the original before/after.
#[must_use]
pub fn pending_line_groups(proposal: &PendingFileProposal) -> Vec<PendingLineGroup> {
    let (before, _) = split_lines(&proposal.before);
    let (after, _) = split_lines(&proposal.after);
    line_segments(&before, &after)
        .into_iter()
        .filter_map(|segment| match segment {
            LineSegment::Equal(_) => None,
            LineSegment::Change { id, before, after } => {
                Some(PendingLineGroup { id, before, after })
            }
        })
        .collect()
}

/// Groups that still need Accept or Reject.
#[must_use]
pub fn remaining_pending_groups(proposal: &PendingFileProposal) -> Vec<PendingLineGroup> {
    pending_line_groups(proposal)
        .into_iter()
        .filter(|group| {
            !proposal
                .group_decisions
                .iter()
                .any(|decision| decision.id == group.id)
        })
        .collect()
}

/// Normalizes `1` / `group 1` to the stored id.
#[must_use]
pub fn normalize_group_id(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix("group ")
        .or_else(|| trimmed.strip_prefix("Group "))
        .unwrap_or(trimmed)
        .trim()
        .to_owned()
}

/// Unified-style presentation of a pending proposal. Includes the path and
/// remaining groups as hunks (or the whole before/after when there is one group).
#[must_use]
pub fn present_pending_file_diff(proposal: &PendingFileProposal) -> String {
    let path = proposal.relative_path.display();
    let groups = remaining_pending_groups(proposal);
    let mut out = format!("--- a/{path}\n+++ b/{path}\n");
    if groups.is_empty() {
        let before = String::from_utf8_lossy(&proposal.before);
        let after = String::from_utf8_lossy(&proposal.after);
        if before.is_empty() && after.is_empty() {
            out.push_str("@@ empty proposal @@\n");
            return out;
        }
        out.push_str("@@\n");
        append_minus_plus(&mut out, &before, &after);
        return out;
    }
    for group in &groups {
        let _ = writeln!(out, "@@ group {} @@", group.id);
        for line in &group.before {
            out.push('-');
            out.push_str(line);
            out.push('\n');
        }
        for line in &group.after {
            out.push('+');
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn append_minus_plus(out: &mut String, before: &str, after: &str) {
    for line in before.lines() {
        out.push('-');
        out.push_str(line);
        out.push('\n');
    }
    if !before.is_empty() && !before.ends_with('\n') {
        out.push_str("\\ No newline at end of before\n");
    }
    for line in after.lines() {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }
    if !after.is_empty() && !after.ends_with('\n') {
        out.push_str("\\ No newline at end of after\n");
    }
}

/// Concatenated unified diffs for every pending path, with a review header
/// that names each relative path as still **pending**.
#[must_use]
pub fn present_pending_file_set(set: &PendingFileSet) -> String {
    present_pending_review(set)
}

/// First-class pending review: each path (and remaining group) is listed as
/// pending, then diffs.
#[must_use]
pub fn present_pending_review(set: &PendingFileSet) -> String {
    if set.items.is_empty() {
        return "No pending file proposal.".into();
    }
    let mut out = format!("Pending review ({} files):\n", set.items.len());
    for item in &set.items {
        let _ = writeln!(out, "{}: pending", item.relative_path.display());
        for group in remaining_pending_groups(item) {
            let _ = writeln!(out, "  group {}: pending", group.id);
        }
    }
    out.push('\n');
    out.push_str(
        &set.items
            .iter()
            .map(present_pending_file_diff)
            .collect::<Vec<_>>()
            .join("\n"),
    );
    out
}

/// Still-pending relative paths after session switch/restore.
#[must_use]
pub fn present_needs_accept_inbox(set: &PendingFileSet) -> String {
    if set.items.is_empty() {
        return format!("{PLUS_NEEDS_ACCEPT}\n(none)");
    }
    let mut out = format!("{PLUS_NEEDS_ACCEPT}\n");
    for item in &set.items {
        let _ = writeln!(out, "{}", item.relative_path.display());
    }
    out
}

/// Writes the proposed bytes into the bound workspace.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] on path or I/O failure.
pub fn accept_pending_file_proposal(
    bound: &BoundProject,
    proposal: &PendingFileProposal,
) -> Result<(), PlusHostError> {
    write_verified_workspace_bytes(bound, proposal, &proposal.after)
}

/// Rejects the staged intent without touching the workspace.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] on path or I/O failure.
pub fn reject_pending_file_proposal(
    _bound: &BoundProject,
    _proposal: &PendingFileProposal,
) -> Result<(), PlusHostError> {
    Ok(())
}

/// Writes every pending `after`. Does not skip failures.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] on the first path or I/O failure.
pub fn accept_pending_file_set(
    bound: &BoundProject,
    set: &PendingFileSet,
) -> Result<(), PlusHostError> {
    for proposal in &set.items {
        accept_pending_file_proposal(bound, proposal)?;
    }
    Ok(())
}

/// Verifies every proposal in a set against the current descriptor-bound
/// workspace state without writing any file.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] before the first write when any path is
/// stale, unsafe, or lacks a verified snapshot.
pub fn preflight_pending_file_set(
    bound: &BoundProject,
    set: &PendingFileSet,
) -> Result<(), PlusHostError> {
    for proposal in &set.items {
        preflight_pending_file_proposal(bound, proposal)?;
    }
    Ok(())
}

/// Restores the exact bytes that were current immediately before a whole-file
/// Accept, or removes a file that did not exist before that Accept.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the accepted bytes are no longer
/// exact or the descriptor-bound rollback cannot complete.
pub fn rollback_accepted_file_proposal(
    bound: &BoundProject,
    proposal: &PendingFileProposal,
) -> Result<(), PlusHostError> {
    let original_existed = proposal.before_existed.ok_or_else(|| {
        PlusHostError::Proposal(format!(
            "cannot recover legacy proposal {} because it has no verified filesystem snapshot",
            proposal.relative_path.display()
        ))
    })?;
    let before_accept = compose_current_bytes(proposal);
    let existed_before_accept = original_existed
        || proposal
            .group_decisions
            .iter()
            .any(|decision| decision.accepted);
    if existed_before_accept {
        let inverse = PendingFileProposal {
            relative_path: proposal.relative_path.clone(),
            before: proposal.after.clone(),
            before_existed: Some(true),
            after: before_accept,
            group_decisions: Vec::new(),
        };
        write_verified_workspace_bytes(bound, &inverse, &inverse.after)
    } else {
        remove_verified_accepted_file(bound, proposal)
    }
}

/// Rejects every pending intent without touching workspace files.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] on the first path or I/O failure.
pub fn reject_pending_file_set(
    bound: &BoundProject,
    set: &PendingFileSet,
) -> Result<(), PlusHostError> {
    for proposal in &set.items {
        reject_pending_file_proposal(bound, proposal)?;
    }
    Ok(())
}

/// Accepts one relative path and returns the remaining set.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the path is missing or I/O fails.
pub fn accept_pending_file_in_set(
    bound: &BoundProject,
    set: &PendingFileSet,
    relative_path: impl AsRef<Path>,
) -> Result<PendingFileSet, PlusHostError> {
    apply_one_in_set(bound, set, relative_path.as_ref(), true)
}

/// Rejects one relative path and returns the remaining set.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the path is missing or I/O fails.
pub fn reject_pending_file_in_set(
    bound: &BoundProject,
    set: &PendingFileSet,
    relative_path: impl AsRef<Path>,
) -> Result<PendingFileSet, PlusHostError> {
    apply_one_in_set(bound, set, relative_path.as_ref(), false)
}

/// Accepts one named group inside a still-pending file. Sibling groups stay
/// pending. Writes the composed bytes (group `after` plus remaining `before`).
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the path or group is missing.
pub fn accept_pending_group_in_set(
    bound: &BoundProject,
    set: &PendingFileSet,
    relative_path: impl AsRef<Path>,
    group_id: &str,
) -> Result<PendingFileSet, PlusHostError> {
    apply_group_in_set(bound, set, relative_path.as_ref(), group_id, true)
}

/// Rejects one named group inside a still-pending file. Does not revert
/// already-accepted sibling groups.
///
/// # Errors
///
/// Returns [`PlusHostError::Proposal`] when the path or group is missing.
pub fn reject_pending_group_in_set(
    bound: &BoundProject,
    set: &PendingFileSet,
    relative_path: impl AsRef<Path>,
    group_id: &str,
) -> Result<PendingFileSet, PlusHostError> {
    apply_group_in_set(bound, set, relative_path.as_ref(), group_id, false)
}

fn apply_one_in_set(
    bound: &BoundProject,
    set: &PendingFileSet,
    relative_path: &Path,
    accept: bool,
) -> Result<PendingFileSet, PlusHostError> {
    let mut remaining = PendingFileSet::default();
    let mut found = false;
    for proposal in &set.items {
        if proposal.relative_path == relative_path {
            found = true;
            if accept {
                accept_pending_file_proposal(bound, proposal)?;
            } else {
                reject_pending_file_proposal(bound, proposal)?;
            }
        } else {
            remaining.items.push(proposal.clone());
        }
    }
    if found {
        Ok(remaining)
    } else {
        Err(PlusHostError::Proposal(format!(
            "no pending proposal for {}",
            relative_path.display()
        )))
    }
}

fn apply_group_in_set(
    bound: &BoundProject,
    set: &PendingFileSet,
    relative_path: &Path,
    group_id: &str,
    accept: bool,
) -> Result<PendingFileSet, PlusHostError> {
    let group_id = normalize_group_id(group_id);
    let mut remaining = PendingFileSet::default();
    let mut found_path = false;
    for proposal in &set.items {
        if proposal.relative_path != relative_path {
            remaining.items.push(proposal.clone());
            continue;
        }
        found_path = true;
        let groups = pending_line_groups(proposal);
        if !groups.iter().any(|group| group.id == group_id) {
            return Err(PlusHostError::Proposal(format!(
                "no pending group {group_id} for {}",
                relative_path.display()
            )));
        }
        if proposal
            .group_decisions
            .iter()
            .any(|decision| decision.id == group_id)
        {
            return Err(PlusHostError::Proposal(format!(
                "group {group_id} already decided for {}",
                relative_path.display()
            )));
        }
        let mut updated = proposal.clone();
        updated.group_decisions.push(PendingGroupDecision {
            id: group_id.clone(),
            accepted: accept,
        });
        if accept {
            let composed = compose_current_bytes(&updated);
            write_verified_workspace_bytes(bound, proposal, &composed)?;
        }
        if remaining_pending_groups(&updated).is_empty() {
            continue;
        }
        remaining.items.push(updated);
    }
    if found_path {
        Ok(remaining)
    } else {
        Err(PlusHostError::Proposal(format!(
            "no pending proposal for {}",
            relative_path.display()
        )))
    }
}

fn compose_current_bytes(proposal: &PendingFileProposal) -> Vec<u8> {
    let (before_lines, before_nl) = split_lines(&proposal.before);
    let (after_lines, after_nl) = split_lines(&proposal.after);
    let segments = line_segments(&before_lines, &after_lines);
    let mut lines = Vec::new();
    for segment in segments {
        match segment {
            LineSegment::Equal(equal) => lines.extend(equal),
            LineSegment::Change { id, before, after } => {
                let accepted = proposal
                    .group_decisions
                    .iter()
                    .find(|decision| decision.id == id)
                    .map(|decision| decision.accepted);
                match accepted {
                    Some(true) => lines.extend(after),
                    Some(false) | None => lines.extend(before),
                }
            }
        }
    }
    join_lines(&lines, before_nl || after_nl)
}

fn preflight_pending_file_proposal(
    bound: &BoundProject,
    proposal: &PendingFileProposal,
) -> Result<(), PlusHostError> {
    let original_existed = proposal.before_existed.ok_or_else(|| {
        PlusHostError::Proposal(format!(
            "cannot accept legacy proposal {}: it has no verified filesystem snapshot; reject it and stage a fresh proposal",
            proposal.relative_path.display()
        ))
    })?;
    let expected = compose_current_bytes(proposal);
    let expected_existed = original_existed
        || proposal
            .group_decisions
            .iter()
            .any(|decision| decision.accepted);
    let (current_existed, current) =
        snapshot_workspace_file(bound.folder(), &proposal.relative_path)?;
    if current_existed != expected_existed || current != expected {
        return Err(stale_proposal_error(&proposal.relative_path));
    }
    Ok(())
}

fn remove_verified_accepted_file(
    bound: &BoundProject,
    proposal: &PendingFileProposal,
) -> Result<(), PlusHostError> {
    let (parent, leaf) = open_workspace_parent(bound.folder(), &proposal.relative_path, false)?
        .ok_or_else(|| stale_proposal_error(&proposal.relative_path))?;
    let descriptor = openat(
        &parent,
        leaf.as_os_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| stale_proposal_error(&proposal.relative_path))?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|error| {
        PlusHostError::Proposal(format!(
            "cannot inspect accepted file {} for recovery: {error}",
            proposal.relative_path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(PlusHostError::Proposal(format!(
            "cannot recover {} because the accepted path is not a regular file",
            proposal.relative_path.display()
        )));
    }
    let current = read_opened_file(&mut file, &metadata, &proposal.relative_path)?;
    if current != proposal.after {
        return Err(PlusHostError::Proposal(format!(
            "cannot recover {} because it changed after Accept",
            proposal.relative_path.display()
        )));
    }
    unlinkat(&parent, leaf.as_os_str(), AtFlags::empty()).map_err(|error| {
        PlusHostError::Proposal(format!(
            "cannot remove newly accepted file {} during recovery: {error}",
            proposal.relative_path.display()
        ))
    })?;
    parent.sync_all().map_err(|error| {
        PlusHostError::Proposal(format!(
            "cannot sync recovery parent for {}: {error}",
            proposal.relative_path.display()
        ))
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "descriptor identity, stale checks, atomic write, and post-write verification form one fail-closed Accept boundary"
)]
fn write_verified_workspace_bytes(
    bound: &BoundProject,
    proposal: &PendingFileProposal,
    bytes: &[u8],
) -> Result<(), PlusHostError> {
    let original_existed = proposal.before_existed.ok_or_else(|| {
        PlusHostError::Proposal(format!(
            "cannot accept legacy proposal {}: it has no verified filesystem snapshot; reject it and stage a fresh proposal",
            proposal.relative_path.display()
        ))
    })?;
    let expected_bytes = compose_current_bytes(proposal);
    let expected_existed = original_existed
        || proposal
            .group_decisions
            .iter()
            .any(|decision| decision.accepted);
    let (parent, leaf) = open_workspace_parent(bound.folder(), &proposal.relative_path, true)?
        .ok_or_else(|| PlusHostError::Proposal("cannot create verified workspace parent".into()))?;
    let opened = openat(
        &parent,
        leaf.as_os_str(),
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    );
    if expected_existed {
        let descriptor = opened.map_err(|error| {
            PlusHostError::Proposal(format!(
                "cannot accept {} because its staged file is unavailable or unsafe: {error}",
                proposal.relative_path.display()
            ))
        })?;
        let mut file = File::from(descriptor);
        let opened_metadata = file.metadata().map_err(|error| {
            PlusHostError::Proposal(format!(
                "cannot inspect staged file {}: {error}",
                proposal.relative_path.display()
            ))
        })?;
        if !opened_metadata.is_file() {
            return Err(PlusHostError::Proposal(format!(
                "cannot accept {} because the staged path is not a regular file",
                proposal.relative_path.display()
            )));
        }
        let current = read_opened_file(&mut file, &opened_metadata, &proposal.relative_path)?;
        if current != expected_bytes {
            return Err(stale_proposal_error(&proposal.relative_path));
        }
        file.seek(SeekFrom::Start(0)).map_err(|error| {
            PlusHostError::Proposal(format!(
                "cannot seek staged file {}: {error}",
                proposal.relative_path.display()
            ))
        })?;
        file.write_all(bytes).map_err(|error| {
            PlusHostError::Proposal(format!(
                "cannot accept {}: {error}",
                proposal.relative_path.display()
            ))
        })?;
        file.set_len(bytes.len() as u64).map_err(|error| {
            PlusHostError::Proposal(format!(
                "cannot truncate accepted file {}: {error}",
                proposal.relative_path.display()
            ))
        })?;
        file.sync_all().map_err(|error| {
            PlusHostError::Proposal(format!(
                "cannot durably accept {}: {error}",
                proposal.relative_path.display()
            ))
        })?;
        let rebound = openat(
            &parent,
            leaf.as_os_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            PlusHostError::Proposal(format!(
                "accepted file {} changed identity during write: {error}",
                proposal.relative_path.display()
            ))
        })?;
        if !same_file_identity(
            &opened_metadata,
            &rebound.metadata().map_err(|error| {
                PlusHostError::Proposal(format!(
                    "cannot recheck accepted file {}: {error}",
                    proposal.relative_path.display()
                ))
            })?,
        ) {
            return Err(PlusHostError::Proposal(format!(
                "accepted file {} changed identity during write; success was not recorded",
                proposal.relative_path.display()
            )));
        }
        parent.sync_all().map_err(|error| {
            PlusHostError::Proposal(format!(
                "cannot sync parent for {}: {error}",
                proposal.relative_path.display()
            ))
        })?;
        Ok(())
    } else {
        match opened {
            Ok(_) => Err(stale_proposal_error(&proposal.relative_path)),
            Err(error) if error == rustix::io::Errno::NOENT => {
                let descriptor = openat(
                    &parent,
                    leaf.as_os_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(|error| {
                    PlusHostError::Proposal(format!(
                        "cannot accept newly staged file {}: {error}",
                        proposal.relative_path.display()
                    ))
                })?;
                let mut file = File::from(descriptor);
                file.write_all(bytes).map_err(|error| {
                    PlusHostError::Proposal(format!(
                        "cannot accept {}: {error}",
                        proposal.relative_path.display()
                    ))
                })?;
                file.sync_all().map_err(|error| {
                    PlusHostError::Proposal(format!(
                        "cannot durably accept {}: {error}",
                        proposal.relative_path.display()
                    ))
                })?;
                parent.sync_all().map_err(|error| {
                    PlusHostError::Proposal(format!(
                        "cannot sync parent for {}: {error}",
                        proposal.relative_path.display()
                    ))
                })
            }
            Err(error) => Err(PlusHostError::Proposal(format!(
                "cannot verify newly staged file {}: {error}",
                proposal.relative_path.display()
            ))),
        }
    }
}

fn stale_proposal_error(relative_path: &Path) -> PlusHostError {
    PlusHostError::Proposal(format!(
        "cannot accept {} because the file changed after staging; refresh and stage a new proposal",
        relative_path.display()
    ))
}

enum LineSegment {
    Equal(Vec<String>),
    Change {
        id: String,
        before: Vec<String>,
        after: Vec<String>,
    },
}

fn split_lines(bytes: &[u8]) -> (Vec<String>, bool) {
    let text = String::from_utf8_lossy(bytes);
    let ends_with_newline = text.ends_with('\n');
    if text.is_empty() {
        return (Vec::new(), false);
    }
    (text.lines().map(str::to_owned).collect(), ends_with_newline)
}

fn join_lines(lines: &[String], ends_with_newline: bool) -> Vec<u8> {
    if lines.is_empty() {
        return Vec::new();
    }
    let mut text = lines.join("\n");
    if ends_with_newline {
        text.push('\n');
    }
    text.into_bytes()
}

fn line_segments(before: &[String], after: &[String]) -> Vec<LineSegment> {
    let pairs = matching_pairs(before, after);
    let mut segments = Vec::new();
    let mut next_id = 1_u32;
    let mut i = 0;
    let mut j = 0;
    for &(ai, bj) in &pairs {
        if i < ai || j < bj {
            segments.push(LineSegment::Change {
                id: next_id.to_string(),
                before: before[i..ai].to_vec(),
                after: after[j..bj].to_vec(),
            });
            next_id += 1;
        }
        push_equal(&mut segments, before[ai].clone());
        i = ai + 1;
        j = bj + 1;
    }
    if i < before.len() || j < after.len() {
        segments.push(LineSegment::Change {
            id: next_id.to_string(),
            before: before[i..].to_vec(),
            after: after[j..].to_vec(),
        });
    }
    segments
}

fn push_equal(segments: &mut Vec<LineSegment>, line: String) {
    if let Some(LineSegment::Equal(lines)) = segments.last_mut() {
        lines.push(line);
    } else {
        segments.push(LineSegment::Equal(vec![line]));
    }
}

fn matching_pairs(before: &[String], after: &[String]) -> Vec<(usize, usize)> {
    let n = before.len();
    let m = after.len();
    if n == 0 || m == 0 || n > 512 || m > 512 {
        return Vec::new();
    }
    let mut dp = vec![vec![0_usize; m + 1]; n + 1];
    for i in 0..n {
        for j in 0..m {
            dp[i + 1][j + 1] = if before[i] == after[j] {
                dp[i][j] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut pairs = Vec::new();
    let mut i = n;
    let mut j = m;
    while i > 0 && j > 0 {
        if before[i - 1] == after[j - 1] && dp[i][j] == dp[i - 1][j - 1] + 1 {
            pairs.push((i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    pairs.reverse();
    pairs
}

fn snapshot_workspace_file(root: &Path, relative: &Path) -> Result<(bool, Vec<u8>), PlusHostError> {
    let Some((parent, leaf)) = open_workspace_parent(root, relative, false)? else {
        return Ok((false, Vec::new()));
    };
    let descriptor = match openat(
        &parent,
        leaf.as_os_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok((false, Vec::new())),
        Err(error) => {
            return Err(PlusHostError::Proposal(format!(
                "cannot stage {} because its path is unavailable or unsafe: {error}",
                relative.display()
            )));
        }
    };
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|error| {
        PlusHostError::Proposal(format!(
            "cannot inspect staged file {}: {error}",
            relative.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(PlusHostError::Proposal(format!(
            "cannot stage {} because it is not a regular file",
            relative.display()
        )));
    }
    read_opened_file(&mut file, &metadata, relative).map(|bytes| (true, bytes))
}

fn read_opened_file(
    file: &mut File,
    opened_metadata: &fs::Metadata,
    relative: &Path,
) -> Result<Vec<u8>, PlusHostError> {
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes).map_err(|error| {
        PlusHostError::Proposal(format!("cannot read {}: {error}", relative.display()))
    })?;
    let after = file.metadata().map_err(|error| {
        PlusHostError::Proposal(format!(
            "cannot recheck staged file {}: {error}",
            relative.display()
        ))
    })?;
    if !same_file_snapshot(opened_metadata, &after) {
        return Err(PlusHostError::Proposal(format!(
            "cannot use {} because it changed while being read",
            relative.display()
        )));
    }
    Ok(bytes)
}

fn open_workspace_root(root: &Path) -> Result<File, PlusHostError> {
    open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        PlusHostError::Proposal(format!(
            "workspace root is unavailable or unsafe (symlinks are refused): {error}"
        ))
    })
}

fn open_workspace_parent(
    root: &Path,
    relative: &Path,
    create: bool,
) -> Result<Option<(File, OsString)>, PlusHostError> {
    validate_workspace_file(relative)?;
    let mut components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(PlusHostError::Proposal(format!(
                "workspace path contains a non-normal component: {}",
                relative.display()
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = components.pop().ok_or_else(|| {
        PlusHostError::Proposal("workspace file path has no final component".into())
    })?;
    let mut directory = open_workspace_root(root)?;
    for component in components {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let next = match openat(&directory, component.as_os_str(), flags, Mode::empty()) {
            Ok(next) => next,
            Err(error) if error == rustix::io::Errno::NOENT && !create => return Ok(None),
            Err(error) if error == rustix::io::Errno::NOENT => {
                match mkdirat(
                    &directory,
                    component.as_os_str(),
                    Mode::from_raw_mode(0o700),
                ) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => {
                        return Err(PlusHostError::Proposal(format!(
                            "cannot create verified workspace directory {}: {error}",
                            component.to_string_lossy()
                        )));
                    }
                }
                openat(&directory, component.as_os_str(), flags, Mode::empty()).map_err(
                    |error| {
                        PlusHostError::Proposal(format!(
                            "cannot bind new workspace directory {}: {error}",
                            component.to_string_lossy()
                        ))
                    },
                )?
            }
            Err(error) => {
                return Err(PlusHostError::Proposal(format!(
                    "workspace directory {} is unavailable or unsafe: {error}",
                    component.to_string_lossy()
                )));
            }
        };
        directory = File::from(next);
    }
    Ok(Some((directory, leaf)))
}

fn validate_workspace_file(relative: &Path) -> Result<(), PlusHostError> {
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        Err(PlusHostError::Proposal(format!(
            "proposal path must be a relative workspace file: {}",
            relative.display()
        )))
    } else {
        Ok(())
    }
}

pub(crate) fn open_workspace_node(root: &Path, relative: &Path) -> Result<File, PlusHostError> {
    let Some((parent, leaf)) = open_workspace_parent(root, relative, false)? else {
        return Err(PlusHostError::Proposal(format!(
            "workspace path does not exist: {}",
            relative.display()
        )));
    };
    openat(
        &parent,
        leaf.as_os_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        PlusHostError::Proposal(format!(
            "workspace path is unavailable or unsafe (symlinks are refused) {}: {error}",
            relative.display()
        ))
    })
}

pub(crate) fn open_workspace_directory(
    root: &Path,
    relative: &Path,
) -> Result<File, PlusHostError> {
    if relative.as_os_str().is_empty() || relative == Path::new(".") {
        return open_workspace_root(root);
    }
    let Some((parent, leaf)) = open_workspace_parent(root, relative, false)? else {
        return Err(PlusHostError::Proposal(format!(
            "workspace directory does not exist: {}",
            relative.display()
        )));
    };
    openat(
        &parent,
        leaf.as_os_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        PlusHostError::Proposal(format!(
            "workspace directory is unavailable or unsafe (symlinks are refused) {}: {error}",
            relative.display()
        ))
    })
}

pub(crate) fn read_workspace_file_bytes(
    root: &Path,
    relative: &Path,
    limit: usize,
) -> Result<Vec<u8>, PlusHostError> {
    let mut file = open_workspace_node(root, relative)?;
    let opened = file.metadata().map_err(|error| {
        PlusHostError::Proposal(format!("cannot inspect {}: {error}", relative.display()))
    })?;
    if !opened.is_file() {
        return Err(PlusHostError::Proposal(format!(
            "workspace path is not a regular file: {}",
            relative.display()
        )));
    }
    if opened.len() > limit as u64 {
        return Err(PlusHostError::Proposal(format!(
            "workspace file exceeds {limit} bytes: {}",
            relative.display()
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    std::io::Read::by_ref(&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            PlusHostError::Proposal(format!("cannot read {}: {error}", relative.display()))
        })?;
    let after = file.metadata().map_err(|error| {
        PlusHostError::Proposal(format!("cannot recheck {}: {error}", relative.display()))
    })?;
    if bytes.len() > limit || !same_file_snapshot(&opened, &after) {
        return Err(PlusHostError::Proposal(format!(
            "workspace file changed while being read: {}",
            relative.display()
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

#[cfg(unix)]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    same_file_identity(left, right)
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_file_identity(left, right)
}

pub(crate) fn workspace_file(root: &Path, relative: &Path) -> Result<PathBuf, PlusHostError> {
    validate_workspace_file(relative)?;
    Ok(root.join(relative))
}
