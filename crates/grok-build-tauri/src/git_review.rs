//! User-only per-hunk Git Review lane, separate from Agent Proposals/Accept.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use grok_build_plus_host::{
    PlusKnownProject, PlusSessionStore, bind_project_folder, worktree_recovery_digest,
};
use serde::Serialize;

use crate::git_process::{
    MAX_GIT_METADATA_BYTES, git_command, require_git_difference, require_git_success, run_git,
};

const MAX_REVIEW_FILES: usize = 500;
const MAX_REVIEW_HUNKS: usize = 2_000;
const MAX_REVIEW_PATCH_BYTES: usize = 16 * 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 4 * 1024;
const GIT_REVIEW_OPERATIONS_FILE: &str = "plus-git-review-operations.jsonl";

static NEXT_GIT_REVIEW_OPERATION: AtomicU64 = AtomicU64::new(1);
static GIT_REVIEW_MUTATION_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
type BeforeHunkApplyHook = (String, Box<dyn FnOnce() + Send>);
#[cfg(test)]
static BEFORE_HUNK_APPLY_HOOK: Mutex<Option<BeforeHunkApplyHook>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GitLane {
    Staged,
    Unstaged,
}

impl GitLane {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Unstaged => "unstaged",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HunkAction {
    Stage,
    Unstage,
    Discard,
}

impl HunkAction {
    const fn lane(self) -> GitLane {
        match self {
            Self::Stage | Self::Discard => GitLane::Unstaged,
            Self::Unstage => GitLane::Staged,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Stage => "stage-hunk",
            Self::Unstage => "unstage-hunk",
            Self::Discard => "discard-hunk",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitHunkView {
    id: String,
    path: String,
    lane: &'static str,
    header: String,
    diff: String,
    added_lines: usize,
    removed_lines: usize,
    index_identity: String,
    worktree_identity: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitFileReviewView {
    path: String,
    lane: &'static str,
    change_kind: &'static str,
    binary: bool,
    conflicted: bool,
    detail: String,
    hunks: Vec<GitHunkView>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitReviewView {
    project_id: String,
    root: String,
    available: bool,
    status: String,
    truncated: bool,
    conflict_paths: Vec<String>,
    staged_files: Vec<GitFileReviewView>,
    unstaged_files: Vec<GitFileReviewView>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitHunkActionView {
    pub(crate) outcome: &'static str,
    pub(crate) detail: String,
    pub(crate) review: GitReviewView,
}

#[derive(Clone)]
struct GitHunkRecord {
    view: GitHunkView,
    lane: GitLane,
    relative_path: PathBuf,
    patch: Vec<u8>,
    semantic_body: Vec<u8>,
}

struct GitReviewScan {
    view: GitReviewView,
    records: HashMap<String, GitHunkRecord>,
}

#[derive(Serialize)]
struct GitReviewOperation<'a> {
    schema_version: u16,
    sequence: u64,
    timestamp_unix_ms: u64,
    project_id: &'a str,
    root: String,
    hunk_id: &'a str,
    operation: &'a str,
    state: &'a str,
}

pub(crate) fn list_git_review(project: &PlusKnownProject) -> GitReviewView {
    scan_git_review(project).view
}

pub(crate) fn stage_git_hunk(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    hunk_id: &str,
) -> Result<GitHunkActionView, String> {
    mutate_hunk(store, project, hunk_id, HunkAction::Stage, None)
}

pub(crate) fn unstage_git_hunk(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    hunk_id: &str,
) -> Result<GitHunkActionView, String> {
    mutate_hunk(store, project, hunk_id, HunkAction::Unstage, None)
}

pub(crate) fn discard_git_hunk(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    hunk_id: &str,
    confirmation: &str,
) -> Result<GitHunkActionView, String> {
    mutate_hunk(
        store,
        project,
        hunk_id,
        HunkAction::Discard,
        Some(confirmation),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the user-only hunk effect, semantic state verification, rollback, and durable outcome are one serialized security boundary"
)]
fn mutate_hunk(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    hunk_id: &str,
    action: HunkAction,
    confirmation: Option<&str>,
) -> Result<GitHunkActionView, String> {
    let _mutation_guard = GIT_REVIEW_MUTATION_LOCK
        .lock()
        .map_err(|_| "Git Review mutation lock is unavailable; action refused.".to_owned())?;
    validate_hunk_id(hunk_id)?;
    validate_action_confirmation(action, hunk_id, confirmation)?;

    let initial = scan_git_review(project);
    if !initial.view.available {
        append_operation(store, project, hunk_id, action, "refused-unavailable")?;
        return Ok(refused(
            initial.view,
            "Git hunk action refused because Git Review is unavailable.",
        ));
    }
    if !initial.view.conflict_paths.is_empty() {
        append_operation(store, project, hunk_id, action, "refused-conflict")?;
        return Ok(refused(
            initial.view,
            "Git hunk action refused while unresolved conflicts are present. Resolve and refresh first.",
        ));
    }
    if matching_record(&initial, hunk_id, action.lane()).is_none() {
        append_operation(store, project, hunk_id, action, "refused-stale")?;
        return Ok(refused(
            initial.view,
            "Git hunk identity is stale or belongs to another lane. Refresh before acting.",
        ));
    }

    append_operation(store, project, hunk_id, action, "intent")?;
    let before_check = scan_git_review(project);
    if matching_record(&before_check, hunk_id, action.lane()).is_none() {
        append_operation(
            store,
            project,
            hunk_id,
            action,
            "refused-drift-before-check",
        )?;
        return Ok(refused(
            before_check.view,
            "Repository state changed before validation. Nothing was applied; refresh and retry.",
        ));
    }
    let before_effect = scan_git_review(project);
    let Some(record) = matching_record(&before_effect, hunk_id, action.lane()).cloned() else {
        append_operation(
            store,
            project,
            hunk_id,
            action,
            "refused-drift-before-effect",
        )?;
        return Ok(refused(
            before_effect.view,
            "Repository state changed after validation. Nothing was applied; refresh and retry.",
        ));
    };
    #[cfg(test)]
    run_before_hunk_apply_hook(hunk_id);
    if let Err(error) = apply_patch(project.active_root(), &record.patch, action) {
        append_operation(store, project, hunk_id, action, "failed")?;
        let review = scan_git_review(project).view;
        return Ok(refused(
            review,
            format!("Git refused the hunk during application. {error}"),
        ));
    }

    let after = scan_git_review(project);
    if !exact_hunk_transition(
        project.active_root(),
        &before_effect,
        &after,
        &record,
        action,
    ) {
        let rollback = rollback_patch(project.active_root(), &record.patch, action);
        let rollback_state = if rollback.is_ok() {
            "failed-drift-rolled-back"
        } else {
            "failed-drift-rollback-failed"
        };
        append_operation(store, project, hunk_id, action, rollback_state)?;
        let review = scan_git_review(project).view;
        let detail = if let Err(rollback_error) = rollback {
            format!(
                "Repository state drifted during the hunk action. Success was not recorded, and the inverse patch was refused ({rollback_error}); refresh and inspect the exact Git state."
            )
        } else {
            "Repository state drifted during the hunk action. The selected effect was rolled back; refresh before retrying."
                .into()
        };
        return Ok(refused(review, detail));
    }
    append_operation(store, project, hunk_id, action, "effect-complete")?;
    Ok(GitHunkActionView {
        outcome: match action {
            HunkAction::Stage => "staged",
            HunkAction::Unstage => "unstaged",
            HunkAction::Discard => "discarded",
        },
        detail: match action {
            HunkAction::Stage => {
                "Selected hunk staged in the Git index. Agent Proposals were not touched."
            }
            HunkAction::Unstage => {
                "Selected hunk removed from the Git index and left in the worktree."
            }
            HunkAction::Discard => {
                "Explicitly confirmed worktree hunk discarded. The Git index was not changed."
            }
        }
        .into(),
        review: after.view,
    })
}

#[cfg(test)]
fn run_before_hunk_apply_hook(hunk_id: &str) {
    let hook = BEFORE_HUNK_APPLY_HOOK
        .lock()
        .expect("test hunk hook lock")
        .take();
    if let Some((expected_id, hook)) = hook {
        if expected_id == hunk_id {
            hook();
        } else {
            *BEFORE_HUNK_APPLY_HOOK.lock().expect("restore test hook") = Some((expected_id, hook));
        }
    }
}

fn validate_action_confirmation(
    action: HunkAction,
    hunk_id: &str,
    confirmation: Option<&str>,
) -> Result<(), String> {
    if action != HunkAction::Discard {
        return Ok(());
    }
    let required = format!("DISCARD HUNK {}", &hunk_id[..12]);
    if confirmation == Some(required.as_str()) {
        Ok(())
    } else {
        Err(format!(
            "Discard requires the exact confirmation `{required}`."
        ))
    }
}

fn refused(view: GitReviewView, detail: impl Into<String>) -> GitHunkActionView {
    GitHunkActionView {
        outcome: "refused",
        detail: detail.into(),
        review: view,
    }
}

fn matching_record<'a>(
    scan: &'a GitReviewScan,
    hunk_id: &str,
    lane: GitLane,
) -> Option<&'a GitHunkRecord> {
    scan.records
        .get(hunk_id)
        .filter(|record| record.lane == lane && record.view.id == hunk_id)
}

fn exact_hunk_transition(
    root: &Path,
    before: &GitReviewScan,
    after: &GitReviewScan,
    selected: &GitHunkRecord,
    action: HunkAction,
) -> bool {
    if !after.view.available || !after.view.conflict_paths.is_empty() {
        return false;
    }
    let mut expected = path_hunk_semantics(before, &selected.relative_path);
    let Some(position) = expected
        .iter()
        .position(|(lane, body)| *lane == action.lane() && *body == selected.semantic_body)
    else {
        return false;
    };
    expected.remove(position);
    match action {
        HunkAction::Stage => expected.push((GitLane::Staged, selected.semantic_body.clone())),
        HunkAction::Unstage => expected.push((GitLane::Unstaged, selected.semantic_body.clone())),
        HunkAction::Discard => {}
    }
    expected.sort();
    let actual = path_hunk_semantics(after, &selected.relative_path);
    if actual != expected || after.records.contains_key(&selected.view.id) {
        return false;
    }

    let Ok(after_index) = index_identity(root, &selected.relative_path) else {
        return false;
    };
    let Ok(after_worktree) = worktree_identity(root, &selected.relative_path) else {
        return false;
    };
    match action {
        HunkAction::Stage | HunkAction::Unstage => {
            after_worktree == selected.view.worktree_identity
                && after_index != selected.view.index_identity
        }
        HunkAction::Discard => {
            after_index == selected.view.index_identity
                && after_worktree != selected.view.worktree_identity
        }
    }
}

fn path_hunk_semantics(scan: &GitReviewScan, path: &Path) -> Vec<(GitLane, Vec<u8>)> {
    let mut semantics = scan
        .records
        .values()
        .filter(|record| record.relative_path == path)
        .map(|record| (record.lane, record.semantic_body.clone()))
        .collect::<Vec<_>>();
    semantics.sort();
    semantics
}

fn validate_hunk_id(hunk_id: &str) -> Result<(), String> {
    if hunk_id.len() == 64 && hunk_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("Git hunk identity is malformed.".into())
    }
}

fn scan_git_review(project: &PlusKnownProject) -> GitReviewScan {
    let root = project.active_root();
    if let Err(error) = verify_repository_root(root) {
        return unavailable_scan(project, error);
    }
    let conflict_paths = match name_list(root, NameList::Conflicted) {
        Ok(paths) => paths,
        Err(error) => return unavailable_scan(project, error),
    };
    let conflict_bytes: BTreeSet<Vec<u8>> = conflict_paths.iter().cloned().collect();
    let shown_conflicts = conflict_paths
        .iter()
        .map(|path| display_git_path(path))
        .collect::<Vec<_>>();
    let staged_paths = match name_list(root, NameList::Staged) {
        Ok(paths) => paths,
        Err(error) => return unavailable_scan(project, error),
    };
    let mut unstaged_paths = match name_list(root, NameList::Unstaged) {
        Ok(paths) => paths,
        Err(error) => return unavailable_scan(project, error),
    };
    let untracked_paths = match name_list(root, NameList::Untracked) {
        Ok(paths) => paths,
        Err(error) => return unavailable_scan(project, error),
    };
    let untracked_set: BTreeSet<Vec<u8>> = untracked_paths.iter().cloned().collect();
    unstaged_paths.extend(untracked_paths);
    unstaged_paths.sort();
    unstaged_paths.dedup();

    let mut records = HashMap::new();
    let mut staged_files = Vec::new();
    let mut unstaged_files = Vec::new();
    let mut totals = ScanTotals::default();
    scan_lane(
        project,
        GitLane::Staged,
        &staged_paths,
        &conflict_bytes,
        &BTreeSet::new(),
        &mut staged_files,
        &mut records,
        &mut totals,
    );
    scan_lane(
        project,
        GitLane::Unstaged,
        &unstaged_paths,
        &conflict_bytes,
        &untracked_set,
        &mut unstaged_files,
        &mut records,
        &mut totals,
    );
    let file_count = staged_files.len() + unstaged_files.len();
    let hunk_count = records.len();
    let status = if shown_conflicts.is_empty() {
        if file_count == 0 {
            "Git working tree and index are clean.".into()
        } else if totals.truncated {
            format!(
                "Showing a bounded partial Git view: {file_count} file entries and {hunk_count} hunks."
            )
        } else {
            format!("{file_count} Git file entries · {hunk_count} actionable text hunks.")
        }
    } else {
        format!(
            "{} unresolved conflict path(s). Hunk actions refuse until resolved.",
            shown_conflicts.len()
        )
    };
    GitReviewScan {
        view: GitReviewView {
            project_id: project.id.to_string(),
            root: root.display().to_string(),
            available: true,
            status,
            truncated: totals.truncated,
            conflict_paths: shown_conflicts,
            staged_files,
            unstaged_files,
        },
        records,
    }
}

#[derive(Default)]
struct ScanTotals {
    files: usize,
    hunks: usize,
    patch_bytes: usize,
    truncated: bool,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn scan_lane(
    project: &PlusKnownProject,
    lane: GitLane,
    paths: &[Vec<u8>],
    conflicts: &BTreeSet<Vec<u8>>,
    untracked: &BTreeSet<Vec<u8>>,
    files: &mut Vec<GitFileReviewView>,
    records: &mut HashMap<String, GitHunkRecord>,
    totals: &mut ScanTotals,
) {
    for path_bytes in paths {
        if totals.files >= MAX_REVIEW_FILES
            || totals.hunks >= MAX_REVIEW_HUNKS
            || totals.patch_bytes >= MAX_REVIEW_PATCH_BYTES
        {
            totals.truncated = true;
            break;
        }
        let Ok(relative_path) = path_from_git_bytes(path_bytes) else {
            files.push(unsupported_file(
                display_git_path(path_bytes),
                lane,
                "unsupported",
                "Git returned a malformed path; no hunk action is available.",
                false,
            ));
            totals.files += 1;
            continue;
        };
        if let Err(error) = validate_relative_path(&relative_path) {
            files.push(unsupported_file(
                display_git_path(path_bytes),
                lane,
                "unsupported",
                &error,
                false,
            ));
            totals.files += 1;
            continue;
        }
        let shown = display_git_path(path_bytes);
        if conflicts.contains(path_bytes) {
            files.push(unsupported_file(
                shown,
                lane,
                "conflicted",
                "Unresolved conflict; resolve it outside hunk actions and refresh.",
                true,
            ));
            totals.files += 1;
            continue;
        }
        let is_untracked = lane == GitLane::Unstaged && untracked.contains(path_bytes);
        let diff_bytes =
            match diff_for_path(project.active_root(), lane, &relative_path, is_untracked) {
                Ok(diff_bytes) => diff_bytes,
                Err(error) => {
                    files.push(unsupported_file(
                        shown,
                        lane,
                        if is_untracked {
                            "untracked"
                        } else {
                            "unsupported"
                        },
                        &error,
                        false,
                    ));
                    totals.files += 1;
                    continue;
                }
            };
        totals.patch_bytes = totals.patch_bytes.saturating_add(diff_bytes.len());
        if totals.patch_bytes > MAX_REVIEW_PATCH_BYTES {
            totals.truncated = true;
            break;
        }
        let index_identity = match index_identity(project.active_root(), &relative_path) {
            Ok(identity) => identity,
            Err(error) => {
                files.push(unsupported_file(shown, lane, "unsupported", &error, false));
                totals.files += 1;
                continue;
            }
        };
        let worktree_identity = match worktree_identity(project.active_root(), &relative_path) {
            Ok(identity) => identity,
            Err(error) => {
                files.push(unsupported_file(shown, lane, "unsupported", &error, false));
                totals.files += 1;
                continue;
            }
        };
        let parsed = parse_file_patch(
            project,
            lane,
            &relative_path,
            shown,
            &diff_bytes,
            &index_identity,
            &worktree_identity,
            is_untracked,
        );
        let (file, file_records) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                files.push(unsupported_file(
                    display_path(&relative_path),
                    lane,
                    "unsupported",
                    &error,
                    false,
                ));
                totals.files += 1;
                continue;
            }
        };
        if totals.hunks.saturating_add(file_records.len()) > MAX_REVIEW_HUNKS {
            totals.truncated = true;
            break;
        }
        totals.hunks += file_records.len();
        totals.files += 1;
        for record in file_records {
            records.insert(record.view.id.clone(), record);
        }
        files.push(file);
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn parse_file_patch(
    project: &PlusKnownProject,
    lane: GitLane,
    relative_path: &Path,
    shown: String,
    diff_bytes: &[u8],
    index_identity: &str,
    worktree_identity: &str,
    is_untracked: bool,
) -> Result<(GitFileReviewView, Vec<GitHunkRecord>), String> {
    let hunk_starts = line_starts(diff_bytes)
        .into_iter()
        .filter(|start| diff_bytes[*start..].starts_with(b"@@ "))
        .collect::<Vec<_>>();
    let binary = diff_bytes
        .windows(b"GIT binary patch".len())
        .any(|window| window == b"GIT binary patch")
        || diff_bytes
            .windows(b"Binary files".len())
            .any(|window| window == b"Binary files");
    let change_kind = if is_untracked {
        "untracked"
    } else if diff_bytes
        .windows(b"new file mode".len())
        .any(|window| window == b"new file mode")
    {
        "added"
    } else if diff_bytes
        .windows(b"deleted file mode".len())
        .any(|window| window == b"deleted file mode")
    {
        "deleted"
    } else if hunk_starts.is_empty() {
        "mode change"
    } else {
        "modified"
    };
    if binary || hunk_starts.is_empty() {
        return Ok((
            GitFileReviewView {
                path: shown,
                lane: lane.as_str(),
                change_kind,
                binary,
                conflicted: false,
                detail: if binary {
                    "Binary change shown for status only; per-hunk actions refuse.".into()
                } else {
                    "No textual hunk is available for this Git change.".into()
                },
                hunks: Vec::new(),
            },
            Vec::new(),
        ));
    }
    let header = &diff_bytes[..hunk_starts[0]];
    let mut views = Vec::with_capacity(hunk_starts.len());
    let mut records = Vec::with_capacity(hunk_starts.len());
    for (index, start) in hunk_starts.iter().enumerate() {
        let end = hunk_starts
            .get(index + 1)
            .copied()
            .unwrap_or(diff_bytes.len());
        let body = &diff_bytes[*start..end];
        let hunk_patch = [header, body].concat();
        let header_line = body
            .split(|byte| *byte == b'\n')
            .next()
            .ok_or_else(|| "Git hunk header is missing.".to_owned())?;
        let header_text = String::from_utf8(header_line.to_vec())
            .map_err(|_| "Git hunk header is not UTF-8.".to_owned())?;
        let (added_lines, removed_lines) = hunk_line_counts(body);
        let id = hunk_identity(
            project,
            lane,
            relative_path,
            index_identity,
            worktree_identity,
            &hunk_patch,
        );
        let view = GitHunkView {
            id: id.clone(),
            path: shown.clone(),
            lane: lane.as_str(),
            header: header_text,
            diff: String::from_utf8_lossy(body).into_owned(),
            added_lines,
            removed_lines,
            index_identity: index_identity.to_owned(),
            worktree_identity: worktree_identity.to_owned(),
        };
        views.push(view.clone());
        records.push(GitHunkRecord {
            view,
            lane,
            relative_path: relative_path.to_path_buf(),
            patch: hunk_patch,
            semantic_body: body
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or_else(Vec::new, |line_end| body[line_end + 1..].to_vec()),
        });
    }
    Ok((
        GitFileReviewView {
            path: shown,
            lane: lane.as_str(),
            change_kind,
            binary: false,
            conflicted: false,
            detail: format!(
                "{} text hunk(s); each action revalidates index and worktree identity.",
                views.len()
            ),
            hunks: views,
        },
        records,
    ))
}

fn unavailable_scan(project: &PlusKnownProject, status: String) -> GitReviewScan {
    GitReviewScan {
        view: GitReviewView {
            project_id: project.id.to_string(),
            root: project.active_root().display().to_string(),
            available: false,
            status,
            truncated: false,
            conflict_paths: Vec::new(),
            staged_files: Vec::new(),
            unstaged_files: Vec::new(),
        },
        records: HashMap::new(),
    }
}

fn unsupported_file(
    path: String,
    lane: GitLane,
    change_kind: &'static str,
    detail: &str,
    conflicted: bool,
) -> GitFileReviewView {
    GitFileReviewView {
        path,
        lane: lane.as_str(),
        change_kind,
        binary: false,
        conflicted,
        detail: detail.to_owned(),
        hunks: Vec::new(),
    }
}

#[derive(Clone, Copy)]
enum NameList {
    Staged,
    Unstaged,
    Untracked,
    Conflicted,
}

fn name_list(root: &Path, kind: NameList) -> Result<Vec<Vec<u8>>, String> {
    let mut command = git_command(root);
    match kind {
        NameList::Untracked => {
            command
                .arg("ls-files")
                .arg("--others")
                .arg("--exclude-standard")
                .arg("-z")
                .arg("--");
        }
        NameList::Staged | NameList::Unstaged | NameList::Conflicted => {
            command.arg("diff");
            if matches!(kind, NameList::Staged) {
                command.arg("--cached");
            }
            if matches!(kind, NameList::Conflicted) {
                command.arg("--diff-filter=U");
            }
            command
                .arg("--name-only")
                .arg("--no-renames")
                .arg("-z")
                .arg("--");
        }
    }
    let output = require_git_success(
        run_git(command, None, MAX_GIT_METADATA_BYTES)?,
        "list Git changes",
    )?;
    let mut paths = output
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn diff_for_path(
    root: &Path,
    lane: GitLane,
    path: &Path,
    untracked: bool,
) -> Result<Vec<u8>, String> {
    let mut command = git_command(root);
    command.arg("diff");
    if untracked {
        command.arg("--no-index");
    } else if lane == GitLane::Staged {
        command.arg("--cached");
    }
    command
        .arg("--binary")
        .arg("--full-index")
        .arg("--no-ext-diff")
        .arg("--no-textconv")
        .arg("--no-color")
        .arg("--no-renames")
        .arg("--unified=3")
        .arg("--");
    if untracked {
        command.arg("/dev/null");
    }
    command.arg(path);
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES)?;
    if untracked {
        require_git_difference(output, "render the untracked Git change")
    } else {
        require_git_success(output, "render the Git change")
    }
}

fn verify_repository_root(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root.join(".git")).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "Git Changes are unavailable because the active workspace is not a Git working tree."
                .to_owned()
        } else {
            format!("Cannot inspect active Git metadata: {error}")
        }
    })?;
    if !(metadata.file_type().is_file() || metadata.file_type().is_dir()) {
        return Err(
            "Git Changes are unavailable because .git is not a regular file or directory.".into(),
        );
    }
    let bound = bind_project_folder(root).map_err(|error| error.to_string())?;
    let mut command = git_command(root);
    command.arg("rev-parse").arg("--show-toplevel");
    let bytes = require_git_success(
        run_git(command, None, MAX_GIT_METADATA_BYTES)?,
        "inspect the Git root",
    )?;
    let line = single_git_line(&bytes, "Git root")?;
    let reported = path_from_git_bytes(line.as_bytes())?
        .canonicalize()
        .map_err(|error| format!("Cannot canonicalize Git root: {error}"))?;
    if reported != bound.folder() {
        return Err(format!(
            "Git Changes require the active workspace root itself; Git reported {}.",
            reported.display()
        ));
    }
    Ok(())
}

fn index_identity(root: &Path, path: &Path) -> Result<String, String> {
    let mut command = git_command(root);
    command
        .arg("ls-files")
        .arg("--stage")
        .arg("-z")
        .arg("--")
        .arg(path);
    let bytes = require_git_success(
        run_git(command, None, MAX_GIT_METADATA_BYTES)?,
        "inspect the Git index blob",
    )?;
    let rows = bytes
        .split(|byte| *byte == 0)
        .filter(|row| !row.is_empty())
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return Ok("absent".into());
    }
    if rows.len() != 1 {
        return Err("Git index has conflict stages for this path; hunk action refused.".into());
    }
    let metadata = rows[0]
        .split(|byte| *byte == b'\t')
        .next()
        .ok_or_else(|| "Git index row is malformed.".to_owned())?;
    let fields = metadata.split(|byte| *byte == b' ').collect::<Vec<_>>();
    if fields.len() != 3 || fields[2] != b"0" {
        return Err("Git index identity is malformed or conflicted.".into());
    }
    let mode = strict_ascii(fields[0], "Git index mode")?;
    let hash = strict_hash(fields[1], "Git index blob")?;
    Ok(format!("{mode}:{hash}"))
}

fn worktree_identity(root: &Path, path: &Path) -> Result<String, String> {
    let absolute = root.join(path);
    match fs::symlink_metadata(&absolute) {
        Ok(metadata) if metadata.is_dir() => return Ok("directory".into()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok("absent".into()),
        Err(error) => return Err(format!("Cannot inspect worktree path identity: {error}")),
    }
    let mut command = git_command(root);
    command
        .arg("hash-object")
        .arg("--no-filters")
        .arg("--")
        .arg(path);
    let bytes = require_git_success(
        run_git(command, None, MAX_GIT_METADATA_BYTES)?,
        "hash the worktree file",
    )?;
    let hash = strict_hash(
        single_git_line(&bytes, "Git worktree blob")?.as_bytes(),
        "Git worktree blob",
    )?;
    Ok(hash)
}

fn hunk_identity(
    project: &PlusKnownProject,
    lane: GitLane,
    relative_path: &Path,
    index_identity: &str,
    worktree_identity: &str,
    patch_bytes: &[u8],
) -> String {
    let mut material = b"grok-build-plus-git-hunk/v1\0".to_vec();
    append_identity(&mut material, project.id.as_bytes());
    append_identity(&mut material, &path_bytes(project.active_root()));
    append_identity(&mut material, lane.as_str().as_bytes());
    append_identity(&mut material, &path_bytes(relative_path));
    append_identity(&mut material, index_identity.as_bytes());
    append_identity(&mut material, worktree_identity.as_bytes());
    append_identity(&mut material, patch_bytes);
    worktree_recovery_digest(&material)
}

fn append_identity(material: &mut Vec<u8>, bytes: &[u8]) {
    material.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    material.extend_from_slice(bytes);
}

fn apply_patch(root: &Path, patch: &[u8], action: HunkAction) -> Result<(), String> {
    apply_patch_direction(
        root,
        patch,
        matches!(action, HunkAction::Stage | HunkAction::Unstage),
        matches!(action, HunkAction::Unstage | HunkAction::Discard),
        "apply the selected hunk",
    )
}

fn rollback_patch(root: &Path, patch: &[u8], action: HunkAction) -> Result<(), String> {
    apply_patch_direction(
        root,
        patch,
        matches!(action, HunkAction::Stage | HunkAction::Unstage),
        matches!(action, HunkAction::Stage),
        "roll back a drifted hunk action",
    )
}

fn apply_patch_direction(
    root: &Path,
    patch: &[u8],
    cached: bool,
    reverse: bool,
    label: &str,
) -> Result<(), String> {
    let mut command = git_command(root);
    command
        .arg("apply")
        .arg("--recount")
        .arg("--whitespace=nowarn");
    if cached {
        command.arg("--cached");
    }
    if reverse {
        command.arg("--reverse");
    }
    command.arg("-");
    require_git_success(
        run_git(command, Some(patch), MAX_GIT_METADATA_BYTES)?,
        label,
    )?;
    Ok(())
}

fn line_starts(bytes: &[u8]) -> Vec<usize> {
    let mut starts = vec![0];
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' && index + 1 < bytes.len() {
            starts.push(index + 1);
        }
    }
    starts
}

fn hunk_line_counts(bytes: &[u8]) -> (usize, usize) {
    let mut added = 0;
    let mut removed = 0;
    for line in bytes.split(|byte| *byte == b'\n').skip(1) {
        match line.first() {
            Some(b'+') => added += 1,
            Some(b'-') => removed += 1,
            _ => {}
        }
    }
    (added, removed)
}

fn validate_relative_path(path: &Path) -> Result<(), String> {
    let bytes = path_bytes(path);
    if bytes.is_empty() || bytes.len() > MAX_RELATIVE_PATH_BYTES {
        return Err("Git path is empty or exceeds the 4,096-byte review limit.".into());
    }
    if !path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err("Git path contains an absolute, parent, or non-normal component.".into());
    }
    Ok(())
}

fn single_git_line<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{label} is not UTF-8."))?;
    let line = text.trim();
    if line.is_empty() || line.contains('\n') || line.contains('\r') {
        Err(format!("{label} is empty or multiline."))
    } else {
        Ok(line)
    }
}

fn strict_ascii(bytes: &[u8], label: &str) -> Result<String, String> {
    if bytes.is_empty() || !bytes.is_ascii() || bytes.iter().any(u8::is_ascii_control) {
        Err(format!("{label} is malformed."))
    } else {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

fn strict_hash(bytes: &[u8], label: &str) -> Result<String, String> {
    if matches!(bytes.len(), 40 | 64) && bytes.iter().all(u8::is_ascii_hexdigit) {
        Ok(String::from_utf8_lossy(bytes).to_ascii_lowercase())
    } else {
        Err(format!("{label} is malformed."))
    }
}

fn append_operation(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    hunk_id: &str,
    action: HunkAction,
    state: &str,
) -> Result<(), String> {
    create_owner_only_dir(store.state_root())?;
    let event = GitReviewOperation {
        schema_version: 1,
        sequence: NEXT_GIT_REVIEW_OPERATION.fetch_add(1, Ordering::Relaxed),
        timestamp_unix_ms: unix_time_millis(),
        project_id: &project.id,
        root: project.active_root().display().to_string(),
        hunk_id,
        operation: action.as_str(),
        state,
    };
    let mut line = serde_json::to_vec(&event)
        .map_err(|error| format!("Cannot encode Git Review operation: {error}"))?;
    line.push(b'\n');
    let path = store.state_root().join(GIT_REVIEW_OPERATIONS_FILE);
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("Cannot open Git Review operation journal: {error}"))?;
    file.write_all(&line)
        .map_err(|error| format!("Cannot append Git Review operation journal: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("Cannot sync Git Review operation journal: {error}"))
}

fn create_owner_only_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("Cannot create app state directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Cannot restrict app state directory: {error}"))?;
    }
    Ok(())
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(1)
}

#[cfg(unix)]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, String> {
    if bytes.is_empty() || bytes.contains(&0) {
        return Err("Git path is empty or contains NUL.".into());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, String> {
    String::from_utf8(bytes.to_vec())
        .map(PathBuf::from)
        .map_err(|_| "Git path is not UTF-8.".into())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn display_git_path(bytes: &[u8]) -> String {
    display_os_bytes(bytes)
}

#[cfg(not(unix))]
fn display_git_path(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(unix)]
fn display_path(path: &Path) -> String {
    display_os_bytes(path.as_os_str().as_bytes())
}

#[cfg(not(unix))]
fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(unix)]
fn display_os_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut shown = String::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(text) => {
                push_display_text(&mut shown, text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid > 0
                    && let Ok(text) = std::str::from_utf8(&remaining[..valid])
                {
                    push_display_text(&mut shown, text);
                }
                let invalid = error.error_len().unwrap_or(remaining.len() - valid);
                for byte in &remaining[valid..valid + invalid] {
                    let _ = write!(shown, "\\x{byte:02x}");
                }
                remaining = &remaining[valid + invalid..];
            }
        }
    }
    shown
}

#[cfg(unix)]
fn push_display_text(shown: &mut String, text: &str) {
    use std::fmt::Write as _;

    for character in text.chars() {
        if character.is_control() || character == '\\' {
            for byte in character.to_string().as_bytes() {
                let _ = write!(shown, "\\x{byte:02x}");
            }
        } else {
            shown.push(character);
        }
    }
}

#[cfg(test)]
#[path = "git_review/tests.rs"]
mod tests;
