//! User-driven managed Git worktrees with explicit dirty-state refusals.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use grok_build_plus_host::{
    PlusKnownProject, PlusManagedWorktree, PlusSessionStore, managed_worktree_identity,
    managed_worktree_record, worktree_recovery_digest,
};
use serde::Serialize;

use crate::git_process::{MAX_GIT_METADATA_BYTES, git_command, require_git_success, run_git};

const MAX_BASE_REF_BYTES: usize = 256;
const MAX_COMMIT_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_RECOVERY_PATCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECOVERY_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECOVERY_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const MAX_RECOVERY_FILES: usize = 10_000;
const WORKTREE_OPERATIONS_FILE: &str = "plus-worktree-operations.jsonl";

static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorktreeDirtyView {
    pub(crate) dirty: bool,
    pub(crate) staged: Vec<String>,
    pub(crate) unstaged: Vec<String>,
    pub(crate) conflicted: Vec<String>,
    pub(crate) untracked: Vec<String>,
    pub(crate) ignored: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorktreeView {
    pub(crate) id: String,
    task: String,
    branch: String,
    path: String,
    base_commit: String,
    active: bool,
    state: &'static str,
    detail: String,
    dirty: WorktreeDirtyView,
    recovery_manifest: Option<String>,
    recovery_current: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorktreeListView {
    project_id: String,
    source_root: String,
    active_root: String,
    active_worktree_id: Option<String>,
    available: bool,
    setup_available: bool,
    status: String,
    worktrees: Vec<WorktreeView>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorktreeRemoveView {
    pub(crate) outcome: &'static str,
    pub(crate) detail: String,
    pub(crate) dirty: WorktreeDirtyView,
    pub(crate) removed_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorktreeUserActionView {
    outcome: &'static str,
    detail: String,
    dirty: WorktreeDirtyView,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorktreeRecoveryExportView {
    outcome: &'static str,
    detail: String,
    path: String,
    manifest_hash: String,
    state_hash: String,
    dirty: WorktreeDirtyView,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitSetupView {
    pub(crate) outcome: &'static str,
    pub(crate) detail: String,
    pub(crate) initialized: bool,
    pub(crate) commit: Option<String>,
}

fn git_setup_outcome(
    outcome: &'static str,
    detail: impl Into<String>,
    initialized: bool,
) -> GitSetupView {
    GitSetupView {
        outcome,
        detail: detail.into(),
        initialized,
        commit: None,
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    reason = "the user-only Git initialization transaction keeps each fail-closed phase and its structured partial/refused outcome in one auditable sequence"
)]
pub(crate) fn initialize_project_git(
    project: &PlusKnownProject,
    author_name: Option<&str>,
    author_email: Option<&str>,
) -> Result<GitSetupView, String> {
    let author = match (author_name, author_email) {
        (Some(name), Some(email)) => {
            let name = match validate_git_identity(name, "name") {
                Ok(name) => name,
                Err(error) => return Ok(git_setup_outcome("refused", error, false)),
            };
            let email = match validate_git_email(email) {
                Ok(email) => email,
                Err(error) => return Ok(git_setup_outcome("refused", error, false)),
            };
            Some((name, email))
        }
        (None, None) => None,
        _ => {
            return Ok(git_setup_outcome(
                "refused",
                "Git setup requires both repository-local Name and Email.",
                false,
            ));
        }
    };
    let canonical = match project.root.canonicalize() {
        Ok(canonical) => canonical,
        Err(error) => {
            return Ok(git_setup_outcome(
                "refused",
                format!("Cannot canonicalize the project before Git setup: {error}"),
                false,
            ));
        }
    };
    if canonical != project.root {
        return Ok(git_setup_outcome(
            "refused",
            "Git setup refused because the bound project identity changed.",
            false,
        ));
    }
    let git_path = project.root.join(".git");
    let existed = match fs::symlink_metadata(&git_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !(metadata.is_dir() || metadata.is_file()) {
                return Ok(git_setup_outcome(
                    "refused",
                    "Git setup refused unsafe .git metadata.",
                    false,
                ));
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Ok(git_setup_outcome(
                "refused",
                format!("Cannot inspect Git metadata: {error}"),
                false,
            ));
        }
    };
    if !existed {
        let mut command = git_command(&project.root);
        command.arg("init").arg("-b").arg("main");
        if let Err(error) = run_git(command, None, MAX_GIT_METADATA_BYTES)
            .and_then(|output| require_git_success(output, "initialize this project"))
        {
            let initialized = git_metadata_is_regular(&git_path);
            return Ok(git_setup_outcome(
                if initialized { "partial" } else { "refused" },
                error,
                initialized,
            ));
        }
    }
    if let Some((name, email)) = author {
        let mut name_command = git_command(&project.root);
        name_command
            .arg("config")
            .arg("--local")
            .arg("user.name")
            .arg(name);
        if let Err(error) = run_git(name_command, None, MAX_GIT_METADATA_BYTES)
            .and_then(|output| require_git_success(output, "save the repository-local author name"))
        {
            return Ok(git_setup_outcome("partial", error, true));
        }
        let mut email_command = git_command(&project.root);
        email_command
            .arg("config")
            .arg("--local")
            .arg("user.email")
            .arg(email);
        if let Err(error) =
            run_git(email_command, None, MAX_GIT_METADATA_BYTES).and_then(|output| {
                require_git_success(output, "save the repository-local author email")
            })
        {
            return Ok(git_setup_outcome("partial", error, true));
        }
    }

    let mut head = git_command(&project.root);
    head.arg("rev-parse").arg("--verify").arg("HEAD");
    let head = match run_git(head, None, MAX_GIT_METADATA_BYTES) {
        Ok(head) => head,
        Err(error) => return Ok(git_setup_outcome("partial", error, true)),
    };
    if head.success() {
        let commit = match strict_git_line(&head.stdout, "Git first commit") {
            Ok(commit) => commit,
            Err(error) => return Ok(git_setup_outcome("partial", error, true)),
        };
        return Ok(GitSetupView {
            outcome: "committed",
            detail: "Git is ready.".into(),
            initialized: true,
            commit: Some(commit.to_owned()),
        });
    }

    let mut unborn = git_command(&project.root);
    unborn
        .arg("status")
        .arg("--porcelain=v1")
        .arg("--untracked-files=no")
        .arg("--");
    if let Err(error) = run_git(unborn, None, MAX_GIT_METADATA_BYTES)
        .and_then(|output| require_git_success(output, "verify the initialized repository"))
    {
        return Ok(git_setup_outcome("partial", error, true));
    }

    let name = match local_git_config(&project.root, "user.name") {
        Ok(name) => name,
        Err(error) => return Ok(git_setup_outcome("partial", error, true)),
    };
    let email = match local_git_config(&project.root, "user.email") {
        Ok(email) => email,
        Err(error) => return Ok(git_setup_outcome("partial", error, true)),
    };
    if name.is_none() || email.is_none() {
        return Ok(git_setup_outcome(
            "needs_identity",
            "Git was initialized. Add a repository-local Name and Email to create the empty first commit.",
            true,
        ));
    }

    let mut staged = git_command(&project.root);
    staged
        .arg("diff")
        .arg("--cached")
        .arg("--name-only")
        .arg("--");
    let staged = match run_git(staged, None, MAX_GIT_METADATA_BYTES)
        .and_then(|output| require_git_success(output, "verify the empty first commit"))
    {
        Ok(staged) => staged,
        Err(error) => return Ok(git_setup_outcome("partial", error, true)),
    };
    if !staged.is_empty() {
        return Ok(git_setup_outcome(
            "partial",
            "Git setup stopped because files are already staged; no first commit was created.",
            true,
        ));
    }

    match fs::symlink_metadata(&git_path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        _ => {
            return Ok(git_setup_outcome(
                "refused",
                "Git setup refused an unsupported or changed .git directory before commit.",
                true,
            ));
        }
    }
    let alternate_index = git_path.join(format!(
        ".grok-build-plus-empty-index-{}-{}",
        std::process::id(),
        unix_time_millis()
    ));
    if fs::symlink_metadata(&alternate_index).is_ok() {
        return Ok(git_setup_outcome(
            "refused",
            "Git setup refused an existing temporary index identity.",
            true,
        ));
    }

    let mut commit = git_command(&project.root);
    commit.env("GIT_INDEX_FILE", &alternate_index);
    commit
        .arg("commit")
        .arg("--allow-empty")
        .arg("--no-gpg-sign")
        .arg("--no-verify")
        .arg("--message=Initial project checkpoint");
    let committed = run_git(commit, None, MAX_GIT_METADATA_BYTES)
        .and_then(|output| require_git_success(output, "create the empty first commit"));
    let cleanup = remove_git_setup_index(&alternate_index, &git_path);
    if let Err(error) = committed {
        let detail = match cleanup {
            Ok(()) => error,
            Err(cleanup_error) => format!("{error} Cleanup also failed: {cleanup_error}"),
        };
        return Ok(git_setup_outcome("partial", detail, true));
    }
    if let Err(error) = cleanup {
        return Ok(git_setup_outcome("partial", error, true));
    }
    let mut verify = git_command(&project.root);
    verify
        .arg("show")
        .arg("--format=%H")
        .arg("--name-only")
        .arg("HEAD");
    let output = match run_git(verify, None, MAX_GIT_METADATA_BYTES)
        .and_then(|output| require_git_success(output, "verify the empty first commit"))
    {
        Ok(output) => output,
        Err(error) => return Ok(git_setup_outcome("partial", error, true)),
    };
    let Ok(text) = String::from_utf8(output) else {
        return Ok(git_setup_outcome(
            "partial",
            "Git returned non-UTF-8 first-commit verification.",
            true,
        ));
    };
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let commit = lines
        .next()
        .filter(|line| {
            matches!(line.len(), 40 | 64) && line.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .map(str::to_owned);
    let Some(commit) = commit else {
        return Ok(git_setup_outcome(
            "partial",
            "Git returned an invalid first-commit identity.",
            true,
        ));
    };
    if lines.next().is_some() {
        return Ok(git_setup_outcome(
            "partial",
            "Git first-commit verification found project files; setup refused success.",
            true,
        ));
    }
    Ok(GitSetupView {
        outcome: "committed",
        detail: "Git is ready. The first commit contains no project files.".into(),
        initialized: true,
        commit: Some(commit.to_ascii_lowercase()),
    })
}

fn git_metadata_is_regular(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        !metadata.file_type().is_symlink() && (metadata.is_dir() || metadata.is_file())
    })
}

fn remove_git_setup_index(path: &Path, git_directory: &Path) -> Result<(), String> {
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    for candidate in [path.to_path_buf(), PathBuf::from(lock_name)] {
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(&candidate).map_err(|error| {
                    format!("Cannot remove a temporary Git setup index file: {error}")
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err("Temporary Git setup index changed identity; cleanup refused.".into());
            }
            Err(error) => {
                return Err(format!(
                    "Cannot inspect a temporary Git setup index file: {error}"
                ));
            }
        }
    }
    sync_directory(git_directory).map_err(|error| format!("Cannot sync Git setup cleanup: {error}"))
}

fn local_git_config(root: &Path, key: &str) -> Result<Option<String>, String> {
    let mut command = git_command(root);
    command.arg("config").arg("--local").arg("--get").arg(key);
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES)?;
    if output.success() {
        return Ok(Some(
            strict_git_line(&output.stdout, "Git identity")?.to_owned(),
        ));
    }
    if output.code() == Some(1) {
        Ok(None)
    } else {
        require_git_success(output, "read repository-local Git identity").map(|_| None)
    }
}

fn validate_git_identity<'a>(value: &'a str, label: &str) -> Result<&'a str, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "Git author {label} must be 1–128 safe UTF-8 bytes."
        ));
    }
    Ok(value)
}

fn validate_git_email(value: &str) -> Result<&str, String> {
    let value = validate_git_identity(value, "email")?;
    if !value.contains('@')
        || value.contains(char::is_whitespace)
        || value.starts_with('@')
        || value.ends_with('@')
    {
        return Err("Git author email must contain one usable @ address.".into());
    }
    Ok(value)
}

#[derive(Serialize)]
struct RecoveryManifest {
    schema_version: u16,
    project_id: String,
    worktree_id: String,
    task: String,
    branch: String,
    source_root: String,
    worktree_root: String,
    exported_at_unix_ms: u64,
    dirty_state_sha256: String,
    staged_patch: RecoveryArtifact,
    unstaged_patch: RecoveryArtifact,
    untracked_files: Vec<RecoveryArtifact>,
    ignored_files: Vec<RecoveryArtifact>,
}

#[derive(Serialize)]
struct RecoveryArtifact {
    path: String,
    byte_count: usize,
    sha256: String,
}

#[derive(Clone, Debug)]
struct GitWorktreeRow {
    path: PathBuf,
    head: Option<String>,
    branch: Option<String>,
    prunable: bool,
}

struct DirtyStatus {
    view: WorktreeDirtyView,
    raw: Vec<u8>,
    ignored_raw: Vec<u8>,
}

#[derive(Serialize)]
struct WorktreeOperationEvent<'a> {
    schema_version: u16,
    sequence: u64,
    timestamp_unix_ms: u64,
    project_id: &'a str,
    worktree_id: Option<&'a str>,
    operation: &'a str,
    state: &'a str,
}

pub(crate) fn list_managed_worktrees(project: &PlusKnownProject) -> WorktreeListView {
    let setup_available = git_setup_available(&project.root);
    let rows = match git_worktree_rows(&project.root) {
        Ok(rows) => rows,
        Err(error) => {
            return WorktreeListView {
                project_id: project.id.to_string(),
                source_root: project.root.display().to_string(),
                active_root: project.active_root().display().to_string(),
                active_worktree_id: project.active_worktree_id.as_ref().map(ToString::to_string),
                available: false,
                setup_available,
                status: error,
                worktrees: project
                    .worktrees
                    .iter()
                    .map(|worktree| unavailable_worktree_view(project, worktree))
                    .collect(),
            };
        }
    };
    let by_path: HashMap<&Path, &GitWorktreeRow> =
        rows.iter().map(|row| (row.path.as_path(), row)).collect();
    let mut views = Vec::with_capacity(project.worktrees.len());
    for worktree in &project.worktrees {
        let row = by_path.get(worktree.path.as_path()).copied();
        views.push(worktree_view(project, worktree, row));
    }
    WorktreeListView {
        project_id: project.id.to_string(),
        source_root: project.root.display().to_string(),
        active_root: project.active_root().display().to_string(),
        active_worktree_id: project.active_worktree_id.as_ref().map(ToString::to_string),
        available: true,
        setup_available,
        status: if views.is_empty() {
            "No managed worktrees yet.".into()
        } else {
            format!("{} managed worktree(s)", views.len())
        },
        worktrees: views,
    }
}

fn git_setup_available(root: &Path) -> bool {
    let git_path = root.join(".git");
    match fs::symlink_metadata(&git_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Ok(metadata)
            if !metadata.file_type().is_symlink() && (metadata.is_dir() || metadata.is_file()) => {}
        _ => return false,
    }
    let mut head = git_command(root);
    head.arg("rev-parse").arg("--verify").arg("HEAD");
    let Ok(head) = run_git(head, None, MAX_GIT_METADATA_BYTES) else {
        return false;
    };
    if head.success() {
        return false;
    }
    let mut status = git_command(root);
    status
        .arg("status")
        .arg("--porcelain=v1")
        .arg("--untracked-files=no")
        .arg("--");
    run_git(status, None, MAX_GIT_METADATA_BYTES).is_ok_and(|output| output.success())
}

pub(crate) fn create_managed_worktree(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    task: &str,
    base_ref: &str,
) -> Result<PlusManagedWorktree, String> {
    verify_source_repository(&project.root)?;
    let base_ref = validate_base_ref(base_ref)?;
    let (id, branch) =
        managed_worktree_identity(&project.id, task).map_err(|error| error.to_string())?;
    if project.worktrees.iter().any(|worktree| worktree.id == id) {
        return Err("A managed worktree already exists for this task.".into());
    }
    let path = store
        .managed_worktree_path(&project.id, &id)
        .map_err(|error| error.to_string())?;
    if path.exists() {
        return Err(format!(
            "The app-owned worktree path already exists: {}",
            path.display()
        ));
    }
    let commit = resolve_base_commit(&project.root, base_ref)?;
    append_operation(store, &project.id, Some(&id), "create", "intent")?;
    let result: Result<PlusManagedWorktree, String> = (|| {
        let parent = path
            .parent()
            .ok_or_else(|| "Managed worktree path has no parent.".to_owned())?;
        create_owner_only_dir(parent)?;
        let mut command = git_command(&project.root);
        command
            .arg("worktree")
            .arg("add")
            .arg("-b")
            .arg(&branch)
            .arg(&path)
            .arg(&commit);
        let output = run_git(command, None, MAX_GIT_METADATA_BYTES)?;
        require_git_success(output, "create managed worktree")?;
        let canonical = path
            .canonicalize()
            .map_err(|error| format!("Git created an unreadable worktree: {error}"))?;
        if canonical != path {
            return Err(format!(
                "Git worktree path did not remain canonical: {}",
                canonical.display()
            ));
        }
        managed_worktree_record(&project.id, task, canonical, &commit)
            .map_err(|error| error.to_string())
    })();
    append_operation(
        store,
        &project.id,
        Some(&id),
        "create",
        if result.is_ok() {
            "effect-complete"
        } else {
            "failed"
        },
    )?;
    result
}

pub(crate) fn remove_managed_worktree(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    worktree_id: &str,
) -> Result<WorktreeRemoveView, String> {
    let worktree = known_worktree(project, worktree_id)?;
    let status = read_dirty_status(&worktree.path)?;
    if status.view.dirty {
        return Ok(WorktreeRemoveView {
            outcome: "refused",
            detail: "Dirty worktree refused. Commit, explicitly discard, or export a recovery bundle before removal.".into(),
            dirty: status.view,
            removed_id: None,
        });
    }
    append_operation(store, &project.id, Some(worktree_id), "remove", "intent")?;
    let mut command = git_command(&project.root);
    command.arg("worktree").arg("remove").arg(&worktree.path);
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES)?;
    let result = require_git_success(output, "remove clean managed worktree");
    append_operation(
        store,
        &project.id,
        Some(worktree_id),
        "remove",
        if result.is_ok() {
            "effect-complete"
        } else {
            "failed"
        },
    )?;
    result?;
    Ok(WorktreeRemoveView {
        outcome: "removed",
        detail: "Clean managed worktree removed by Git.".into(),
        dirty: WorktreeDirtyView::default(),
        removed_id: Some(worktree_id.to_owned()),
    })
}

pub(crate) fn commit_managed_worktree(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    worktree_id: &str,
    message: &str,
) -> Result<WorktreeUserActionView, String> {
    let worktree = known_worktree(project, worktree_id)?;
    let message = validate_commit_message(message)?;
    let before = read_dirty_status(&worktree.path)?;
    if before.view.staged.is_empty() {
        return Err("No staged Git changes are available to commit.".into());
    }
    append_operation(store, &project.id, Some(worktree_id), "commit", "intent")?;
    let mut command = git_command(&worktree.path);
    command
        .arg("commit")
        .arg("--no-verify")
        .arg("--no-gpg-sign")
        .arg("--file=-");
    let output = run_git(command, Some(message.as_bytes()), MAX_GIT_METADATA_BYTES)?;
    let result = require_git_success(output, "commit staged worktree changes");
    append_operation(
        store,
        &project.id,
        Some(worktree_id),
        "commit",
        if result.is_ok() {
            "effect-complete"
        } else {
            "failed"
        },
    )?;
    result?;
    let after = read_dirty_status(&worktree.path)?;
    Ok(WorktreeUserActionView {
        outcome: "committed",
        detail: if after.view.dirty {
            "Staged changes committed. Other exact paths remain dirty.".into()
        } else {
            "Staged changes committed; the worktree is clean.".into()
        },
        dirty: after.view,
    })
}

pub(crate) fn discard_managed_worktree(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    worktree_id: &str,
    confirmation: &str,
) -> Result<WorktreeUserActionView, String> {
    let worktree = known_worktree(project, worktree_id)?;
    let required = format!("DISCARD {}", worktree.task);
    if confirmation != required {
        return Err(format!(
            "Explicit discard requires the exact confirmation `{required}`."
        ));
    }
    let before = read_dirty_status(&worktree.path)?;
    if !before.view.dirty {
        return Ok(WorktreeUserActionView {
            outcome: "clean",
            detail: "The managed worktree is already clean; nothing was discarded.".into(),
            dirty: before.view,
        });
    }
    append_operation(store, &project.id, Some(worktree_id), "discard", "intent")?;
    let result: Result<WorktreeDirtyView, String> = (|| {
        let mut restore = git_command(&worktree.path);
        restore
            .arg("reset")
            .arg("--hard")
            .arg("--quiet")
            .arg("HEAD");
        require_git_success(
            run_git(restore, None, MAX_GIT_METADATA_BYTES)?,
            "discard tracked worktree changes",
        )?;
        let mut clean = git_command(&worktree.path);
        clean.arg("clean").arg("-fdx").arg("--").arg(".");
        require_git_success(
            run_git(clean, None, MAX_GIT_METADATA_BYTES)?,
            "discard untracked worktree files",
        )?;
        let after = read_dirty_status(&worktree.path)?;
        if after.view.dirty {
            return Err(
                "Explicit discard completed incompletely; exact dirty paths remain.".into(),
            );
        }
        Ok(after.view)
    })();
    append_operation(
        store,
        &project.id,
        Some(worktree_id),
        "discard",
        if result.is_ok() {
            "effect-complete"
        } else {
            "failed"
        },
    )?;
    Ok(WorktreeUserActionView {
        outcome: "discarded",
        detail: "Explicitly confirmed tracked and untracked changes were discarded. Removal remains a separate action.".into(),
        dirty: result?,
    })
}

pub(crate) fn export_worktree_recovery(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    worktree_id: &str,
    destination: &Path,
) -> Result<WorktreeRecoveryExportView, String> {
    let worktree = known_worktree(project, worktree_id)?;
    let before = read_dirty_status(&worktree.path)?;
    if !before.view.dirty {
        return Err("The managed worktree is clean; no recovery bundle is needed.".into());
    }
    let destination = canonical_existing_directory(destination, "recovery destination")?;
    append_operation(store, &project.id, Some(worktree_id), "export", "intent")?;
    let result = build_recovery_bundle(project, worktree, &destination, &before);
    let (path, manifest_hash, state_hash) = match result {
        Ok(result) => result,
        Err(error) => {
            append_operation(store, &project.id, Some(worktree_id), "export", "failed")?;
            return Err(error);
        }
    };
    store
        .remember_worktree_recovery(&project.id, worktree_id, &manifest_hash, &state_hash)
        .map_err(|error| {
            format!(
                "Recovery bundle exists at {} but its verified receipt could not be persisted: {error}",
                path.display()
            )
        })?;
    append_operation(
        store,
        &project.id,
        Some(worktree_id),
        "export",
        "effect-complete",
    )?;
    Ok(WorktreeRecoveryExportView {
        outcome: "exported",
        detail: "Recovery bundle verified and recorded. Dirty removal remains a separate explicit action.".into(),
        path: path.display().to_string(),
        manifest_hash,
        state_hash,
        dirty: before.view,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "dirty removal keeps export identity revalidation, atomic quarantine, Git reconciliation, and receipt persistence in one fail-closed transaction"
)]
pub(crate) fn remove_worktree_after_export(
    store: &PlusSessionStore,
    project: &PlusKnownProject,
    worktree_id: &str,
    manifest_hash: &str,
    confirmation: &str,
) -> Result<WorktreeRemoveView, String> {
    let worktree = known_worktree(project, worktree_id)?;
    let required = format!("REMOVE {}", worktree.task);
    if confirmation != required {
        return Err(format!(
            "Post-export removal requires the exact confirmation `{required}`."
        ));
    }
    let status = read_dirty_status(&worktree.path)?;
    if !status.view.dirty {
        return Err(
            "The worktree is now clean. Use the ordinary clean Remove action instead.".into(),
        );
    }
    let current_state = recovery_state_hash(worktree, &status)?;
    if worktree.recovery_manifest.as_deref() != Some(manifest_hash)
        || worktree.recovery_state.as_deref() != Some(current_state.as_str())
    {
        return Ok(WorktreeRemoveView {
            outcome: "refused",
            detail: "Dirty state changed after the recovery export. Export a new recovery bundle before removal.".into(),
            dirty: status.view,
            removed_id: None,
        });
    }
    append_operation(
        store,
        &project.id,
        Some(worktree_id),
        "remove-after-export",
        "intent",
    )?;
    let pre_remove_status = read_dirty_status(&worktree.path)?;
    if recovery_state_hash(worktree, &pre_remove_status)? != current_state {
        append_operation(
            store,
            &project.id,
            Some(worktree_id),
            "remove-after-export",
            "refused-state-changed",
        )?;
        return Ok(WorktreeRemoveView {
            outcome: "refused",
            detail: "Dirty state changed after confirmation. Export again before removal.".into(),
            dirty: pre_remove_status.view,
            removed_id: None,
        });
    }
    let quarantine_parent = store.state_root().join("worktree-recovery-quarantine");
    create_owner_only_dir(&quarantine_parent)?;
    let quarantine = quarantine_parent.join(format!(
        "{}-{}-{}",
        &worktree.id[..12],
        unix_time_millis(),
        NEXT_OPERATION.fetch_add(1, Ordering::Relaxed)
    ));
    if quarantine.exists() {
        return Err("Recovery quarantine path unexpectedly already exists.".into());
    }
    fs::rename(&worktree.path, &quarantine)
        .map_err(|error| format!("Cannot atomically quarantine dirty worktree: {error}"))?;
    sync_directory(&quarantine_parent)?;

    let result: Result<(), String> = (|| {
        let mut command = git_command(&project.root);
        command.arg("worktree").arg("prune").arg("--expire=now");
        require_git_success(
            run_git(command, None, MAX_GIT_METADATA_BYTES)?,
            "prune the atomically quarantined worktree registration",
        )?;
        if git_worktree_rows(&project.root)?
            .iter()
            .any(|row| row.path == worktree.path)
        {
            return Err(
                "Git still reports the quarantined worktree; removal success was not recorded."
                    .into(),
            );
        }
        let receipt = serde_json::to_vec_pretty(&serde_json::json!({
            "schemaVersion": 1,
            "projectId": project.id,
            "worktreeId": worktree.id,
            "originalPath": worktree.path,
            "manifestSha256": manifest_hash,
            "dirtyStateSha256": current_state,
            "quarantinedAtUnixMs": unix_time_millis(),
            "disposition": "retained-recoverable-copy"
        }))
        .map_err(|error| format!("Cannot encode quarantine receipt: {error}"))?;
        write_new_owner_file(
            &quarantine.join("grok-build-quarantine-receipt.json"),
            &receipt,
        )?;
        sync_directory(&quarantine)?;
        Ok(())
    })();
    if let Err(error) = &result {
        if !worktree.path.exists() {
            let _ = fs::rename(&quarantine, &worktree.path);
        }
        append_operation(
            store,
            &project.id,
            Some(worktree_id),
            "remove-after-export",
            "failed-quarantine-registration",
        )?;
        return Err(error.clone());
    }
    append_operation(
        store,
        &project.id,
        Some(worktree_id),
        "remove-after-export",
        "effect-complete-recoverable-quarantine",
    )?;
    Ok(WorktreeRemoveView {
        outcome: "removed-after-export",
        detail: format!(
            "Dirty managed worktree removed from Git only after exact export validation. A recoverable quarantine copy was retained at {}.",
            quarantine.display()
        ),
        dirty: status.view,
        removed_id: Some(worktree_id.to_owned()),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the recovery export must atomically bind patches, untracked and ignored files, hashes, manifest, and final promotion"
)]
fn build_recovery_bundle(
    project: &PlusKnownProject,
    worktree: &PlusManagedWorktree,
    destination: &Path,
    before: &DirtyStatus,
) -> Result<(PathBuf, String, String), String> {
    let stamp = unix_time_millis();
    let nonce = NEXT_OPERATION.fetch_add(1, Ordering::Relaxed);
    let name = format!("GrokBuild-Recovery-{}-{stamp}-{nonce}", &worktree.id[..12]);
    let final_path = destination.join(&name);
    let partial_path =
        destination.join(format!(".{name}.partial-{}-{}", std::process::id(), nonce));
    if final_path.exists() || partial_path.exists() {
        return Err("Recovery bundle destination already exists; choose another folder.".into());
    }
    create_owner_only_dir(&partial_path)?;
    let result = (|| {
        let staged = git_patch(&worktree.path, true)?;
        let unstaged = git_patch(&worktree.path, false)?;
        let staged_artifact = write_recovery_bytes(&partial_path, "staged.patch", &staged)?;
        let unstaged_artifact = write_recovery_bytes(&partial_path, "unstaged.patch", &unstaged)?;
        let untracked_paths = untracked_paths_from_status(&before.raw)?;
        let ignored_paths = nul_paths(&before.ignored_raw, "ignored worktree path")?;
        let recovery_file_count = untracked_paths.len().saturating_add(ignored_paths.len());
        if recovery_file_count > MAX_RECOVERY_FILES {
            return Err(format!(
                "Recovery export has {recovery_file_count} untracked/ignored files; limit is {MAX_RECOVERY_FILES}."
            ));
        }
        let untracked_root = partial_path.join("untracked");
        let ignored_root = partial_path.join("ignored");
        create_owner_only_dir(&untracked_root)?;
        create_owner_only_dir(&ignored_root)?;
        let mut untracked_files = Vec::with_capacity(untracked_paths.len());
        let mut untracked_state = Vec::with_capacity(untracked_paths.len());
        let mut ignored_files = Vec::with_capacity(ignored_paths.len());
        let mut ignored_state = Vec::with_capacity(ignored_paths.len());
        let mut total = staged.len().saturating_add(unstaged.len());
        for relative in untracked_paths {
            let (bytes, shown) = read_recovery_file(&worktree.path, &relative, "untracked")?;
            total = total.saturating_add(bytes.len());
            if total > MAX_RECOVERY_TOTAL_BYTES {
                return Err(format!(
                    "Recovery export exceeded the {MAX_RECOVERY_TOTAL_BYTES} byte total limit."
                ));
            }
            let target = safe_recovery_target(&untracked_root, &relative)?;
            if let Some(parent) = target.parent() {
                create_owner_only_dir(parent)?;
            }
            write_new_owner_file(&target, &bytes)?;
            let digest = worktree_recovery_digest(&bytes);
            untracked_state.push((relative, digest.clone()));
            untracked_files.push(RecoveryArtifact {
                path: format!("untracked/{shown}"),
                byte_count: bytes.len(),
                sha256: digest,
            });
        }
        for relative in ignored_paths {
            let (bytes, shown) = read_recovery_file(&worktree.path, &relative, "ignored")?;
            total = total.saturating_add(bytes.len());
            if total > MAX_RECOVERY_TOTAL_BYTES {
                return Err(format!(
                    "Recovery export exceeded the {MAX_RECOVERY_TOTAL_BYTES} byte total limit."
                ));
            }
            let target = safe_recovery_target(&ignored_root, &relative)?;
            if let Some(parent) = target.parent() {
                create_owner_only_dir(parent)?;
            }
            write_new_owner_file(&target, &bytes)?;
            let digest = worktree_recovery_digest(&bytes);
            ignored_state.push((relative, digest.clone()));
            ignored_files.push(RecoveryArtifact {
                path: format!("ignored/{shown}"),
                byte_count: bytes.len(),
                sha256: digest,
            });
        }
        let state_hash = recovery_state_hash_from_parts(
            &before.raw,
            &before.ignored_raw,
            &staged,
            &unstaged,
            &untracked_state,
            &ignored_state,
        );
        let after = read_dirty_status(&worktree.path)?;
        if recovery_state_hash(worktree, &after)? != state_hash {
            return Err(
                "Worktree changed during recovery export. Nothing was promoted; retry.".into(),
            );
        }
        let manifest = RecoveryManifest {
            schema_version: 2,
            project_id: project.id.to_string(),
            worktree_id: worktree.id.to_string(),
            task: worktree.task.clone(),
            branch: worktree.branch.clone(),
            source_root: project.root.display().to_string(),
            worktree_root: worktree.path.display().to_string(),
            exported_at_unix_ms: stamp,
            dirty_state_sha256: state_hash.clone(),
            staged_patch: staged_artifact,
            unstaged_patch: unstaged_artifact,
            untracked_files,
            ignored_files,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| format!("Cannot encode recovery manifest: {error}"))?;
        let manifest_hash = worktree_recovery_digest(&manifest_bytes);
        write_new_owner_file(&partial_path.join("manifest.json"), &manifest_bytes)?;
        sync_directory(&partial_path)?;
        fs::rename(&partial_path, &final_path)
            .map_err(|error| format!("Cannot atomically promote recovery bundle: {error}"))?;
        sync_directory(destination)?;
        Ok((final_path.clone(), manifest_hash, state_hash))
    })();
    if result.is_err() && partial_path.starts_with(destination) {
        let _ = fs::remove_dir_all(&partial_path);
    }
    result
}

fn recovery_state_hash(
    worktree: &PlusManagedWorktree,
    status: &DirtyStatus,
) -> Result<String, String> {
    let staged = git_patch(&worktree.path, true)?;
    let unstaged = git_patch(&worktree.path, false)?;
    let paths = untracked_paths_from_status(&status.raw)?;
    let ignored_paths = nul_paths(&status.ignored_raw, "ignored worktree path")?;
    let recovery_file_count = paths.len().saturating_add(ignored_paths.len());
    if recovery_file_count > MAX_RECOVERY_FILES {
        return Err(format!(
            "Recovery state has {recovery_file_count} untracked/ignored files; limit is {MAX_RECOVERY_FILES}."
        ));
    }
    let mut untracked = Vec::with_capacity(paths.len());
    let mut ignored = Vec::with_capacity(ignored_paths.len());
    let mut total = staged.len().saturating_add(unstaged.len());
    for path in paths {
        let (bytes, _) = read_recovery_file(&worktree.path, &path, "untracked")?;
        total = total.saturating_add(bytes.len());
        if total > MAX_RECOVERY_TOTAL_BYTES {
            return Err(format!(
                "Recovery state exceeded the {MAX_RECOVERY_TOTAL_BYTES} byte total limit."
            ));
        }
        untracked.push((path, worktree_recovery_digest(&bytes)));
    }
    for path in ignored_paths {
        let (bytes, _) = read_recovery_file(&worktree.path, &path, "ignored")?;
        total = total.saturating_add(bytes.len());
        if total > MAX_RECOVERY_TOTAL_BYTES {
            return Err(format!(
                "Recovery state exceeded the {MAX_RECOVERY_TOTAL_BYTES} byte total limit."
            ));
        }
        ignored.push((path, worktree_recovery_digest(&bytes)));
    }
    Ok(recovery_state_hash_from_parts(
        &status.raw,
        &status.ignored_raw,
        &staged,
        &unstaged,
        &untracked,
        &ignored,
    ))
}

fn recovery_state_hash_from_parts(
    status: &[u8],
    ignored_status: &[u8],
    staged: &[u8],
    unstaged: &[u8],
    untracked: &[(PathBuf, String)],
    ignored: &[(PathBuf, String)],
) -> String {
    let mut material = b"grok-build-plus-worktree-recovery-state/v2\0".to_vec();
    append_recovery_field(&mut material, status);
    append_recovery_field(&mut material, ignored_status);
    append_recovery_field(&mut material, worktree_recovery_digest(staged).as_bytes());
    append_recovery_field(&mut material, worktree_recovery_digest(unstaged).as_bytes());
    for (path, digest) in untracked {
        append_recovery_field(&mut material, b"untracked");
        append_recovery_field(&mut material, &recovery_path_bytes(path));
        append_recovery_field(&mut material, digest.as_bytes());
    }
    for (path, digest) in ignored {
        append_recovery_field(&mut material, b"ignored");
        append_recovery_field(&mut material, &recovery_path_bytes(path));
        append_recovery_field(&mut material, digest.as_bytes());
    }
    worktree_recovery_digest(&material)
}

fn append_recovery_field(material: &mut Vec<u8>, bytes: &[u8]) {
    material.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    material.extend_from_slice(bytes);
}

#[cfg(unix)]
fn recovery_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn recovery_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

fn git_patch(worktree: &Path, staged: bool) -> Result<Vec<u8>, String> {
    let mut command = git_command(worktree);
    command.arg("diff");
    if staged {
        command.arg("--cached");
    }
    command
        .arg("--binary")
        .arg("--no-ext-diff")
        .arg("--no-color")
        .arg("--");
    let output = run_git(command, None, MAX_RECOVERY_PATCH_BYTES)?;
    require_git_success(
        output,
        if staged {
            "export the staged binary patch"
        } else {
            "export the unstaged binary patch"
        },
    )
}

fn write_recovery_bytes(root: &Path, name: &str, bytes: &[u8]) -> Result<RecoveryArtifact, String> {
    write_new_owner_file(&root.join(name), bytes)?;
    Ok(RecoveryArtifact {
        path: name.to_owned(),
        byte_count: bytes.len(),
        sha256: worktree_recovery_digest(bytes),
    })
}

fn untracked_paths_from_status(bytes: &[u8]) -> Result<Vec<PathBuf>, String> {
    let fields: Vec<&[u8]> = bytes.split(|byte| *byte == 0).collect();
    let mut paths = Vec::new();
    let mut index = 0;
    while index < fields.len() {
        let field = fields[index];
        index += 1;
        if field.is_empty() {
            continue;
        }
        if field.len() < 4 || field[2] != b' ' {
            return Err("Git returned malformed porcelain status during export.".into());
        }
        let x = field[0];
        let y = field[1];
        if x == b'?' && y == b'?' {
            paths.push(path_from_git_bytes(&field[3..])?);
        }
        if matches!(x, b'R' | b'C') {
            index = index
                .checked_add(1)
                .ok_or_else(|| "Git rename index overflowed.".to_owned())?;
            if index > fields.len() {
                return Err("Git rename status omitted its source path.".into());
            }
        }
    }
    Ok(paths)
}

fn read_recovery_file(
    root: &Path,
    relative: &Path,
    kind: &str,
) -> Result<(Vec<u8>, String), String> {
    let absolute = safe_recovery_target(root, relative)?;
    let mut walked = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(format!(
                "{kind} recovery path contains a non-normal component."
            ));
        };
        walked.push(component);
        let metadata = fs::symlink_metadata(&walked).map_err(|error| {
            format!(
                "Cannot inspect {kind} recovery path `{}`: {error}",
                display_path(relative)
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "Recovery export refuses {kind} symlink `{}`.",
                display_path(relative)
            ));
        }
    }
    let before = fs::metadata(&absolute).map_err(|error| {
        format!(
            "Cannot inspect {kind} recovery file `{}`: {error}",
            display_path(relative)
        )
    })?;
    if !before.is_file() {
        return Err(format!(
            "Recovery export supports regular {kind} files only: `{}`.",
            display_path(relative)
        ));
    }
    if before.len() > MAX_RECOVERY_FILE_BYTES as u64 {
        return Err(format!(
            "{kind} file `{}` is {} bytes; per-file limit is {MAX_RECOVERY_FILE_BYTES}.",
            display_path(relative),
            before.len()
        ));
    }
    let canonical = absolute.canonicalize().map_err(|error| {
        format!(
            "Cannot resolve {kind} recovery file `{}`: {error}",
            display_path(relative)
        )
    })?;
    if !canonical.starts_with(root) {
        return Err(format!(
            "{kind} recovery path escaped the worktree: `{}`.",
            display_path(relative)
        ));
    }
    let mut file = fs::File::open(&canonical).map_err(|error| {
        format!(
            "Cannot open {kind} recovery file `{}`: {error}",
            display_path(relative)
        )
    })?;
    let opened = file.metadata().map_err(|error| {
        format!(
            "Cannot inspect opened recovery file `{}`: {error}",
            display_path(relative)
        )
    })?;
    if !same_file_identity(&before, &opened) {
        return Err(format!(
            "{kind} file changed while opening: `{}`.",
            display_path(relative)
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    (&mut file)
        .take((MAX_RECOVERY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!(
                "Cannot read {kind} recovery file `{}`: {error}",
                display_path(relative)
            )
        })?;
    let after = file.metadata().map_err(|error| {
        format!(
            "Cannot recheck recovery file `{}`: {error}",
            display_path(relative)
        )
    })?;
    if bytes.len() > MAX_RECOVERY_FILE_BYTES || !same_file_snapshot(&opened, &after) {
        return Err(format!(
            "{kind} file changed while reading: `{}`.",
            display_path(relative)
        ));
    }
    Ok((bytes, display_path(relative)))
}

fn safe_recovery_target(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err("Recovery path must be a non-empty relative path.".into());
    }
    let mut target = root.to_path_buf();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(component) => target.push(component),
            _ => return Err("Recovery path contains `.`, `..`, root, or prefix.".into()),
        }
    }
    Ok(target)
}

fn write_new_owner_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("Cannot create recovery file `{}`: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("Cannot write recovery file `{}`: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("Cannot sync recovery file `{}`: {error}", path.display()))
}

fn canonical_existing_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("{label} must be an absolute folder."));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("Cannot inspect {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must be a real directory, not a symlink."));
    }
    path.canonicalize()
        .map_err(|error| format!("Cannot resolve {label}: {error}"))
}

fn sync_directory(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "Cannot sync recovery directory `{}`: {error}",
                path.display()
            )
        })
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.is_file() == right.is_file()
}

fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_file_identity(left, right)
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

fn worktree_view(
    project: &PlusKnownProject,
    worktree: &PlusManagedWorktree,
    row: Option<&GitWorktreeRow>,
) -> WorktreeView {
    let Some(row) = row else {
        return unavailable_worktree_view(project, worktree);
    };
    if row.prunable {
        return worktree_state_view(
            project,
            worktree,
            "prunable",
            "Git reports this worktree as prunable.",
        );
    }
    let expected_branch = format!("refs/heads/{}", worktree.branch);
    if row.branch.as_deref() != Some(expected_branch.as_str()) {
        return worktree_state_view(
            project,
            worktree,
            "error",
            "Git branch identity differs from the managed record.",
        );
    }
    match read_dirty_status(&worktree.path) {
        Ok(dirty) => {
            let recovery_current = worktree.recovery_state.as_ref().is_some_and(|expected| {
                recovery_state_hash(worktree, &dirty).is_ok_and(|actual| actual == *expected)
            });
            WorktreeView {
                id: worktree.id.to_string(),
                task: worktree.task.clone(),
                branch: worktree.branch.clone(),
                path: worktree.path.display().to_string(),
                base_commit: row
                    .head
                    .clone()
                    .unwrap_or_else(|| worktree.base_commit.clone()),
                active: project.active_worktree_id.as_deref() == Some(worktree.id.as_str()),
                state: "ready",
                detail: if dirty.view.dirty {
                    "Dirty · removal will refuse.".into()
                } else {
                    "Clean · managed by Git.".into()
                },
                recovery_current,
                recovery_manifest: worktree.recovery_manifest.clone(),
                dirty: dirty.view,
            }
        }
        Err(error) => worktree_state_view(project, worktree, "error", &error),
    }
}

fn unavailable_worktree_view(
    project: &PlusKnownProject,
    worktree: &PlusManagedWorktree,
) -> WorktreeView {
    worktree_state_view(
        project,
        worktree,
        "missing",
        "The managed path is absent from Git worktree porcelain output.",
    )
}

fn worktree_state_view(
    project: &PlusKnownProject,
    worktree: &PlusManagedWorktree,
    state: &'static str,
    detail: &str,
) -> WorktreeView {
    WorktreeView {
        id: worktree.id.to_string(),
        task: worktree.task.clone(),
        branch: worktree.branch.clone(),
        path: worktree.path.display().to_string(),
        base_commit: worktree.base_commit.clone(),
        active: project.active_worktree_id.as_deref() == Some(worktree.id.as_str()),
        state,
        detail: detail.to_owned(),
        dirty: WorktreeDirtyView::default(),
        recovery_manifest: worktree.recovery_manifest.clone(),
        recovery_current: false,
    }
}

fn known_worktree<'a>(
    project: &'a PlusKnownProject,
    worktree_id: &str,
) -> Result<&'a PlusManagedWorktree, String> {
    project
        .worktrees
        .iter()
        .find(|worktree| worktree.id == worktree_id)
        .ok_or_else(|| "Managed worktree is not associated with the active project.".into())
}

fn verify_source_repository(source_root: &Path) -> Result<(), String> {
    verify_source_repository_shallow(source_root)?;
    let mut command = git_command(source_root);
    command.arg("rev-parse").arg("--show-toplevel");
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES)?;
    let bytes = require_git_success(output, "inspect base Git repository")?;
    let shown = strict_git_line(&bytes, "Git source root")?;
    let canonical = PathBuf::from(shown)
        .canonicalize()
        .map_err(|error| format!("Cannot canonicalize Git source root: {error}"))?;
    if canonical != source_root {
        return Err(format!(
            "Worktrees require the bound source root itself, not a subdirectory: {}",
            canonical.display()
        ));
    }
    Ok(())
}

fn resolve_base_commit(source_root: &Path, base_ref: &str) -> Result<String, String> {
    let expression = format!("{base_ref}^{{commit}}");
    let mut command = git_command(source_root);
    command
        .arg("rev-parse")
        .arg("--verify")
        .arg("--end-of-options")
        .arg(expression);
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES)?;
    let bytes = require_git_success(output, "resolve selected worktree base ref")?;
    let commit = strict_git_line(&bytes, "Git base commit")?;
    if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Git returned a malformed full base commit id.".into());
    }
    Ok(commit.to_ascii_lowercase())
}

fn validate_base_ref(base_ref: &str) -> Result<&str, String> {
    let base_ref = base_ref.trim();
    if base_ref.is_empty()
        || base_ref.len() > MAX_BASE_REF_BYTES
        || base_ref.contains('\0')
        || base_ref.chars().any(char::is_control)
    {
        Err("Base ref must be 1–256 non-control UTF-8 bytes.".into())
    } else {
        Ok(base_ref)
    }
}

fn validate_commit_message(message: &str) -> Result<&str, String> {
    let message = message.trim();
    if message.is_empty()
        || message.len() > MAX_COMMIT_MESSAGE_BYTES
        || message.contains('\0')
        || message
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        Err(
            "Commit message must be 1–4,096 UTF-8 bytes without NUL or unsupported controls."
                .into(),
        )
    } else {
        Ok(message)
    }
}

fn git_worktree_rows(source_root: &Path) -> Result<Vec<GitWorktreeRow>, String> {
    verify_source_repository_shallow(source_root)?;
    let mut command = git_command(source_root);
    command
        .arg("worktree")
        .arg("list")
        .arg("--porcelain")
        .arg("-z");
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES)?;
    let stdout = require_git_success(output, "list Git worktrees")?;
    parse_git_worktree_rows(&stdout)
}

fn verify_source_repository_shallow(source_root: &Path) -> Result<(), String> {
    if !source_root.is_absolute() {
        return Err("Git source root is not absolute.".into());
    }
    let git_metadata = source_root.join(".git");
    let metadata = fs::symlink_metadata(&git_metadata).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "Worktree isolation is unavailable because the bound source root is not a Git working tree."
                .to_owned()
        } else {
            format!("Cannot inspect bound source Git metadata: {error}")
        }
    })?;
    let file_type = metadata.file_type();
    if !(file_type.is_dir() || file_type.is_file()) {
        return Err(
            "Worktree isolation is unavailable because .git is not a regular file or directory."
                .into(),
        );
    }
    Ok(())
}

fn parse_git_worktree_rows(bytes: &[u8]) -> Result<Vec<GitWorktreeRow>, String> {
    let mut rows = Vec::new();
    let mut current: Option<GitWorktreeRow> = None;
    for field in bytes.split(|byte| *byte == 0) {
        if field.is_empty() {
            if let Some(row) = current.take() {
                rows.push(row);
            }
            continue;
        }
        if let Some(path) = field.strip_prefix(b"worktree ") {
            if let Some(row) = current.take() {
                rows.push(row);
            }
            current = Some(GitWorktreeRow {
                path: path_from_git_bytes(path)?,
                head: None,
                branch: None,
                prunable: false,
            });
        } else if let Some(row) = current.as_mut() {
            if let Some(head) = field.strip_prefix(b"HEAD ") {
                row.head = Some(strict_ascii_field(head, "Git worktree HEAD")?);
            } else if let Some(branch) = field.strip_prefix(b"branch ") {
                row.branch = Some(strict_ascii_field(branch, "Git worktree branch")?);
            } else if field == b"prunable" || field.starts_with(b"prunable ") {
                row.prunable = true;
            }
        }
    }
    if let Some(row) = current {
        rows.push(row);
    }
    if rows.is_empty() {
        return Err("Git returned no worktree records.".into());
    }
    Ok(rows)
}

fn read_dirty_status(worktree: &Path) -> Result<DirtyStatus, String> {
    let mut command = git_command(worktree);
    command
        .arg("status")
        .arg("--porcelain=v1")
        .arg("-z")
        .arg("--untracked-files=all");
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES)?;
    let raw = require_git_success(output, "inspect managed worktree status")?;
    let ignored_raw = ignored_paths_raw(worktree)?;
    let ignored_paths = nul_paths(&ignored_raw, "ignored worktree path")?;
    let mut view = parse_dirty_status(&raw)?;
    view.ignored = ignored_paths
        .iter()
        .map(|path| display_path(path))
        .collect();
    view.dirty |= !view.ignored.is_empty();
    Ok(DirtyStatus {
        view,
        raw,
        ignored_raw,
    })
}

fn ignored_paths_raw(worktree: &Path) -> Result<Vec<u8>, String> {
    let mut command = git_command(worktree);
    command
        .arg("ls-files")
        .arg("--others")
        .arg("--ignored")
        .arg("--exclude-standard")
        .arg("-z")
        .arg("--");
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES)?;
    require_git_success(output, "list exact ignored worktree files")
}

fn nul_paths(bytes: &[u8], label: &str) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for field in bytes.split(|byte| *byte == 0) {
        if field.is_empty() {
            continue;
        }
        let path = path_from_git_bytes(field)?;
        safe_recovery_target(Path::new("."), &path)
            .map_err(|error| format!("Git returned unsafe {label}: {error}"))?;
        paths.push(path);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn parse_dirty_status(bytes: &[u8]) -> Result<WorktreeDirtyView, String> {
    let mut staged = BTreeSet::new();
    let mut unstaged = BTreeSet::new();
    let mut conflicted = BTreeSet::new();
    let mut untracked = BTreeSet::new();
    let fields: Vec<&[u8]> = bytes.split(|byte| *byte == 0).collect();
    let mut index = 0;
    while index < fields.len() {
        let field = fields[index];
        index += 1;
        if field.is_empty() {
            continue;
        }
        if field.len() < 4 || field[2] != b' ' {
            return Err("Git returned malformed porcelain status.".into());
        }
        let x = field[0];
        let y = field[1];
        let mut shown = display_git_path(&field[3..]);
        if matches!(x, b'R' | b'C') {
            let original = fields
                .get(index)
                .ok_or_else(|| "Git rename status omitted its source path.".to_owned())?;
            index += 1;
            shown = format!("{} ← {}", shown, display_git_path(original));
        }
        if x == b'?' && y == b'?' {
            untracked.insert(shown);
        } else if is_conflict_status(x, y) {
            conflicted.insert(shown);
        } else {
            if x != b' ' {
                staged.insert(shown.clone());
            }
            if y != b' ' {
                unstaged.insert(shown);
            }
        }
    }
    let dirty = !(staged.is_empty()
        && unstaged.is_empty()
        && conflicted.is_empty()
        && untracked.is_empty());
    Ok(WorktreeDirtyView {
        dirty,
        staged: staged.into_iter().collect(),
        unstaged: unstaged.into_iter().collect(),
        conflicted: conflicted.into_iter().collect(),
        untracked: untracked.into_iter().collect(),
        ignored: Vec::new(),
    })
}

fn is_conflict_status(x: u8, y: u8) -> bool {
    matches!(
        (x, y),
        (b'D' | b'U', b'D') | (b'A' | b'D' | b'U', b'U') | (b'A' | b'U', b'A')
    )
}

fn strict_git_line<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{label} is not UTF-8."))?;
    let line = text.trim();
    if line.is_empty() || line.contains('\n') || line.contains('\r') {
        Err(format!("{label} is empty or multiline."))
    } else {
        Ok(line)
    }
}

fn strict_ascii_field(bytes: &[u8], label: &str) -> Result<String, String> {
    if bytes.is_empty() || !bytes.is_ascii() || bytes.iter().any(u8::is_ascii_control) {
        return Err(format!("{label} is malformed."));
    }
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(unix)]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, String> {
    if bytes.is_empty() || bytes.contains(&0) {
        return Err("Git worktree path is empty or contains NUL.".into());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, String> {
    String::from_utf8(bytes.to_vec())
        .map(PathBuf::from)
        .map_err(|_| "Git worktree path is not UTF-8.".into())
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
fn display_os_bytes(bytes: &[u8]) -> String {
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

#[cfg(unix)]
fn display_path(path: &Path) -> String {
    display_os_bytes(path.as_os_str().as_bytes())
}

#[cfg(not(unix))]
fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn create_owner_only_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("Cannot create app-owned worktree directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Cannot restrict app-owned worktree directory: {error}"))?;
    }
    Ok(())
}

fn append_operation(
    store: &PlusSessionStore,
    project_id: &str,
    worktree_id: Option<&str>,
    operation: &str,
    state: &str,
) -> Result<(), String> {
    create_owner_only_dir(store.state_root())?;
    let event = WorktreeOperationEvent {
        schema_version: 1,
        sequence: NEXT_OPERATION.fetch_add(1, Ordering::Relaxed),
        timestamp_unix_ms: unix_time_millis(),
        project_id,
        worktree_id,
        operation,
        state,
    };
    let mut line = serde_json::to_vec(&event)
        .map_err(|error| format!("Cannot encode worktree operation intent: {error}"))?;
    line.push(b'\n');
    let path = store.state_root().join(WORKTREE_OPERATIONS_FILE);
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("Cannot open worktree operation journal: {error}"))?;
    file.write_all(&line)
        .map_err(|error| format!("Cannot append worktree operation journal: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("Cannot sync worktree operation journal: {error}"))
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use grok_build_plus_host::{PlusKnownProject, PlusSessionStore, bind_project_folder};

    use super::{
        MAX_GIT_METADATA_BYTES, create_managed_worktree, discard_managed_worktree,
        export_worktree_recovery, git_command, initialize_project_git, list_managed_worktrees,
        parse_dirty_status, parse_git_worktree_rows, read_dirty_status, remove_managed_worktree,
        remove_worktree_after_export, require_git_success, run_git,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn fixture() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "grok-build-worktree-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn test_git(root: &std::path::Path, args: &[&str]) {
        let mut command = git_command(root);
        command.args(args);
        let output = run_git(command, None, MAX_GIT_METADATA_BYTES).expect("run fixture Git");
        require_git_success(output, "prepare test fixture").expect("fixture Git success");
    }

    fn prepare_repository(root: &std::path::Path) {
        fs::create_dir_all(root).expect("create repository");
        test_git(root, &["init", "--quiet", "--initial-branch=main"]);
        test_git(root, &["config", "user.name", "Grok Build Test"]);
        test_git(root, &["config", "user.email", "grok-build-test@invalid"]);
        fs::write(root.join("tracked.txt"), "baseline\n").expect("write tracked fixture");
        fs::write(root.join(".gitignore"), "ignored-cache/\n").expect("write ignore fixture");
        test_git(root, &["add", "--", "tracked.txt", ".gitignore"]);
        test_git(root, &["commit", "--quiet", "-m", "baseline"]);
    }

    fn assert_post_export_dirty_removal(store: &PlusSessionStore, export_root: &std::path::Path) {
        let project = store.active_known_project().expect("active base project");
        let beta = create_managed_worktree(store, &project, "Task Beta", "HEAD")
            .expect("create beta worktree");
        store
            .register_managed_worktree(&project.id, beta.clone(), true)
            .expect("register beta worktree");
        fs::write(beta.path.join("only-untracked.txt"), "beta recovery\n")
            .expect("write beta untracked");
        let project = store.active_known_project().expect("active beta project");
        let exported = export_worktree_recovery(store, &project, &beta.id, export_root)
            .expect("export beta recovery");
        let project = store.active_known_project().expect("reloaded beta receipt");
        fs::write(
            beta.path.join("only-untracked.txt"),
            "beta changed after export\n",
        )
        .expect("change beta after export");
        let refused = remove_worktree_after_export(
            store,
            &project,
            &beta.id,
            &exported.manifest_hash,
            "REMOVE Task Beta",
        )
        .expect("stale beta export refusal");
        assert_eq!(refused.outcome, "refused");
        assert!(beta.path.exists());
        let project = store.active_known_project().expect("beta after refusal");
        let exported = export_worktree_recovery(store, &project, &beta.id, export_root)
            .expect("refresh beta recovery");
        let project = store
            .active_known_project()
            .expect("reloaded fresh beta receipt");
        let removed = remove_worktree_after_export(
            store,
            &project,
            &beta.id,
            &exported.manifest_hash,
            "REMOVE Task Beta",
        )
        .expect("remove beta after export");
        assert_eq!(removed.outcome, "removed-after-export");
        store
            .forget_managed_worktree(&project.id, &beta.id)
            .expect("forget beta");
        assert!(!beta.path.exists());
    }

    #[test]
    fn parses_porcelain_worktrees_and_exact_dirty_categories() {
        let rows = parse_git_worktree_rows(
            b"worktree /tmp/base\0HEAD 0123456789012345678901234567890123456789\0branch refs/heads/main\0\0worktree /tmp/task\0HEAD aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0branch refs/heads/task\0\0",
        )
        .expect("porcelain worktrees");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].path, std::path::PathBuf::from("/tmp/task"));

        let dirty = parse_dirty_status(
            b"M  staged.txt\0 M unstaged.txt\0UU conflict.txt\0?? untracked.txt\0",
        )
        .expect("porcelain status");
        assert_eq!(dirty.staged, ["staged.txt"]);
        assert_eq!(dirty.unstaged, ["unstaged.txt"]);
        assert_eq!(dirty.conflicted, ["conflict.txt"]);
        assert_eq!(dirty.untracked, ["untracked.txt"]);
        assert!(dirty.dirty);
    }

    #[test]
    fn non_git_projects_are_unavailable_without_invoking_git() {
        let root = fixture();
        fs::create_dir_all(&root).expect("create non-Git project");
        let root = root.canonicalize().expect("canonical non-Git project");
        let project = PlusKnownProject {
            id: "non-git-project".into(),
            name: "non-git".into(),
            root: root.clone(),
            active_worktree_id: None,
            worktrees: Vec::new(),
        };

        let view = list_managed_worktrees(&project);

        assert!(!view.available);
        assert!(view.status.contains("not a Git working tree"));
        assert!(view.worktrees.is_empty());
        fs::remove_dir_all(root).expect("clean non-Git project");
    }

    #[test]
    fn git_setup_creates_empty_first_commit_without_staging_project_files() {
        let root = fixture();
        fs::create_dir_all(&root).expect("create setup project");
        fs::write(
            root.join("must-remain-untracked.txt"),
            "private local bytes\n",
        )
        .expect("write untracked fixture");
        let root = root.canonicalize().expect("canonical setup project");
        let project = PlusKnownProject {
            id: "git-setup-project".into(),
            name: "git-setup".into(),
            root: root.clone(),
            active_worktree_id: None,
            worktrees: Vec::new(),
        };
        let setup = initialize_project_git(
            &project,
            Some("Grok Build Test"),
            Some("grok-build-test@invalid"),
        )
        .expect("setup Git");
        assert_eq!(setup.outcome, "committed");
        assert!(setup.commit.is_some());
        let mut tree = git_command(&root);
        tree.arg("ls-tree").arg("--name-only").arg("HEAD");
        let tree = require_git_success(
            run_git(tree, None, MAX_GIT_METADATA_BYTES).expect("tree command"),
            "inspect empty first tree",
        )
        .expect("tree success");
        assert!(tree.is_empty(), "first commit must contain no files");
        assert!(root.join("must-remain-untracked.txt").is_file());
        fs::remove_dir_all(root).expect("cleanup setup project");
    }

    #[test]
    fn git_setup_reports_missing_identity_partial_state_and_unsafe_metadata() {
        let root = fixture();
        fs::create_dir_all(&root).expect("create setup project");
        fs::write(root.join("keep-untracked.txt"), "stay untracked\n").expect("seed file");
        let root = root.canonicalize().expect("canonical setup project");
        let project = PlusKnownProject {
            id: "git-setup-state-project".into(),
            name: "git-setup-state".into(),
            root: root.clone(),
            active_worktree_id: None,
            worktrees: Vec::new(),
        };

        let needs_identity = initialize_project_git(&project, None, None).expect("initialize Git");
        assert_eq!(needs_identity.outcome, "needs_identity");
        assert!(needs_identity.initialized);
        assert!(
            list_managed_worktrees(&project).setup_available,
            "an unborn repository must keep the setup action available after restart"
        );

        for (key, value) in [
            ("user.name", "Grok Build Test"),
            ("user.email", "grok-build-test@invalid"),
        ] {
            let mut config = git_command(&root);
            config.arg("config").arg("--local").arg(key).arg(value);
            require_git_success(
                run_git(config, None, MAX_GIT_METADATA_BYTES).expect("config command"),
                "configure test identity",
            )
            .expect("config succeeds");
        }
        let mut stage = git_command(&root);
        stage.arg("add").arg("--").arg("keep-untracked.txt");
        require_git_success(
            run_git(stage, None, MAX_GIT_METADATA_BYTES).expect("stage command"),
            "stage fixture",
        )
        .expect("stage succeeds");
        let partial = initialize_project_git(&project, None, None).expect("inspect partial setup");
        assert_eq!(partial.outcome, "partial");
        assert!(partial.initialized);
        assert!(list_managed_worktrees(&project).setup_available);
        let mut head = git_command(&root);
        head.arg("rev-parse").arg("--verify").arg("HEAD");
        assert!(
            !run_git(head, None, MAX_GIT_METADATA_BYTES)
                .expect("head command")
                .success()
        );
        fs::remove_dir_all(&root).expect("cleanup partial setup project");

        let unsafe_root = fixture();
        let target = fixture();
        fs::create_dir_all(&unsafe_root).expect("create unsafe setup root");
        fs::create_dir_all(&target).expect("create symlink target");
        std::os::unix::fs::symlink(&target, unsafe_root.join(".git"))
            .expect("create unsafe Git symlink");
        let unsafe_root = unsafe_root.canonicalize().expect("canonical unsafe root");
        let unsafe_project = PlusKnownProject {
            id: "git-setup-unsafe-project".into(),
            name: "git-setup-unsafe".into(),
            root: unsafe_root.clone(),
            active_worktree_id: None,
            worktrees: Vec::new(),
        };
        let refused = initialize_project_git(
            &unsafe_project,
            Some("Grok Build Test"),
            Some("grok-build-test@invalid"),
        )
        .expect("unsafe metadata has structured refusal");
        assert_eq!(refused.outcome, "refused");
        assert!(!refused.initialized);
        fs::remove_dir_all(unsafe_root).expect("cleanup unsafe setup root");
        fs::remove_dir_all(target).expect("cleanup symlink target");
    }

    #[test]
    fn stalled_git_children_are_stopped_at_the_host_deadline() {
        let mut child = Command::new("/bin/sleep");
        child.arg("5");
        let started = Instant::now();
        let error = crate::bounded_process::collect(
            child,
            &[],
            &crate::bounded_process::Limits {
                input: 0,
                output: 0,
                error: 0,
                timeout: Duration::from_millis(25),
            },
        )
        .err()
        .expect("stop bounded child fixture");
        assert!(error.contains("deadline"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn managed_worktree_lifecycle_refuses_dirty_and_separates_sessions() {
        let root = fixture();
        let source = root.join("source");
        prepare_repository(&source);
        let source = source.canonicalize().expect("canonical source");
        let store = PlusSessionStore::from_state_root(root.join("state"));
        let bound = bind_project_folder(&source).expect("bind source");
        store
            .remember_known_project(&bound)
            .expect("remember source project");
        let project = store.active_known_project().expect("active source project");

        let alpha = create_managed_worktree(&store, &project, "Task Alpha", "HEAD")
            .expect("create alpha worktree");
        let (book, _) = store
            .register_managed_worktree(&project.id, alpha.clone(), true)
            .expect("register alpha worktree");
        assert_eq!(book.active_id.as_deref(), Some(project.id.as_str()));
        assert_eq!(book.projects[0].active_root(), alpha.path);
        store
            .remember_chat_transcript("alpha-only-chat")
            .expect("remember alpha chat");
        store
            .activate_project_workspace(&project.id, None)
            .expect("activate base project");
        assert_ne!(
            store.load_chat_transcript().expect("base chat"),
            Some("alpha-only-chat".into())
        );
        store
            .remember_chat_transcript("base-only-chat")
            .expect("remember base chat");
        store
            .activate_project_workspace(&project.id, Some(&alpha.id))
            .expect("reactivate alpha");
        assert_eq!(
            store.load_chat_transcript().expect("alpha chat"),
            Some("alpha-only-chat".into())
        );
        let project = store.active_known_project().expect("active alpha project");

        fs::write(alpha.path.join("tracked.txt"), "staged change\n").expect("modify tracked file");
        test_git(&alpha.path, &["add", "--", "tracked.txt"]);
        fs::write(alpha.path.join("untracked.txt"), "recovery payload\n")
            .expect("write untracked file");
        fs::create_dir_all(alpha.path.join("ignored-cache")).expect("create ignored directory");
        fs::write(
            alpha.path.join("ignored-cache/private.bin"),
            "ignored recovery payload\n",
        )
        .expect("write ignored file");
        let dirty = read_dirty_status(&alpha.path).expect("dirty alpha");
        assert_eq!(dirty.view.staged, ["tracked.txt"]);
        assert_eq!(dirty.view.untracked, ["untracked.txt"]);
        assert_eq!(dirty.view.ignored, ["ignored-cache/private.bin"]);

        let refused =
            remove_managed_worktree(&store, &project, &alpha.id).expect("dirty removal response");
        assert_eq!(refused.outcome, "refused");
        assert!(alpha.path.exists());

        let export_root = root.join("exports");
        fs::create_dir_all(&export_root).expect("create export destination");
        let exported = export_worktree_recovery(
            &store,
            &store.active_known_project().expect("active alpha project"),
            &alpha.id,
            &export_root,
        )
        .expect("export alpha recovery");
        let export_path = std::path::PathBuf::from(&exported.path);
        assert!(export_path.join("manifest.json").is_file());
        assert!(export_path.join("staged.patch").is_file());
        let manifest_bytes =
            fs::read(export_path.join("manifest.json")).expect("read recovery manifest");
        assert_eq!(
            exported.manifest_hash,
            grok_build_plus_host::worktree_recovery_digest(&manifest_bytes)
        );
        assert_eq!(
            fs::read_to_string(export_path.join("untracked/untracked.txt"))
                .expect("read recovered untracked file"),
            "recovery payload\n"
        );
        assert_eq!(
            fs::read_to_string(export_path.join("ignored/ignored-cache/private.bin"))
                .expect("read recovered ignored file"),
            "ignored recovery payload\n"
        );
        let manifest_text = String::from_utf8(manifest_bytes).expect("manifest UTF-8");
        assert!(manifest_text.contains("ignored/ignored-cache/private.bin"));

        assert!(discard_managed_worktree(&store, &project, &alpha.id, "DISCARD wrong").is_err());
        let discarded = discard_managed_worktree(&store, &project, &alpha.id, "DISCARD Task Alpha")
            .expect("explicitly discard alpha");
        assert!(!discarded.dirty.dirty);
        let removed =
            remove_managed_worktree(&store, &project, &alpha.id).expect("remove clean alpha");
        assert_eq!(removed.outcome, "removed");
        store
            .forget_managed_worktree(&project.id, &alpha.id)
            .expect("forget removed alpha");
        assert!(!alpha.path.exists());

        assert_post_export_dirty_removal(&store, &export_root);

        fs::remove_dir_all(root).expect("clean worktree fixture");
    }
}
