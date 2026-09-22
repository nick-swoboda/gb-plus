//! Project, workspace, Git review, and managed-worktree commands.

use super::{
    AppHandle, AppSnapshot, AppState, Arc, Backend, BoundProject, GitHunkActionView, GitReviewView,
    GitSetupView, PlusProjectBook, PreparedGitOperation, ProjectId, ProjectTransitionContext,
    PtySessionKey, Serialize, SnapshotSeed, State, WorkspaceDirectoryView, WorkspaceFileView,
    WorkspaceId, WorkspaceSessionEffect, WorktreeListView, WorktreeRecoveryExportView,
    WorktreeRemoveView, WorktreeUserActionView, bind_and_remember_project_folder,
    bind_project_folder, commit_managed_worktree, create_managed_worktree, discard_hunk,
    discard_managed_worktree, export_recovery, initialize_project_git, list_managed_worktrees,
    lock_backend, present_snapshot, project_operation_drift, read_git_review,
    read_workspace_directory, read_workspace_file, remove_after_export, remove_managed_worktree,
    stage_hunk, sync_workspace_watch, unstage_hunk,
};

async fn run_project_git_operation<T, F>(
    state: State<'_, AppState>,
    action: crate::events::GitEventAction,
    phase: crate::events::GitEventPhase,
    identity: Option<String>,
    operation: F,
    success_phase: impl FnOnce(&T) -> crate::events::GitEventPhase + Send + 'static,
) -> Result<(T, AppSnapshot), String>
where
    T: Send + 'static,
    F: FnOnce(&PreparedGitOperation) -> Result<T, String> + Send + 'static,
{
    let prepared =
        lock_backend(&state.backend)?.prepare_git_operation(action, phase, identity.as_deref())?;
    execute_prepared_project_operation(
        state,
        prepared,
        operation,
        move |backend, prepared, effect| {
            let terminal_phase = effect
                .as_ref()
                .map_or(crate::events::GitEventPhase::Completed, success_phase);
            backend.finish_prepared_git_with_phase(prepared, effect, terminal_phase)
        },
    )
    .await
}

async fn execute_prepared_project_operation<T, U, Effect, Finish>(
    state: State<'_, AppState>,
    prepared: PreparedGitOperation,
    effect: Effect,
    finish: Finish,
) -> Result<(U, AppSnapshot), String>
where
    T: Send + 'static,
    U: Send + 'static,
    Effect: FnOnce(&PreparedGitOperation) -> Result<T, String> + Send + 'static,
    Finish: FnOnce(
            &mut Backend,
            &PreparedGitOperation,
            Result<T, String>,
        ) -> Result<(U, SnapshotSeed), String>
        + Send
        + 'static,
{
    let shared = Arc::clone(&state.backend);
    let gate = state.operations.gate(&prepared.context.project_id)?;
    let worker_shared = Arc::clone(&shared);
    let (result, seed) = tauri::async_runtime::spawn_blocking(move || {
        let _permit = gate
            .lock()
            .map_err(|_| "Project operation permit is unavailable.".to_owned())?;
        let effect = match lock_backend(&worker_shared)?.revalidate_operation(&prepared.context) {
            Ok(()) => effect(&prepared),
            Err(error) => Err(error),
        };
        let mut backend = lock_backend(&worker_shared)?;
        finish(&mut backend, &prepared, effect)
    })
    .await
    .map_err(|error| format!("Project operation worker stopped before completing: {error}"))??;
    Ok((result, present_snapshot(seed).await?))
}

async fn execute_project_transition<Effect>(
    state: State<'_, AppState>,
    context: ProjectTransitionContext,
    effect: Effect,
) -> Result<AppSnapshot, String>
where
    Effect: FnOnce() -> Result<ProjectTransitionEffect, String> + Send + 'static,
{
    let shared = Arc::clone(&state.backend);
    let transition_gate = state.operations.transition_gate();
    let project_gate = context
        .active_project_id
        .as_ref()
        .map(|project| state.operations.gate(project))
        .transpose()?;
    let worker_shared = Arc::clone(&shared);
    let seed = tauri::async_runtime::spawn_blocking(move || {
        let _transition = transition_gate
            .lock()
            .map_err(|_| "Project transition permit is unavailable.".to_owned())?;
        let _project = project_gate
            .as_ref()
            .map(|gate| {
                gate.lock()
                    .map_err(|_| "Project operation permit is unavailable.".to_owned())
            })
            .transpose()?;
        lock_backend(&worker_shared)?.revalidate_project_transition(&context)?;
        let effect = effect()?;
        let mut backend = lock_backend(&worker_shared)?;
        backend.revalidate_project_transition(&context)?;
        backend.load_active_project(effect.projects, effect.bound, effect.status);
        Ok::<_, String>(backend.snapshot_seed())
    })
    .await
    .map_err(|error| format!("Project transition worker stopped before completing: {error}"))??;
    present_snapshot(seed).await
}

async fn execute_project_read<T, Read>(
    state: State<'_, AppState>,
    context: crate::backend::OperationContext,
    read: Read,
) -> Result<T, String>
where
    T: Send + 'static,
    Read: FnOnce() -> Result<T, String> + Send + 'static,
{
    let shared = Arc::clone(&state.backend);
    let gate = state.operations.gate(&context.project_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _permit = gate
            .lock()
            .map_err(|_| "Project operation permit is unavailable.".to_owned())?;
        lock_backend(&shared)?.revalidate_operation(&context)?;
        let result = read()?;
        lock_backend(&shared)?.revalidate_operation(&context)?;
        Ok(result)
    })
    .await
    .map_err(|error| format!("Project read worker stopped before completing: {error}"))?
}

fn finish_active_workspace(
    backend: &mut Backend,
    prepared: &PreparedGitOperation,
    effect: Result<ActiveWorkspaceEffect, String>,
    event_failure: &'static str,
) -> Result<((), SnapshotSeed), String> {
    let effect = match effect {
        Ok(effect) => {
            if let Err(error) = backend.revalidate_workspace_effect(
                &prepared.context,
                &effect.projects,
                &effect.bound,
                WorkspaceSessionEffect::FollowWorkspace,
            ) {
                let _ = backend.record_git_event(
                    prepared.event_context.clone(),
                    prepared.action,
                    crate::events::GitEventPhase::Refused,
                    prepared.identity.as_deref(),
                );
                return Err(error);
            }
            effect
        }
        Err(error) => {
            backend.revalidate_operation(&prepared.context)?;
            let _ = backend.record_git_event(
                prepared.event_context.clone(),
                prepared.action,
                crate::events::GitEventPhase::Refused,
                prepared.identity.as_deref(),
            );
            return Err(error);
        }
    };
    backend.load_active_project(effect.projects, Some(effect.bound), effect.status);
    backend
        .record_git_event(
            prepared.event_context.clone(),
            prepared.action,
            crate::events::GitEventPhase::Completed,
            effect.terminal_identity.as_deref(),
        )
        .map_err(|error| format!("{event_failure}: {error}"))?;
    Ok(((), backend.snapshot_seed()))
}

fn finish_create_worktree(
    backend: &mut Backend,
    prepared: &PreparedGitOperation,
    effect: Result<CreateWorktreeEffect, String>,
) -> Result<((), SnapshotSeed), String> {
    match effect {
        Ok(CreateWorktreeEffect::Ready(effect)) => finish_active_workspace(
            backend,
            prepared,
            Ok(effect),
            "The managed worktree was created and activated, but its Activity terminal event could not be persisted",
        ),
        Ok(CreateWorktreeEffect::Partial { worktree_id, error }) => {
            backend.revalidate_operation(&prepared.context)?;
            let _ = backend.record_git_event(
                prepared.event_context.clone(),
                prepared.action,
                crate::events::GitEventPhase::PartialFailure,
                Some(&worktree_id),
            );
            Err(error)
        }
        Err(error) => finish_active_workspace(
            backend,
            prepared,
            Err(error),
            "The managed worktree Activity event could not be persisted",
        ),
    }
}

fn finish_remove_worktree(
    backend: &mut Backend,
    prepared: &PreparedGitOperation,
    effect: Result<RemoveWorktreeEffect, String>,
) -> Result<(WorktreeRemoveView, SnapshotSeed), String> {
    let (view, active) = match effect {
        Ok(RemoveWorktreeEffect::Ready(ready)) => (ready.view, ready.active),
        Ok(RemoveWorktreeEffect::StateUpdateFailed(error)) => {
            backend.revalidate_operation(&prepared.context)?;
            return Err(error);
        }
        Err(error) => {
            backend.revalidate_operation(&prepared.context)?;
            let _ = backend.record_git_event(
                prepared.event_context.clone(),
                crate::events::GitEventAction::WorktreeRemoveRefused,
                crate::events::GitEventPhase::Refused,
                prepared.identity.as_deref(),
            );
            return Err(error);
        }
    };
    match active.as_ref() {
        Some((projects, Some(bound), _)) => {
            let session_effect =
                if prepared.project.active_worktree_id.as_deref() == view.removed_id.as_deref() {
                    WorkspaceSessionEffect::FollowWorkspace
                } else {
                    WorkspaceSessionEffect::Preserve
                };
            backend.revalidate_workspace_effect(
                &prepared.context,
                projects,
                bound,
                session_effect,
            )?;
        }
        Some((_, None, _)) => {
            return Err(project_operation_drift());
        }
        None => backend.revalidate_operation(&prepared.context)?,
    }
    if let Some((projects, bound, status)) = active {
        backend.load_active_project(projects, bound, status);
    }
    let removed = view.removed_id.is_some();
    backend.record_git_event(
        prepared.event_context.clone(),
        if removed {
            crate::events::GitEventAction::WorktreeRemoved
        } else {
            crate::events::GitEventAction::WorktreeRemoveRefused
        },
        if removed {
            crate::events::GitEventPhase::Completed
        } else {
            crate::events::GitEventPhase::Refused
        },
        prepared.identity.as_deref(),
    )?;
    Ok((view, backend.snapshot_seed()))
}
#[tauri::command]
pub(crate) async fn bind_project(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let workspace_watch = state.workspace_watch.clone();
    let browser = state.browser.clone();
    let capture = state.capture.clone();
    let desktop = state.desktop.clone();
    let (context, store) = {
        let backend = lock_backend(&state.backend)?;
        (backend.project_transition_context(), backend.store.clone())
    };
    let snapshot = execute_project_transition(state, context, move || {
        let path = path.trim();
        if path.is_empty() {
            return Err("Choose an absolute project folder before binding.".into());
        }
        let bound = bind_and_remember_project_folder(&store, std::path::PathBuf::from(path))
            .map_err(|error| error.to_string())?;
        let projects = store
            .load_project_book()
            .map_err(|error| error.to_string())?;
        let status = format!("Active project: {}", bound.folder().display());
        Ok(ProjectTransitionEffect {
            projects,
            bound: Some(bound),
            status,
        })
    })
    .await?;
    capture.project_switched(None);
    desktop.project_switched(None);
    tauri::async_runtime::spawn_blocking(move || browser.stop_for_project_change())
        .await
        .map_err(|error| format!("Browser project-change stop worker failed: {error}"))??;
    sync_workspace_watch(&app, &workspace_watch, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn switch_project(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let workspace_watch = state.workspace_watch.clone();
    let browser = state.browser.clone();
    let capture = state.capture.clone();
    let desktop = state.desktop.clone();
    let (context, store) = {
        let backend = lock_backend(&state.backend)?;
        (backend.project_transition_context(), backend.store.clone())
    };
    let snapshot = execute_project_transition(state, context, move || {
        let (projects, bound) = store
            .activate_known_project(&id)
            .map_err(|error| error.to_string())?;
        let status = format!("Active project: {}", bound.folder().display());
        Ok(ProjectTransitionEffect {
            projects,
            bound: Some(bound),
            status,
        })
    })
    .await?;
    capture.project_switched(None);
    desktop.project_switched(None);
    tauri::async_runtime::spawn_blocking(move || browser.stop_for_project_change())
        .await
        .map_err(|error| format!("Browser project-change stop worker failed: {error}"))??;
    sync_workspace_watch(&app, &workspace_watch, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn remove_project(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let workspace_watch = state.workspace_watch.clone();
    let pty = state.pty.clone();
    let browser = state.browser.clone();
    let capture = state.capture.clone();
    let desktop = state.desktop.clone();
    let removed_project = ProjectId::new(id.clone());
    let (context, store) = {
        let backend = lock_backend(&state.backend)?;
        (backend.project_transition_context(), backend.store.clone())
    };
    let snapshot = execute_project_transition(state, context, move || {
        let projects = store
            .unlist_known_project(&id)
            .map_err(|error| error.to_string())?;
        let bound = projects
            .active_id
            .as_ref()
            .and_then(|active| {
                projects
                    .projects
                    .iter()
                    .find(|project| &project.id == active)
            })
            .map(|project| bind_project_folder(project.active_root()))
            .transpose()
            .map_err(|error| error.to_string())?;
        let status = bound.as_ref().map_or_else(
            || "No active project. Choose a folder to start.".to_owned(),
            |bound| format!("Active project: {}", bound.folder().display()),
        );
        Ok(ProjectTransitionEffect {
            projects,
            bound,
            status,
        })
    })
    .await?;
    pty.stop_project(&removed_project);
    capture.project_switched(None);
    desktop.project_switched(None);
    tauri::async_runtime::spawn_blocking(move || browser.stop_for_project_change())
        .await
        .map_err(|error| format!("Browser project-removal stop worker failed: {error}"))??;
    sync_workspace_watch(&app, &workspace_watch, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn list_workspace_directory(
    state: State<'_, AppState>,
    path: String,
) -> Result<WorkspaceDirectoryView, String> {
    let bound = lock_backend(&state.backend)?.workspace_read_authority()?;
    tauri::async_runtime::spawn_blocking(move || read_workspace_directory(&bound, &path))
        .await
        .map_err(|error| format!("Workspace reader stopped before completing: {error}"))?
}

#[tauri::command]
pub(crate) async fn open_workspace_file(
    state: State<'_, AppState>,
    path: String,
) -> Result<WorkspaceFileView, String> {
    let bound = lock_backend(&state.backend)?.workspace_read_authority()?;
    tauri::async_runtime::spawn_blocking(move || read_workspace_file(&bound, &path))
        .await
        .map_err(|error| format!("Workspace file reader stopped before completing: {error}"))?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorktreeRemoveResponse {
    result: WorktreeRemoveView,
    snapshot: AppSnapshot,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorktreeUserActionResponse {
    result: WorktreeUserActionView,
    snapshot: AppSnapshot,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorktreeRecoveryExportResponse {
    result: WorktreeRecoveryExportView,
    snapshot: AppSnapshot,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitHunkActionResponse {
    result: GitHunkActionView,
    snapshot: AppSnapshot,
}

struct ActiveWorkspaceEffect {
    projects: PlusProjectBook,
    bound: BoundProject,
    status: String,
    terminal_identity: Option<String>,
}

struct ProjectTransitionEffect {
    projects: PlusProjectBook,
    bound: Option<BoundProject>,
    status: String,
}

enum CreateWorktreeEffect {
    Ready(ActiveWorkspaceEffect),
    Partial { worktree_id: String, error: String },
}

struct RemoveWorktreeReady {
    view: WorktreeRemoveView,
    active: Option<(PlusProjectBook, Option<BoundProject>, String)>,
}

enum RemoveWorktreeEffect {
    Ready(Box<RemoveWorktreeReady>),
    StateUpdateFailed(String),
}

#[tauri::command]
pub(crate) async fn list_git_review(state: State<'_, AppState>) -> Result<GitReviewView, String> {
    let (context, project) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.operation_context()?,
            backend.active_project_record()?,
        )
    };
    execute_project_read(state, context, move || Ok(read_git_review(&project))).await
}

#[tauri::command]
pub(crate) async fn stage_git_hunk(
    state: State<'_, AppState>,
    hunk_id: String,
) -> Result<GitHunkActionResponse, String> {
    let identity = hunk_id.clone();
    let (result, snapshot) = run_project_git_operation(
        state,
        crate::events::GitEventAction::HunkStaged,
        crate::events::GitEventPhase::Requested,
        Some(identity),
        move |prepared| stage_hunk(&prepared.store, &prepared.project, &hunk_id),
        |_| crate::events::GitEventPhase::Completed,
    )
    .await?;
    Ok(GitHunkActionResponse { result, snapshot })
}

#[tauri::command]
pub(crate) async fn unstage_git_hunk(
    state: State<'_, AppState>,
    hunk_id: String,
) -> Result<GitHunkActionResponse, String> {
    let identity = hunk_id.clone();
    let (result, snapshot) = run_project_git_operation(
        state,
        crate::events::GitEventAction::HunkUnstaged,
        crate::events::GitEventPhase::Requested,
        Some(identity),
        move |prepared| unstage_hunk(&prepared.store, &prepared.project, &hunk_id),
        |_| crate::events::GitEventPhase::Completed,
    )
    .await?;
    Ok(GitHunkActionResponse { result, snapshot })
}

#[tauri::command]
pub(crate) async fn discard_git_hunk(
    state: State<'_, AppState>,
    hunk_id: String,
    confirmation: String,
) -> Result<GitHunkActionResponse, String> {
    let identity = hunk_id.clone();
    let (result, snapshot) = run_project_git_operation(
        state,
        crate::events::GitEventAction::HunkDiscarded,
        crate::events::GitEventPhase::Requested,
        Some(identity),
        move |prepared| discard_hunk(&prepared.store, &prepared.project, &hunk_id, &confirmation),
        |_| crate::events::GitEventPhase::Completed,
    )
    .await?;
    Ok(GitHunkActionResponse { result, snapshot })
}

#[tauri::command]
pub(crate) async fn list_worktrees(state: State<'_, AppState>) -> Result<WorktreeListView, String> {
    let (context, project) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.operation_context()?,
            backend.active_project_record()?,
        )
    };
    execute_project_read(state, context, move || Ok(list_managed_worktrees(&project))).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GitSetupResponse {
    result: GitSetupView,
    snapshot: AppSnapshot,
}

#[tauri::command]
pub(crate) async fn initialize_git(
    state: State<'_, AppState>,
    author_name: Option<String>,
    author_email: Option<String>,
) -> Result<GitSetupResponse, String> {
    let (result, snapshot) = run_project_git_operation(
        state,
        crate::events::GitEventAction::RepositoryInitialized,
        crate::events::GitEventPhase::Requested,
        None,
        move |prepared| {
            initialize_project_git(
                &prepared.project,
                author_name.as_deref(),
                author_email.as_deref(),
            )
        },
        |view| match view.outcome {
            "committed" => crate::events::GitEventPhase::Completed,
            "refused" => crate::events::GitEventPhase::Refused,
            _ => crate::events::GitEventPhase::PartialFailure,
        },
    )
    .await?;
    Ok(GitSetupResponse { result, snapshot })
}

#[tauri::command]
pub(crate) async fn create_worktree(
    app: AppHandle,
    state: State<'_, AppState>,
    task: String,
    base_ref: String,
) -> Result<AppSnapshot, String> {
    let workspace_watch = state.workspace_watch.clone();
    let browser = state.browser.clone();
    let capture = state.capture.clone();
    let desktop = state.desktop.clone();
    let prepared = lock_backend(&state.backend)?.prepare_git_operation(
        crate::events::GitEventAction::WorktreeCreated,
        crate::events::GitEventPhase::Requested,
        None,
    )?;
    let ((), snapshot) = execute_prepared_project_operation(
        state,
        prepared,
        move |prepared| {
            let record =
                create_managed_worktree(&prepared.store, &prepared.project, &task, &base_ref)?;
            let worktree_id = record.id.clone();
            let task = record.task.clone();
            Ok(
                match prepared
                    .store
                    .register_managed_worktree(&prepared.project.id, record, true)
                {
                    Ok((projects, bound)) => CreateWorktreeEffect::Ready(ActiveWorkspaceEffect {
                        status: format!("Active worktree `{task}`: {}", bound.folder().display()),
                        projects,
                        bound,
                        terminal_identity: Some(worktree_id.to_string()),
                    }),
                    Err(error) => CreateWorktreeEffect::Partial {
                        worktree_id: worktree_id.to_string(),
                        error: error.to_string(),
                    },
                },
            )
        },
        finish_create_worktree,
    )
    .await?;
    capture.project_switched(None);
    desktop.project_switched(None);
    tauri::async_runtime::spawn_blocking(move || browser.stop_for_project_change())
        .await
        .map_err(|error| format!("Browser worktree-change stop worker failed: {error}"))??;
    sync_workspace_watch(&app, &workspace_watch, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn activate_workspace(
    app: AppHandle,
    state: State<'_, AppState>,
    worktree_id: Option<String>,
) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let workspace_watch = state.workspace_watch.clone();
    let browser = state.browser.clone();
    let capture = state.capture.clone();
    let desktop = state.desktop.clone();
    let prepared = lock_backend(&state.backend)?.prepare_git_operation(
        crate::events::GitEventAction::WorkspaceActivated,
        crate::events::GitEventPhase::Requested,
        worktree_id.as_deref(),
    )?;
    let terminal_identity = worktree_id.clone();
    let ((), snapshot) = execute_prepared_project_operation(
        state,
        prepared,
        move |prepared| {
            let (projects, bound) = prepared
                .store
                .activate_project_workspace(&prepared.project.id, worktree_id.as_deref())
                .map_err(|error| error.to_string())?;
            let status = terminal_identity.as_ref().map_or_else(
                || format!("Active base project: {}", bound.folder().display()),
                |_| format!("Active managed worktree: {}", bound.folder().display()),
            );
            Ok(ActiveWorkspaceEffect {
                projects,
                bound,
                status,
                terminal_identity,
            })
        },
        |backend, prepared, effect| {
            finish_active_workspace(
                backend,
                prepared,
                effect,
                "The workspace was activated, but its Activity terminal event could not be persisted",
            )
        },
    )
    .await?;
    capture.project_switched(None);
    desktop.project_switched(None);
    tauri::async_runtime::spawn_blocking(move || browser.stop_for_project_change())
        .await
        .map_err(|error| format!("Browser workspace-change stop worker failed: {error}"))??;
    sync_workspace_watch(&app, &workspace_watch, &snapshot);
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn remove_worktree(
    app: AppHandle,
    state: State<'_, AppState>,
    worktree_id: String,
) -> Result<WorktreeRemoveResponse, String> {
    let workspace_watch = state.workspace_watch.clone();
    let browser = state.browser.clone();
    let capture = state.capture.clone();
    let desktop = state.desktop.clone();
    let prepared = lock_backend(&state.backend)?.prepare_git_operation(
        crate::events::GitEventAction::WorktreeRemoved,
        crate::events::GitEventPhase::Requested,
        Some(&worktree_id),
    )?;
    let project_id = prepared.context.project_id.clone();
    let pty = state.pty.clone();
    let removed_pty = PtySessionKey {
        project_id,
        workspace_id: WorkspaceId::new(format!("worktree-{worktree_id}")),
    };
    let (result, snapshot) = execute_prepared_project_operation(
        state,
        prepared,
        move |prepared| {
            let view = remove_managed_worktree(&prepared.store, &prepared.project, &worktree_id)?;
            if view.removed_id.as_deref() != Some(worktree_id.as_str()) {
                return Ok(RemoveWorktreeEffect::Ready(Box::new(RemoveWorktreeReady {
                    view,
                    active: None,
                })));
            }
            Ok(
                match prepared
                    .store
                    .forget_managed_worktree(&prepared.project.id, &worktree_id)
                {
                    Ok((projects, bound)) => {
                        let status = bound.as_ref().map_or_else(
                            || "Managed worktree removed.".to_owned(),
                            |bound| format!("Active workspace: {}", bound.folder().display()),
                        );
                        RemoveWorktreeEffect::Ready(Box::new(RemoveWorktreeReady {
                            view,
                            active: Some((projects, bound, status)),
                        }))
                    }
                    Err(error) => RemoveWorktreeEffect::StateUpdateFailed(error.to_string()),
                },
            )
        },
        finish_remove_worktree,
    )
    .await?;
    let response = WorktreeRemoveResponse { result, snapshot };
    if response.result.removed_id.is_some() {
        pty.stop_workspace(&removed_pty);
        capture.project_switched(None);
        desktop.project_switched(None);
        tauri::async_runtime::spawn_blocking(move || browser.stop_for_project_change())
            .await
            .map_err(|error| format!("Browser worktree-removal stop worker failed: {error}"))??;
    }
    sync_workspace_watch(&app, &workspace_watch, &response.snapshot);
    Ok(response)
}

#[tauri::command]
pub(crate) async fn commit_worktree(
    state: State<'_, AppState>,
    worktree_id: String,
    message: String,
) -> Result<WorktreeUserActionResponse, String> {
    let identity = worktree_id.clone();
    let (result, snapshot) = run_project_git_operation(
        state,
        crate::events::GitEventAction::WorktreeCommitted,
        crate::events::GitEventPhase::Requested,
        Some(identity),
        move |prepared| {
            commit_managed_worktree(&prepared.store, &prepared.project, &worktree_id, &message)
        },
        |_| crate::events::GitEventPhase::Completed,
    )
    .await?;
    Ok(WorktreeUserActionResponse { result, snapshot })
}

#[tauri::command]
pub(crate) async fn discard_worktree(
    state: State<'_, AppState>,
    worktree_id: String,
    confirmation: String,
) -> Result<WorktreeUserActionResponse, String> {
    let identity = worktree_id.clone();
    let (result, snapshot) = run_project_git_operation(
        state,
        crate::events::GitEventAction::WorktreeDiscarded,
        crate::events::GitEventPhase::Requested,
        Some(identity),
        move |prepared| {
            discard_managed_worktree(
                &prepared.store,
                &prepared.project,
                &worktree_id,
                &confirmation,
            )
        },
        |_| crate::events::GitEventPhase::Completed,
    )
    .await?;
    Ok(WorktreeUserActionResponse { result, snapshot })
}

#[tauri::command]
pub(crate) async fn choose_worktree_recovery_folder(
    app: AppHandle,
) -> Result<Option<String>, String> {
    choose_project_folder(app, true).await
}

#[tauri::command]
pub(crate) async fn export_worktree_recovery(
    state: State<'_, AppState>,
    worktree_id: String,
    destination: String,
) -> Result<WorktreeRecoveryExportResponse, String> {
    let identity = worktree_id.clone();
    let (result, snapshot) = run_project_git_operation(
        state,
        crate::events::GitEventAction::RecoveryExported,
        crate::events::GitEventPhase::Requested,
        Some(identity),
        move |prepared| {
            export_recovery(
                &prepared.store,
                &prepared.project,
                &worktree_id,
                std::path::Path::new(&destination),
            )
        },
        |_| crate::events::GitEventPhase::Completed,
    )
    .await?;
    Ok(WorktreeRecoveryExportResponse { result, snapshot })
}

#[tauri::command]
pub(crate) async fn remove_worktree_after_export(
    app: AppHandle,
    state: State<'_, AppState>,
    worktree_id: String,
    manifest_hash: String,
    confirmation: String,
) -> Result<WorktreeRemoveResponse, String> {
    let workspace_watch = state.workspace_watch.clone();
    let browser = state.browser.clone();
    let capture = state.capture.clone();
    let desktop = state.desktop.clone();
    let prepared = lock_backend(&state.backend)?.prepare_git_operation(
        crate::events::GitEventAction::WorktreeRemoved,
        crate::events::GitEventPhase::PostExportRequested,
        Some(&worktree_id),
    )?;
    let project_id = prepared.context.project_id.clone();
    let pty = state.pty.clone();
    let removed_pty = PtySessionKey {
        project_id,
        workspace_id: WorkspaceId::new(format!("worktree-{worktree_id}")),
    };
    let (result, snapshot) = execute_prepared_project_operation(
        state,
        prepared,
        move |prepared| {
            let view = remove_after_export(
                &prepared.store,
                &prepared.project,
                &worktree_id,
                &manifest_hash,
                &confirmation,
            )?;
            if view.removed_id.as_deref() != Some(worktree_id.as_str()) {
                return Ok(RemoveWorktreeEffect::Ready(Box::new(RemoveWorktreeReady {
                    view,
                    active: None,
                })));
            }
            Ok(
                match prepared
                    .store
                    .forget_managed_worktree(&prepared.project.id, &worktree_id)
                {
                    Ok((projects, bound)) => {
                        let status = bound.as_ref().map_or_else(
                            || "Managed worktree removed.".to_owned(),
                            |bound| format!("Active workspace: {}", bound.folder().display()),
                        );
                        RemoveWorktreeEffect::Ready(Box::new(RemoveWorktreeReady {
                            view,
                            active: Some((projects, bound, status)),
                        }))
                    }
                    Err(error) => RemoveWorktreeEffect::StateUpdateFailed(error.to_string()),
                },
            )
        },
        finish_remove_worktree,
    )
    .await?;
    let response = WorktreeRemoveResponse { result, snapshot };
    if response.result.removed_id.is_some() {
        pty.stop_workspace(&removed_pty);
        capture.project_switched(None);
        desktop.project_switched(None);
        tauri::async_runtime::spawn_blocking(move || browser.stop_for_project_change())
            .await
            .map_err(|error| format!("Browser worktree-removal stop worker failed: {error}"))??;
    }
    sync_workspace_watch(&app, &workspace_watch, &response.snapshot);
    Ok(response)
}

#[cfg(target_os = "macos")]
fn choose_project_folder_on_main_thread(allow_create: bool) -> Result<Option<String>, String> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSModalResponseOK, NSOpenPanel};

    let marker = MainThreadMarker::new()
        .ok_or_else(|| "The macOS folder picker must run on the main thread.".to_owned())?;
    let panel = NSOpenPanel::openPanel(marker);
    panel.setCanChooseFiles(false);
    panel.setCanChooseDirectories(true);
    panel.setAllowsMultipleSelection(false);
    panel.setCanCreateDirectories(allow_create);
    panel.setResolvesAliases(true);

    if panel.runModal() != NSModalResponseOK {
        return Ok(None);
    }

    let url = panel
        .URL()
        .ok_or_else(|| "macOS did not return the selected project folder.".to_owned())?;
    let path = url
        .path()
        .ok_or_else(|| "The selected macOS location is not a local folder.".to_owned())?
        .to_string();
    if path.trim().is_empty() {
        return Err("macOS returned an empty project-folder path.".to_owned());
    }
    Ok(Some(path))
}

/// Opens the native macOS directory chooser without delegating filesystem
/// authority to the webview. `allow_create` controls the panel's New Folder
/// affordance; the selected path still passes through the existing workspace
/// grant validation when the frontend invokes `bind_project`.
#[tauri::command]
pub(crate) async fn choose_project_folder(
    app: AppHandle,
    allow_create: bool,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        app.run_on_main_thread(move || {
            let _ = sender.send(choose_project_folder_on_main_thread(allow_create));
        })
        .map_err(|error| format!("cannot open the macOS folder picker: {error}"))?;

        tauri::async_runtime::spawn_blocking(move || {
            receiver
                .recv()
                .map_err(|_| "The macOS folder picker stopped without a result.".to_owned())?
        })
        .await
        .map_err(|error| format!("folder-picker worker stopped before completing: {error}"))?
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (app, allow_create);
        Err("The native project-folder picker is available only on macOS.".to_owned())
    }
}
