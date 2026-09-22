//! Agent IPC resolves project/workspace and run authority in Rust.
use super::{AppState, Arc, State, lock_backend};
use crate::collaboration::AgentSettings;
use crate::contracts::{ProjectId, RunId};

#[tauri::command]
pub(crate) async fn agent_settings(
    state: State<'_, AppState>,
    project_id: String,
) -> Result<AgentSettings, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let backend = lock_backend(&shared)?;
        let (_, context) = backend.extension_operation(&project_id)?;
        AgentSettings::load(backend.store.state_root(), &context.project_id)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn set_agents_enabled(
    state: State<'_, AppState>,
    project_id: String,
    enabled: bool,
) -> Result<AgentSettings, String> {
    let shared = Arc::clone(&state.backend);
    let queue = state.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _scheduler = queue.lock_idle_scheduler()?;
        let backend = lock_backend(&shared)?;
        let (_, context) = backend.extension_operation(&project_id)?;
        AgentSettings::set(backend.store.state_root(), &context.project_id, enabled)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn child_agent_result(
    state: State<'_, AppState>,
    project_id: String,
    parent_run_id: String,
    child_run_id: String,
) -> Result<serde_json::Value, String> {
    let shared = Arc::clone(&state.backend);
    let agents = state.agents.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let backend = lock_backend(&shared)?;
        let (project, parent, child) =
            resolve_child(&backend, &project_id, &parent_run_id, &child_run_id)?;
        agents.result(&project, &parent, &child)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn stop_child_agent(
    state: State<'_, AppState>,
    project_id: String,
    parent_run_id: String,
    child_run_id: String,
) -> Result<(), String> {
    let shared = Arc::clone(&state.backend);
    let agents = state.agents.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let backend = lock_backend(&shared)?;
        let (project, parent, child) =
            resolve_child(&backend, &project_id, &parent_run_id, &child_run_id)?;
        agents.stop(&project, &parent, &child)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn decide_child_changes(
    state: State<'_, AppState>,
    project_id: String,
    parent_run_id: String,
    child_run_id: String,
    accept: bool,
) -> Result<(), String> {
    let shared = Arc::clone(&state.backend);
    let agents = state.agents.clone();
    let queue = state.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _scheduler = queue.lock_idle_scheduler()?;
        let backend = lock_backend(&shared)?;
        let (project, parent, child) = resolve_child(&backend, &project_id, &parent_run_id, &child_run_id)?;
        let (_, context) = backend.extension_operation(&project_id)?;
        let bound = grok_build_plus_host::bind_project_folder(&context.active_root).map_err(|e| e.to_string())?;
        let mut conflicts = std::collections::BTreeSet::new();
        if accept {
            let sessions = backend.store.load_session_book().map_err(|e| e.to_string())?;
            for session in sessions.sessions.iter().filter(|session| crate::backend::session_belongs_to_project(&session.id, project.as_str())) {
                conflicts.extend(session.pending.items.iter().map(|proposal| proposal.relative_path.clone()));
            }
            for other in queue.view().children.iter().filter(|other| other.project == project && other.id != child && other.review_pending) {
                let value = agents.result(&project, &other.parent, &other.id)?;
                let Some(pending) = value.pointer("/payload/pending") else { return Err("Another child has unavailable review context. Resolve that review before accepting overlapping work.".into()); };
                let pending: grok_build_plus_host::PendingFileSet = serde_json::from_value(pending.clone()).map_err(|_| "Child proposal inventory is unreadable.")?;
                conflicts.extend(pending.items.into_iter().map(|proposal| proposal.relative_path));
            }
        }
        agents.decide(&project, &parent, &child, accept, &bound, &conflicts)?;
        queue.child_review_result(&parent, &child, false)?;
        backend.finish_project_review_resolution(&project)
    }).await.map_err(|e| e.to_string())?
}

fn resolve_child(
    backend: &crate::backend::Backend,
    project_id: &str,
    parent_id: &str,
    child_id: &str,
) -> Result<(ProjectId, RunId, RunId), String> {
    let (_, context) = backend.extension_operation(project_id)?;
    let view = backend.queue.view();
    if !view.available {
        return Err(view.status);
    }
    let run = view
        .runs
        .iter()
        .find(|run| run.id == parent_id && run.project_id == project_id)
        .ok_or("Child parent is not a retained run in this project.")?;
    if !view.items.iter().any(|item| {
        item.id == run.queue_item_id && item.workspace_id == context.workspace_id.as_str()
    }) {
        return Err(
            "Select the child's original project workspace before accessing its activity.".into(),
        );
    }
    let parent = RunId::new(parent_id);
    let child = backend
        .queue
        .child_records(&parent)?
        .into_iter()
        .find(|child| child.id.as_str() == child_id && child.project == context.project_id)
        .ok_or("Child run does not belong to this project and family.")?;
    Ok((context.project_id, parent, child.id))
}
