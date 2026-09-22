//! Native Chat controls keep authority in the run-owned Rust dispatcher.

use super::{AppState, ProjectId, RunId, State, lock_backend};
use crate::runtime::cli_interactions::{CliAnswer, CliInteraction};

fn queue(state: &AppState, project_id: &str) -> Result<crate::queue::QueueCoordinator, String> {
    let backend = lock_backend(&state.backend)?;
    if backend.active_project_typed_id()?.as_str() != project_id || !backend.standard_engine() {
        return Err("Native CLI control belongs to the selected standard-mode project.".into());
    }
    Ok(backend.queue.clone())
}

#[tauri::command]
pub(crate) async fn pending_cli_interactions(
    state: State<'_, AppState>,
    project_id: String,
    run_id: String,
) -> Result<Vec<CliInteraction>, String> {
    lock_backend(&state.backend)?.validate_cli_chat_run(&project_id, &run_id)?;
    queue(state.inner(), &project_id)?
        .pending_cli_interactions(&ProjectId::new(project_id), &RunId::new(run_id))
}

#[tauri::command]
pub(crate) async fn answer_cli_interaction(
    state: State<'_, AppState>,
    project_id: String,
    run_id: String,
    interaction_id: u64,
    answer: CliAnswer,
) -> Result<(), String> {
    let queue = queue(state.inner(), &project_id)?;
    if queue
        .view()
        .runs
        .iter()
        .any(|entry| entry.id == run_id && entry.state == crate::queue::RunState::Running)
    {
        lock_backend(&state.backend)?.validate_cli_chat_run(&project_id, &run_id)?;
        return queue.answer_cli_interaction(
            &ProjectId::new(project_id),
            &RunId::new(run_id),
            interaction_id,
            answer,
        );
    }
    let (pool, key) = lock_backend(&state.backend)?.cli_activity_scope(&project_id)?;
    pool.answer_idle(&key, &run_id, interaction_id, answer)
}

#[tauri::command]
pub(crate) async fn cli_background_activity(
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
    after: u64,
    run_id: Option<String>,
) -> Result<Option<crate::runtime::acp::standard::IdleSnapshot>, String> {
    let backend = lock_backend(&state.backend)?;
    backend.cli_permission(&project_id, &session_id)?;
    let (pool, key) = backend.cli_activity_scope(&project_id)?;
    pool.idle_snapshot(&key, after, run_id.as_deref())
}

#[tauri::command]
pub(crate) async fn stop_cli_background(
    state: State<'_, AppState>,
    project_id: String,
    run_id: String,
) -> Result<(), String> {
    let (pool, key) = lock_backend(&state.backend)?.cli_activity_scope(&project_id)?;
    tauri::async_runtime::spawn_blocking(move || pool.stop_idle(&key, &run_id))
        .await
        .map_err(|e| format!("CLI Stop worker failed: {e}"))?
}

#[tauri::command]
pub(crate) async fn render_chat_markdown(
    text: String,
) -> Result<crate::markdown::Document, String> {
    tauri::async_runtime::spawn_blocking(move || crate::markdown::render(&text))
        .await
        .map_err(|error| format!("Markdown worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn get_cli_permission(
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
) -> Result<crate::runtime::cli_permissions::CliPermissionChoice, String> {
    lock_backend(&state.backend)?.cli_permission(&project_id, &session_id)
}

#[tauri::command]
pub(crate) async fn set_cli_permission(
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
    mode: crate::runtime::cli_permissions::CliPermissionMode,
) -> Result<crate::runtime::cli_permissions::CliPermissionChoice, String> {
    let shared = std::sync::Arc::clone(&state.backend);
    let queue = lock_backend(&shared)?.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _scheduler = queue.lock_idle_scheduler()?;
        lock_backend(&shared)?.set_cli_permission(&project_id, &session_id, mode)
    })
    .await
    .map_err(|error| format!("CLI permission worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn open_chat_link(url: String) -> Result<(), String> {
    if url.len() > 8192 || url.chars().any(char::is_control) {
        return Err("The link is invalid.".into());
    }
    let parsed = url::Url::parse(&url).map_err(|_| "The link is invalid.")?;
    if !matches!(parsed.scheme(), "https" | "http" | "mailto") || parsed.password().is_some() {
        return Err("This link type cannot be opened from Chat.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let mut command = std::process::Command::new("/usr/bin/open");
        command.env_clear().args(["--", parsed.as_str()]);
        let result = crate::bounded_process::collect(
            command,
            &[],
            &crate::bounded_process::Limits {
                input: 0,
                output: 4096,
                error: 4096,
                timeout: std::time::Duration::from_secs(10),
            },
        )?;
        if !result.status.success() {
            return Err("The system did not open the selected link.".into());
        }
        Ok(())
    })
    .await
    .map_err(|error| format!("Link worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn stage_cli_image(
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
    bytes: Vec<u8>,
) -> Result<String, String> {
    let shared = std::sync::Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        lock_backend(&shared)?.stage_cli_image(&project_id, &session_id, bytes)
    })
    .await
    .map_err(|error| format!("Image worker failed: {error}"))?
}
#[tauri::command]
pub(crate) async fn discard_cli_image(
    state: State<'_, AppState>,
    marker: String,
) -> Result<(), String> {
    lock_backend(&state.backend)?.discard_cli_image(&marker)
}
