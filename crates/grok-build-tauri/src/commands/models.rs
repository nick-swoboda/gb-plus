//! Authenticated catalog and explicit per-session model selection IPC.

use super::{AppState, Arc, State, lock_backend};
use crate::runtime::models::{ModelCatalog, ModelSelection};

#[tauri::command]
pub(crate) async fn list_session_models(
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
) -> Result<ModelCatalog, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let (runtime, binding) =
            lock_backend(&shared)?.prepare_model_operation(&project_id, &session_id)?;
        runtime.authenticated_model_catalog(binding.root())
    })
    .await
    .map_err(|error| format!("Model catalog worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn select_session_model(
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
    model_id: String,
    reasoning_effort: Option<String>,
) -> Result<ModelSelection, String> {
    let shared = Arc::clone(&state.backend);
    let queue = lock_backend(&shared)?.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        // A model probe is an execution. Maintenance owns scheduler admission
        // until the probe connection is closed and the exact selection committed.
        let _scheduler = queue.lock_idle_scheduler()?;
        let (runtime, binding) =
            lock_backend(&shared)?.prepare_model_operation(&project_id, &session_id)?;
        let selection =
            runtime.verify_model_selection(binding.root(), &model_id, reasoning_effort)?;
        lock_backend(&shared)?.commit_model_selection(&project_id, &session_id, &selection)?;
        Ok(selection)
    })
    .await
    .map_err(|error| format!("Model selection worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn get_session_native_protocol(
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
) -> Result<crate::runtime::native_protocol::NativeProtocol, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        lock_backend(&shared)?.native_protocol(&project_id, &session_id)
    })
    .await
    .map_err(|error| format!("Connection preference worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn set_session_native_protocol(
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
    protocol: crate::runtime::native_protocol::NativeProtocol,
) -> Result<crate::runtime::native_protocol::NativeProtocol, String> {
    let shared = Arc::clone(&state.backend);
    let queue = lock_backend(&shared)?.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _scheduler = queue.lock_idle_scheduler()?;
        let (runtime, binding) =
            lock_backend(&shared)?.prepare_model_operation(&project_id, &session_id)?;
        let verified = runtime.verify_native_protocol(binding.root(), protocol)?;
        lock_backend(&shared)?.commit_native_protocol(
            &project_id,
            &session_id,
            protocol,
            &verified,
        )?;
        Ok(protocol)
    })
    .await
    .map_err(|error| format!("Connection verification worker failed: {error}"))?
}
