//! Explicit, project-bound extension preview, installation and enablement.
use super::{AppState, Arc, State, lock_backend};
use crate::extensions::{ExtensionPreview, ExtensionView};

#[tauri::command]
pub(crate) async fn project_memory_view(
    state: State<'_, AppState>,
    project_id: String,
) -> Result<crate::project_memory::MemoryView, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        lock_backend(&shared)?.project_memory(&project_id)?.view()
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn set_project_memory(
    state: State<'_, AppState>,
    project_id: String,
    enabled: bool,
) -> Result<crate::project_memory::MemoryView, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        lock_backend(&shared)?
            .project_memory(&project_id)?
            .set_enabled(enabled)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn remember_project_fact(
    state: State<'_, AppState>,
    project_id: String,
    text: String,
) -> Result<crate::project_memory::MemoryView, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        lock_backend(&shared)?
            .project_memory(&project_id)?
            .remember_user_fact(&text)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn forget_project_fact(
    state: State<'_, AppState>,
    project_id: String,
    fact_id: Option<String>,
) -> Result<crate::project_memory::MemoryView, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        lock_backend(&shared)?
            .project_memory(&project_id)?
            .forget(fact_id.as_deref())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn preview_https_extension(
    state: State<'_, AppState>,
    project_id: String,
    url: String,
    byte_len: u64,
    sha256: String,
) -> Result<ExtensionPreview, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let (store, context) = lock_backend(&shared)?.extension_operation(&project_id)?;
        let preview = store.preview_https(&url, byte_len, &sha256)?;
        lock_backend(&shared)?.revalidate_operation(&context)?;
        Ok(preview)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn list_project_extensions(
    state: State<'_, AppState>,
    project_id: String,
) -> Result<ExtensionView, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let (store, context) = lock_backend(&shared)?.extension_operation(&project_id)?;
        store.view(&context.project_id)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn preview_local_extension(
    state: State<'_, AppState>,
    project_id: String,
    path: String,
) -> Result<ExtensionPreview, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let (store, context) = lock_backend(&shared)?.extension_operation(&project_id)?;
        let preview = store.preview_local(std::path::Path::new(&path))?;
        lock_backend(&shared)?.revalidate_operation(&context)?;
        Ok(preview)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn install_extension(
    state: State<'_, AppState>,
    project_id: String,
    content_digest: String,
) -> Result<ExtensionView, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let (store, context) = lock_backend(&shared)?.extension_operation(&project_id)?;
        store.install(&content_digest)?;
        lock_backend(&shared)?.revalidate_operation(&context)?;
        store.view(&context.project_id)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn set_extension_component(
    state: State<'_, AppState>,
    project_id: String,
    content_digest: String,
    component_id: String,
    enabled: bool,
) -> Result<ExtensionView, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let backend = lock_backend(&shared)?;
        let (store, context) = backend.extension_operation(&project_id)?;
        // The project cannot change between resolution and the atomic setting.
        store.set_enabled(&context.project_id, &content_digest, &component_id, enabled)?;
        store.view(&context.project_id)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn inspect_extension_file(
    state: State<'_, AppState>,
    project_id: String,
    content_digest: String,
    path: String,
) -> Result<String, String> {
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let (store, _) = lock_backend(&shared)?.extension_operation(&project_id)?;
        store.preview_file(&content_digest, &path)
    })
    .await
    .map_err(|e| e.to_string())?
}
