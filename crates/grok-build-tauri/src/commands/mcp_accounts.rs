//! Account selection resolves immutable server/project authority in Rust.
use super::{AppState, Arc, State, lock_backend};
use crate::backend::{OperationContext, SharedBackend};
use crate::extensions::mcp::{
    ServerSpec,
    accounts::{ReviewView, SignInChoice, Status},
};

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ServerSelection {
    project_id: String,
    content_digest: String,
    component_id: String,
    server_name: String,
}
fn resolve(
    backend: &SharedBackend,
    selection: &ServerSelection,
) -> Result<(ServerSpec, OperationContext), String> {
    let (store, context) = lock_backend(backend)?.extension_operation(&selection.project_id)?;
    let spec = store
        .mcp_servers(
            &context.project_id,
            &selection.content_digest,
            &selection.component_id,
        )?
        .into_iter()
        .find(|(v, _)| v.name == selection.server_name)
        .and_then(|(_, spec)| spec)
        .ok_or("The selected frozen MCP server is unavailable.")?;
    lock_backend(backend)?.revalidate_operation(&context)?;
    Ok((spec, context))
}
#[tauri::command]
pub(crate) async fn mcp_account_status(
    state: State<'_, AppState>,
    selection: ServerSelection,
) -> Result<Status, String> {
    let backend = Arc::clone(&state.backend);
    let accounts = state.mcp.accounts.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (spec, context) = resolve(&backend, &selection)?;
        let view = accounts.status(&spec)?;
        lock_backend(&backend)?.revalidate_operation(&context)?;
        Ok(view)
    })
    .await
    .map_err(|_| "MCP account status worker failed.")?
}
#[tauri::command]
pub(crate) async fn review_mcp_account(
    state: State<'_, AppState>,
    selection: ServerSelection,
) -> Result<ReviewView, String> {
    let backend = Arc::clone(&state.backend);
    let (spec, context) =
        tauri::async_runtime::spawn_blocking(move || resolve(&backend, &selection))
            .await
            .map_err(|_| "MCP account review worker failed.")??;
    let view = state.mcp.accounts.review(spec).await?;
    lock_backend(&state.backend)?.revalidate_operation(&context)?;
    Ok(view)
}
#[tauri::command]
pub(crate) async fn begin_mcp_account_signin(
    state: State<'_, AppState>,
    selection: ServerSelection,
    choice: SignInChoice,
) -> Result<(), String> {
    let backend = Arc::clone(&state.backend);
    let accounts = state.mcp.accounts.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (spec, context) = resolve(&backend, &selection)?;
        accounts.begin(
            &spec,
            choice,
            Arc::new(move || lock_backend(&backend)?.revalidate_operation(&context)),
        )
    })
    .await
    .map_err(|_| "MCP sign-in worker failed.")?
}
#[tauri::command]
pub(crate) async fn disconnect_mcp_account(
    state: State<'_, AppState>,
    selection: ServerSelection,
) -> Result<(), String> {
    let backend = Arc::clone(&state.backend);
    let accounts = state.mcp.accounts.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (spec, _) = resolve(&backend, &selection)?;
        accounts.disconnect(&spec)
    })
    .await
    .map_err(|_| "MCP sign-out worker failed.")?
}
#[tauri::command]
pub(crate) async fn cleanup_mcp_accounts(
    state: State<'_, AppState>,
    project_id: String,
) -> Result<(), String> {
    let backend = Arc::clone(&state.backend);
    let accounts = state.mcp.accounts.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (_, context) = lock_backend(&backend)?.extension_operation(&project_id)?;
        accounts.cleanup(context.project_id.as_str())
    })
    .await
    .map_err(|_| "MCP account cleanup worker failed.")?
}
#[tauri::command]
pub(crate) async fn cancel_mcp_account_signin(
    state: State<'_, AppState>,
    project_id: String,
) -> Result<(), String> {
    state.mcp.accounts.cancel(&project_id)
}
#[tauri::command]
pub(crate) async fn close_mcp_account_review(
    state: State<'_, AppState>,
    project_id: String,
    review_id: String,
) -> Result<(), String> {
    state.mcp.accounts.close_review(&project_id, &review_id)
}
