//! User-invoked catalog review, with project authority resolved by the backend.

use super::{AppState, Arc, State, lock_backend};
use crate::contracts::ProjectId;
use crate::extensions::mcp::{ReviewView, ServerView};
use grok_build_plus_host::McpToolPolicy;

#[tauri::command]
pub(crate) async fn list_mcp_call_approvals(
    state: State<'_, AppState>,
    project_id: String,
) -> Result<Vec<crate::extensions::mcp::approvals::ApprovalView>, String> {
    let backend = lock_backend(&state.backend)?;
    let (_, context) = backend.extension_operation(&project_id)?;
    state.mcp.approvals.list(&context.project_id)
}

#[tauri::command]
pub(crate) async fn answer_mcp_call_approval(
    state: State<'_, AppState>,
    project_id: String,
    approval_id: String,
    commitment: String,
    allow: bool,
) -> Result<(), String> {
    let backend = lock_backend(&state.backend)?;
    let (_, context) = backend.extension_operation(&project_id)?;
    state
        .mcp
        .approvals
        .answer(&context.project_id, &approval_id, &commitment, allow)
}

#[tauri::command]
pub(crate) async fn list_extension_mcp_servers(
    state: State<'_, AppState>,
    project_id: String,
    content_digest: String,
    component_id: String,
) -> Result<Vec<ServerView>, String> {
    let backend = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let (store, context) = lock_backend(&backend)?.extension_operation(&project_id)?;
        let entries = store.mcp_servers(&context.project_id, &content_digest, &component_id)?;
        lock_backend(&backend)?.revalidate_operation(&context)?;
        Ok(entries.into_iter().map(|(view, _)| view).collect())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn inspect_extension_mcp_catalog(
    state: State<'_, AppState>,
    project_id: String,
    content_digest: String,
    component_id: String,
    server_name: String,
) -> Result<ReviewView, String> {
    let backend = Arc::clone(&state.backend);
    let (spec, context, service_context) = tauri::async_runtime::spawn_blocking(move || {
        let (store, context) = lock_backend(&backend)?.extension_operation(&project_id)?;
        let spec = store
            .mcp_servers(&context.project_id, &content_digest, &component_id)?
            .into_iter()
            .find(|(view, _)| view.name == server_name)
            .and_then(|(_, spec)| spec)
            .ok_or("This frozen MCP server is unavailable for inspection.")?;
        let service_context = lock_backend(&backend)?.extension_service_context(&context)?;
        Ok::<_, String>((spec, context, service_context))
    })
    .await
    .map_err(|e| e.to_string())??;
    let review = state.mcp_reviews.inspect(spec, service_context).await?;
    if let Err(error) = lock_backend(&state.backend)?.revalidate_operation(&context) {
        state
            .mcp_reviews
            .close(&context.project_id, &review.review_id)?;
        return Err(error);
    }
    Ok(review)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct McpPolicyChoice {
    review_id: String,
    revision: u64,
    app_name: String,
    fingerprint: String,
    policy: McpToolPolicy,
}

#[tauri::command]
pub(crate) async fn set_extension_mcp_policy(
    state: State<'_, AppState>,
    project_id: String,
    choice: McpPolicyChoice,
) -> Result<ReviewView, String> {
    let backend = Arc::clone(&state.backend);
    let reviews = state.mcp_reviews.clone();
    tauri::async_runtime::spawn_blocking(move || {
        // Keep project selection stable through the owner-only atomic commit.
        let backend = lock_backend(&backend)?;
        let (_, context) = backend.extension_operation(&project_id)?;
        reviews.change_policy(
            &context.project_id,
            &choice.review_id,
            choice.revision,
            &choice.app_name,
            &choice.fingerprint,
            choice.policy,
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Keep managed state and owned identifiers at the Tauri command boundary."
)]
pub(crate) fn close_extension_mcp_review(
    state: State<'_, AppState>,
    project_id: String,
    review_id: String,
) -> Result<(), String> {
    // Attenuation only: close the exact opaque review even after a project switch.
    state
        .mcp_reviews
        .close(&ProjectId::new(project_id), &review_id)
}
