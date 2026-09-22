//! Only the user-facing app can answer or navigate an exact pending interaction.

use super::{AppState, Arc, State, lock_backend};

#[tauri::command]
pub(crate) async fn list_mcp_elicitations(
    state: State<'_, AppState>,
    project_id: String,
) -> Result<Vec<crate::extensions::mcp::elicitation::View>, String> {
    let backend = lock_backend(&state.backend)?;
    let (_, context) = backend.extension_operation(&project_id)?;
    state.mcp.elicitations.list(&context.project_id)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ElicitationAnswer {
    id: String,
    commitment: String,
    action: String,
    content: Option<serde_json::Value>,
}

#[tauri::command]
pub(crate) async fn answer_mcp_elicitation(
    state: State<'_, AppState>,
    project_id: String,
    answer: ElicitationAnswer,
) -> Result<(), String> {
    let backend = lock_backend(&state.backend)?;
    let (_, context) = backend.extension_operation(&project_id)?;
    state.mcp.elicitations.answer(
        &context.project_id,
        &answer.id,
        &answer.commitment,
        &answer.action,
        answer.content,
    )
}

#[tauri::command]
pub(crate) async fn open_mcp_elicitation_link(
    state: State<'_, AppState>,
    project_id: String,
    id: String,
    commitment: String,
) -> Result<(), String> {
    let backend = Arc::clone(&state.backend);
    let elicitations = state.mcp.elicitations.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (url, context) = {
            let backend = lock_backend(&backend)?;
            let (_, context) = backend.extension_operation(&project_id)?;
            let url = elicitations.url(&context.project_id, &id, &commitment)?;
            (url, context)
        };
        // No provider or frontend URL is accepted here. The exact pending
        // HTTPS link was validated and is opened only by this explicit UI action.
        let mut command = std::process::Command::new("/usr/bin/open");
        command.env_clear().args(["--", &url]);
        let output = crate::bounded_process::collect(
            command,
            &[],
            &crate::bounded_process::Limits {
                input: 0,
                output: 4096,
                error: 4096,
                timeout: std::time::Duration::from_secs(10),
            },
        )?;
        if !output.status.success() {
            return Err("The system browser did not acknowledge the reviewed link.".into());
        }
        lock_backend(&backend)?.revalidate_operation(&context)?;
        elicitations.opened(&context.project_id, &id, &commitment)
    })
    .await
    .map_err(|e| e.to_string())?
}
