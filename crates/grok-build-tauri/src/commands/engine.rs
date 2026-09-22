//! Typed engine preference command.

use super::{AppSnapshot, AppState, Arc, State, lock_backend};
use crate::runtime::engine::EngineSettings;

#[tauri::command]
pub(crate) async fn set_engine_settings(
    state: State<'_, AppState>,
    settings: EngineSettings,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let queue = lock_backend(&shared)?.queue.clone();
    let seed = tauri::async_runtime::spawn_blocking(move || {
        let _scheduler = queue.lock_scheduler()?;
        lock_backend(&shared)?.set_engine(settings)
    })
    .await
    .map_err(|error| format!("Engine settings worker failed: {error}"))??;
    super::present_snapshot(seed).await
}
