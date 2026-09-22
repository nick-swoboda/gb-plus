//! Contained command and direct interactive PTY commands.

use super::{
    AppHandle, AppSnapshot, AppState, Arc, Emitter, EventContext, EventJournal, EventPayload,
    PTY_EVENT_CHANNEL, PtyEventAction, PtyEventSink, PtyState, PtyUiEvent, PtyView, State,
    emit_activity_event, lock_backend, present_snapshot,
};
use grok_build_plus_host::{observe_plus_guest, plus_terminal_command_with_security_typed};

#[tauri::command]
pub(crate) async fn run_terminal(
    state: State<'_, AppState>,
    command_line: String,
) -> Result<AppSnapshot, String> {
    if command_line.trim().is_empty() {
        return Err("Enter a project command before running.".into());
    }
    let shared = Arc::clone(&state.backend);
    let observation = tauri::async_runtime::spawn_blocking(observe_plus_guest)
        .await
        .map_err(|error| format!("Container validation worker stopped: {error}"))?;
    let prepared = lock_backend(&shared)?.prepare_security_effect(
        observation,
        crate::events::SecurityEventSurface::TerminalArgv,
        "running a project command",
    )?;
    let gate = state.operations.gate(&prepared.context.project_id)?;
    let worker_shared = Arc::clone(&shared);
    let (prepared, outcome) = tauri::async_runtime::spawn_blocking(move || {
        let _permit = gate
            .lock()
            .map_err(|_| "Project operation permit is unavailable.".to_owned())?;
        lock_backend(&worker_shared)?.revalidate_operation(&prepared.context)?;
        let outcome = plus_terminal_command_with_security_typed(
            &prepared.bound,
            prepared.preference,
            false,
            &prepared.observation.lifecycle,
            command_line.trim(),
        );
        Ok::<_, String>((prepared, outcome))
    })
    .await
    .map_err(|error| format!("Contained-command worker stopped: {error}"))??;
    let seed = lock_backend(&shared)?.finish_security_effect(prepared, outcome, "command")?;
    present_snapshot(seed).await
}

#[tauri::command]
pub(crate) async fn pty_status(state: State<'_, AppState>) -> Result<PtyView, String> {
    let target = lock_backend(&state.backend)?.active_pty_target()?;
    state.pty.status(&target)
}

#[tauri::command]
pub(crate) async fn pty_start(
    app: AppHandle,
    state: State<'_, AppState>,
    rows: u16,
    cols: u16,
) -> Result<PtyView, String> {
    let (target, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_pty_target()?,
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    let workspace_id = target.key.workspace_id.clone();
    let sink = pty_event_sink(app, journal, context, workspace_id);
    let pty = state.pty.clone();
    tauri::async_runtime::spawn_blocking(move || pty.start(target, rows, cols, sink))
        .await
        .map_err(|error| format!("PTY worker stopped before completing: {error}"))?
}

#[tauri::command]
pub(crate) async fn pty_write(state: State<'_, AppState>, data: Vec<u8>) -> Result<(), String> {
    let target = lock_backend(&state.backend)?.active_pty_target()?;
    let pty = state.pty.clone();
    tauri::async_runtime::spawn_blocking(move || pty.write(&target, &data))
        .await
        .map_err(|error| format!("PTY input worker stopped before completing: {error}"))?
}

#[tauri::command]
pub(crate) async fn pty_resize(
    state: State<'_, AppState>,
    rows: u16,
    cols: u16,
) -> Result<PtyView, String> {
    let target = lock_backend(&state.backend)?.active_pty_target()?;
    let pty = state.pty.clone();
    tauri::async_runtime::spawn_blocking(move || pty.resize(&target, rows, cols))
        .await
        .map_err(|error| format!("PTY resize worker stopped before completing: {error}"))?
}

#[tauri::command]
pub(crate) async fn pty_interrupt(state: State<'_, AppState>) -> Result<(), String> {
    let target = lock_backend(&state.backend)?.active_pty_target()?;
    let pty = state.pty.clone();
    tauri::async_runtime::spawn_blocking(move || pty.interrupt(&target))
        .await
        .map_err(|error| format!("PTY interrupt worker stopped before completing: {error}"))?
}

#[tauri::command]
pub(crate) async fn pty_stop(state: State<'_, AppState>) -> Result<PtyView, String> {
    let target = lock_backend(&state.backend)?.active_pty_target()?;
    let pty = state.pty.clone();
    tauri::async_runtime::spawn_blocking(move || pty.stop(&target))
        .await
        .map_err(|error| format!("PTY stop worker stopped before completing: {error}"))?
}
fn pty_event_sink(
    app: AppHandle,
    journal: EventJournal,
    context: EventContext,
    workspace_id: crate::contracts::WorkspaceId,
) -> PtyEventSink {
    Arc::new(move |event: PtyUiEvent| {
        if let Some(state) = event.state() {
            let action = match state {
                PtyState::Starting => PtyEventAction::Starting,
                PtyState::Live => PtyEventAction::Live,
                PtyState::Stopping => PtyEventAction::StopRequested,
                PtyState::Exited => PtyEventAction::Exited,
                PtyState::Failed => PtyEventAction::Failed,
                PtyState::NotStarted => return Err("A non-event PTY state was emitted.".into()),
            };
            let activity = journal.record(
                context.clone(),
                EventPayload::Pty {
                    action,
                    workspace_id: workspace_id.clone(),
                },
            )?;
            emit_activity_event(&app, &activity);
        }
        let _ = app.emit(PTY_EVENT_CHANNEL, event);
        Ok(())
    })
}
