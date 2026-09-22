//! Typed Tauri IPC commands and the native folder-picker boundary.

use std::sync::{Arc, MutexGuard};

use grok_build_plus_host::{
    BoundProject, PLUS_PRODUCT_VERSION, PlusProjectBook, bind_and_remember_project_folder,
    bind_project_folder,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::backend::{
    AppSnapshot, AppState, Backend, PrepareQueuedRunError, PrepareQueuedRunErrorKind,
    PreparedGitOperation, PreparedQueuedRun, ProjectTransitionContext, SharedBackend, SnapshotSeed,
    WorkspaceSessionEffect, project_operation_drift,
};
use crate::browser::{BrowserActionView, BrowserMode, BrowserPhase, BrowserView};
use crate::browser_assets::BrowserAssetProgress;
use crate::capture::{CapturePermission, CapturePhase, CaptureView};
use crate::contracts::{AppEvent, ProjectId, QueueItemId, RunId, SessionId, WorkspaceId};
use crate::desktop::{DesktopPermission, DesktopPhase, DesktopView};
use crate::diagnostics::{
    DiagnosticExportView, default_diagnostic_filename, export_diagnostic_zip,
};
use crate::events::{
    BrowserEventAction, CaptureEventAction, DesktopEventAction, DiagnosticEventAction,
    EventContext, EventErrorCode, EventJournal, EventPayload, ProposalEventAction, PtyEventAction,
    QueueEventAction, QueueMode, RunEventAction, SteeringEventAction, ToolEventAction,
    VoiceEventAction,
};
use crate::git_review::{
    GitHunkActionView, GitReviewView, discard_git_hunk as discard_hunk,
    list_git_review as read_git_review, stage_git_hunk as stage_hunk,
    unstage_git_hunk as unstage_hunk,
};
use crate::pty::{PtyEventSink, PtySessionKey, PtyState, PtyUiEvent, PtyView};
use crate::queue::{BegunRun, QueueCoordinator, QueueRemovalOutcome, RunCompletion};
use crate::read_aloud::{ReadAloudAudio, ReadAloudView};
use crate::runtime::acp::{GrokCliOAuthPhase, run_grok_cli_oauth};
use crate::runtime::native_secret::prompt_xai_key;
use crate::runtime::types::{
    AdapterContext, AdapterTurn, AdapterTurnOutcome, RuntimeEvent, RuntimeTransport,
};
use crate::voice::{VoiceModel, VoicePhase, VoiceProgress, VoiceTranscript, VoiceView};
use crate::workspace::{
    WorkspaceDirectoryView, WorkspaceFileView,
    list_workspace_directory as read_workspace_directory,
    open_workspace_file as read_workspace_file,
};
use crate::workspace_watch::WorkspaceWatch;
use crate::worktrees::{
    GitSetupView, WorktreeListView, WorktreeRecoveryExportView, WorktreeRemoveView,
    WorktreeUserActionView, commit_managed_worktree, create_managed_worktree,
    discard_managed_worktree, export_worktree_recovery as export_recovery, initialize_project_git,
    list_managed_worktrees, remove_managed_worktree,
    remove_worktree_after_export as remove_after_export,
};

const RUNTIME_EVENT_CHANNEL: &str = "grok-build-plus-runtime-event";
const QUEUED_RUNTIME_EVENT_CHANNEL: &str = "grok-build-plus-queued-runtime-event";
pub(crate) const SNAPSHOT_EVENT_CHANNEL: &str = "grok-build-plus-snapshot";
const ACTIVITY_EVENT_CHANNEL: &str = "grok-build-plus-activity-event";
const PTY_EVENT_CHANNEL: &str = "grok-build-plus-pty-event";
const VOICE_EVENT_CHANNEL: &str = "grok-build-plus-voice-event";
const BROWSER_EVENT_CHANNEL: &str = "grok-build-plus-browser-event";
const DESKTOP_FOCUS_COUNTDOWN: std::time::Duration = std::time::Duration::from_secs(3);

mod account_voice;
mod agents;
mod workflows;
pub(crate) use workflows::{
    list_project_workflows, resume_project_workflow, start_project_workflow, stop_project_workflow,
    workflow_result,
};
mod cli_chat;
mod diagnostics;
mod engine;
pub(crate) use cli_chat::*;
pub(crate) use engine::*;
mod extension_mcp;
mod extensions;
pub(crate) use agents::{
    agent_settings, child_agent_result, decide_child_changes, set_agents_enabled, stop_child_agent,
};
mod high_power;
mod mcp_accounts;
mod mcp_elicitation;
mod models;
mod scheduling;
mod terminal;
mod workspace_git;

pub(crate) use account_voice::*;
pub(crate) use diagnostics::*;
pub(crate) use extension_mcp::*;
pub(crate) use extensions::*;
pub(crate) use high_power::*;
pub(crate) use mcp_accounts::*;
pub(crate) use mcp_elicitation::*;
pub(crate) use models::*;
pub(crate) use scheduling::*;
pub(crate) use terminal::*;
pub(crate) use workspace_git::*;

pub(crate) fn lock_backend(shared: &SharedBackend) -> Result<MutexGuard<'_, Backend>, String> {
    shared
        .lock()
        .map_err(|_| "The local UI state lock is unavailable.".to_owned())
}

async fn with_backend<T, F>(state: State<'_, AppState>, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut Backend) -> Result<T, String> + Send + 'static,
{
    let shared = Arc::clone(&state.backend);
    tauri::async_runtime::spawn_blocking(move || {
        let mut backend = lock_backend(&shared)?;
        operation(&mut backend)
    })
    .await
    .map_err(|error| format!("UI worker stopped before completing: {error}"))?
}

pub(crate) async fn present_snapshot(seed: SnapshotSeed) -> Result<AppSnapshot, String> {
    Ok(seed.present_current())
}

async fn with_backend_snapshot<F>(
    state: State<'_, AppState>,
    operation: F,
) -> Result<AppSnapshot, String>
where
    F: FnOnce(&mut Backend) -> Result<SnapshotSeed, String> + Send + 'static,
{
    present_snapshot(with_backend(state, operation).await?).await
}

pub(crate) async fn current_snapshot(shared: &SharedBackend) -> Result<AppSnapshot, String> {
    let seed = lock_backend(shared)?.snapshot_seed();
    present_snapshot(seed).await
}

#[tauri::command]
pub(crate) fn product_version() -> &'static str {
    PLUS_PRODUCT_VERSION
}

#[tauri::command]
pub(crate) async fn bootstrap(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let workspace_watch = state.workspace_watch.clone();
    let snapshot = with_backend_snapshot(state, |backend| Ok(backend.snapshot_seed())).await?;
    sync_workspace_watch(&app, &workspace_watch, &snapshot);
    Ok(snapshot)
}

pub(crate) fn emit_runtime_event(app: &AppHandle, event: RuntimeEvent) {
    let _ = app.emit(RUNTIME_EVENT_CHANNEL, event);
}

fn emit_activity_event(app: &AppHandle, event: &AppEvent) {
    let _ = app.emit(ACTIVITY_EVENT_CHANNEL, event);
}

fn record_activity(
    app: &AppHandle,
    journal: &EventJournal,
    context: EventContext,
    payload: EventPayload,
) -> Result<AppEvent, String> {
    let event = journal.record(context, payload)?;
    emit_activity_event(app, &event);
    Ok(event)
}

fn sync_workspace_watch(app: &AppHandle, workspace_watch: &WorkspaceWatch, snapshot: &AppSnapshot) {
    let root = snapshot.folder_path.as_deref().map(std::path::Path::new);
    if let Err(error) = workspace_watch.sync(app, root) {
        workspace_watch.emit_error(app, &error);
    }
}

#[cfg(test)]
mod tests;
