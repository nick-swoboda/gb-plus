//! User-invoked workflow management; source, project and scheduler stay Rust-owned.
use super::{AppHandle, AppState, Arc, State, current_snapshot, lock_backend, schedule_available};
use crate::queue::workflows::WorkflowTicket;
use crate::workflows::{JobInput, JobState};
use serde_json::{Value, json};

#[tauri::command]
pub(crate) async fn stop_project_workflow(
    state: State<'_, AppState>,
    project_id: String,
    job_id: String,
) -> Result<(), String> {
    let shared = Arc::clone(&state.backend);
    let registry = state.workflows.clone();
    let queue = state.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let backend = lock_backend(&shared)?;
        let (_, context) = backend.extension_operation(&project_id)?;
        let job = registry.get(&context.project_id, &job_id)?;
        let job = job.lock().map_err(|_| "Workflow checkpoint lock failed.")?;
        let run = job.run.as_ref().ok_or("Workflow has no active run.")?;
        queue.stop_workflow(
            &context.project_id,
            &WorkflowTicket {
                job_id: job.id.clone(),
                attempt: job.attempt,
            },
            run,
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn list_project_workflows(
    state: State<'_, AppState>,
    project_id: String,
) -> Result<Value, String> {
    let shared = Arc::clone(&state.backend);
    let registry = state.workflows.clone();
    let queue = state.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _scheduler = queue.lock_scheduler()?;
        let (store, context) = lock_backend(&shared)?.extension_operation(&project_id)?;
        let workflows = store.enabled_workflows(&context.project_id)?;
        let jobs = registry.view(&context.project_id, &queue)?.into_iter().map(|job| {
            json!({"id":job.id,"name":job.input.name,"state":job.state,"attempt":job.attempt,"maximum":job.input.maximum,"used":job.used,"phase":job.phase,"available":job.available,"transient":job.input.transient,"runId":job.run})
        }).collect::<Vec<_>>();
        Ok(json!({"workflows":workflows,"jobs":jobs}))
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub(crate) async fn workflow_result(
    state: State<'_, AppState>,
    project_id: String,
    job_id: String,
) -> Result<Value, String> {
    let shared = Arc::clone(&state.backend);
    let registry = state.workflows.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (_, context) = lock_backend(&shared)?.extension_operation(&project_id)?;
        let job = registry.get(&context.project_id, &job_id)?;
        let job = job.lock().map_err(|_| "Workflow checkpoint lock failed.")?;
        Ok(json!({"id":job.id,"state":job.state,"available":job.available,"outcome":job.outcome,"phase":job.phase,"used":job.used,"maximum":job.input.maximum}))
    }).await.map_err(|e| e.to_string())?
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartWorkflowRequest {
    project_id: String,
    extension: String,
    component: String,
    args: Value,
    maximum: Option<u16>,
    transient: bool,
}
#[tauri::command]
pub(crate) async fn start_project_workflow(
    app: AppHandle,
    state: State<'_, AppState>,
    request: StartWorkflowRequest,
) -> Result<crate::backend::AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let registry = state.workflows.clone();
    let queue = state.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _scheduler = queue.lock_scheduler()?;
        let backend = lock_backend(&shared)?;
        let (store, context) = backend.extension_operation(&request.project_id)?;
        let frozen = store.workflow(&context.project_id, &request.extension, &request.component)?;
        let queued = backend.queue_request(&format!("Workflow: {}", frozen.name), true)?;
        backend.events.ensure_available()?;
        let job = registry.create(JobInput {
            project: queued.project_id.clone(),
            workspace: queued.workspace_id.clone(),
            session: queued.session_id.clone(),
            transport: queued.transport,
            extension: frozen.extension,
            component: frozen.component,
            name: frozen.name,
            script: frozen.script,
            args: request.args,
            maximum: request.maximum.unwrap_or(8),
            transient: request.transient,
        })?;
        let mut job = job.lock().map_err(|_| "Workflow checkpoint lock failed.")?;
        let ticket = WorkflowTicket {
            job_id: job.id.clone(),
            attempt: job.attempt,
        };
        let item = queue.enqueue_workflow(queued, ticket)?;
        job.mutate(backend.store.state_root(), |job| {
            job.queue_item = Some(item.id);
            Ok(())
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    schedule_available(&app, &state.backend, None, false)?;
    current_snapshot(&state.backend).await
}

#[tauri::command]
pub(crate) async fn resume_project_workflow(
    app: AppHandle,
    state: State<'_, AppState>,
    project_id: String,
    job_id: String,
) -> Result<crate::backend::AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let registry = state.workflows.clone();
    let queue = state.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _scheduler = queue.lock_idle_scheduler()?;
        let backend = lock_backend(&shared)?;
        let (store, context) = backend.extension_operation(&project_id)?;
        let job = registry.get(&context.project_id, &job_id)?;
        let mut job = job.lock().map_err(|_| "Workflow checkpoint lock failed.")?;
        let frozen = store.workflow(
            &context.project_id,
            &job.input.extension,
            &job.input.component,
        )?;
        if frozen.script != job.input.script {
            return Err("Workflow script changed; resume refused.".into());
        }
        let queued =
            backend.queue_request(&format!("Resume workflow: {}", job.input.name), true)?;
        if queued.workspace_id != job.input.workspace
            || queued.session_id != job.input.session
            || queued.transport != job.input.transport
        {
            return Err(
                "Open the workflow's original workspace, chat and transport before Resume.".into(),
            );
        }
        if job.state == JobState::Running {
            return Err("Stop the active workflow before Resume.".into());
        }
        job.reconcile_ready(backend.store.state_root(), &queue)?;
        job.resume(backend.store.state_root())?;
        let item = queue.enqueue_workflow(
            queued,
            WorkflowTicket {
                job_id: job.id.clone(),
                attempt: job.attempt,
            },
        )?;
        job.mutate(backend.store.state_root(), |job| {
            job.queue_item = Some(item.id);
            Ok(())
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    schedule_available(&app, &state.backend, None, false)?;
    current_snapshot(&state.backend).await
}
