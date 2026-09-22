//! A typed workflow root invokes the interpreter without starting a parent model.
use super::{
    AdapterTurn, AppHandle, AppState, Arc, PreparedQueuedRun, QueueCoordinator, RunEventRecorder,
    RunId, SharedBackend, emit_current_snapshot, lock_backend, schedule_available,
};
use crate::collaboration::{FamilyController, WorkflowFamilyInput};
use crate::workflows::JobState;
use tauri::Manager as _;

pub(super) fn execute(
    mut prepared: PreparedQueuedRun,
    queue: &QueueCoordinator,
    recorder: &RunEventRecorder,
    app: &AppHandle,
    shared: &SharedBackend,
    run_id: &RunId,
) -> (PreparedQueuedRun, Result<AdapterTurn, String>) {
    let mut family = None;
    let result = (|| {
        let ticket = prepared
            .workflow
            .as_ref()
            .ok_or("Workflow queue identity is absent.")?;
        let registry = app.state::<AppState>().workflows.clone();
        let job = registry.get(&prepared.project_id, &ticket.job_id)?;
        let state_root = lock_backend(shared)?.store.state_root().to_owned();
        let input = {
            let job = job.lock().map_err(|_| "Workflow checkpoint lock failed.")?;
            if job.state != JobState::Ready
                || job.attempt != ticket.attempt
                || !job.available
                || job
                    .queue_item
                    .as_ref()
                    .is_some_and(|id| id != &prepared.queue_item_id)
                || job.input.workspace != prepared.workspace_id
                || job.input.session != prepared.session_id
                || job.input.transport != prepared.runtime.selected_transport()
            {
                return Err("Workflow queue, context or transport binding changed.".into());
            }
            job.input.clone()
        };
        let frozen = crate::extensions::ExtensionStore::new(&state_root).workflow(
            &input.project,
            &input.extension,
            &input.component,
        )?;
        if frozen.script != input.script {
            return Err("Workflow immutable script no longer matches its checkpoint.".into());
        }
        job.lock()
            .map_err(|_| "Workflow checkpoint lock failed.")?
            .mutate(&state_root, |job| {
                job.state = JobState::Running;
                job.queue_item = Some(prepared.queue_item_id.clone());
                job.run = Some(run_id.clone());
                Ok(())
            })?;
        let wake_app = app.clone();
        let wake_shared = Arc::clone(shared);
        let controller = FamilyController::prepare_workflow(
            WorkflowFamilyInput {
                state: &state_root,
                project: prepared.project_id.clone(),
                parent: run_id.clone(),
                bound: prepared.bound.clone(),
                queue: queue.clone(),
                workflow: ticket.job_id.clone(),
                maximum: input.maximum,
            },
            &prepared.runtime,
            Arc::new(move || {
                schedule_available(&wake_app, &wake_shared, None, false)?;
                emit_current_snapshot(&wake_app, &wake_shared);
                Ok(())
            }),
        )?;
        family = Some(controller.clone());
        app.state::<AppState>().agents.retain(controller.clone())?;
        prepared
            .runtime
            .bind_service_run(prepared.project_id.as_str(), run_id.as_str())?;
        let hooks = prepared.runtime.prepare_hooks()?;
        crate::workflows::execute(
            &state_root,
            &job,
            controller,
            &prepared.runtime.cancel_handle(),
            hooks,
        )
    })();
    // The root has no provider model. Runtime disconnect still closes every
    // inherited resource; child cleanup remains necessary on every outcome.
    let close = prepared.runtime.disconnect();
    let family_close = family.as_ref().map_or(Ok(()), FamilyController::close);
    let result = match (
        result,
        close.and(family_close).and(recorder.finish_streams()),
    ) {
        (Ok(turn), Ok(())) => Ok(turn),
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    if result.is_err() {
        let _ = mark_interrupted(&prepared, app, shared, run_id);
    }
    (prepared, result)
}

fn mark_interrupted(
    prepared: &PreparedQueuedRun,
    app: &AppHandle,
    shared: &SharedBackend,
    run: &RunId,
) -> Result<(), String> {
    let ticket = prepared
        .workflow
        .as_ref()
        .ok_or("Workflow identity missing")?;
    let state = lock_backend(shared)?.store.state_root().to_owned();
    let job = app
        .state::<AppState>()
        .workflows
        .get(&prepared.project_id, &ticket.job_id)?;
    let mut job = job.lock().map_err(|_| "Workflow checkpoint lock failed")?;
    if job.run.as_ref() == Some(run) && job.state == JobState::Running {
        job.mutate(&state, |job| {
            job.state = JobState::Interrupted;
            Ok(())
        })?;
    }
    Ok(())
}
