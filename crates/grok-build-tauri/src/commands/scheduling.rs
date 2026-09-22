//! Chat, scheduling, proposal, notification, and contained-check commands.
mod workflow;

use super::{
    AdapterContext, AdapterTurn, AdapterTurnOutcome, AppEvent, AppHandle, AppSnapshot, AppState,
    Arc, Backend, BegunRun, CaptureEventAction, Deserialize, DesktopEventAction, Emitter,
    EventContext, EventErrorCode, EventJournal, EventPayload, PrepareQueuedRunError,
    PrepareQueuedRunErrorKind, PreparedQueuedRun, ProjectId, ProposalEventAction,
    QUEUED_RUNTIME_EVENT_CHANNEL, QueueCoordinator, QueueEventAction, QueueItemId, QueueMode,
    QueueRemovalOutcome, RunCompletion, RunEventAction, RunId, RuntimeEvent, RuntimeTransport,
    SNAPSHOT_EVENT_CHANNEL, Serialize, SessionId, SharedBackend, SnapshotSeed, State,
    SteeringEventAction, ToolEventAction, current_snapshot, emit_activity_event, lock_backend,
    present_snapshot, record_activity, with_backend, with_backend_snapshot,
};
use grok_build_plus_host::{observe_plus_guest, plus_contained_command_with_security_typed};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QueuedRuntimeEvent {
    project_id: String,
    run_id: String,
    event: RuntimeEvent,
}

#[derive(Default)]
struct StreamEventCounts {
    assistant_bytes: usize,
    thought_bytes: usize,
}

#[derive(Clone)]
struct RunEventRecorder {
    journal: EventJournal,
    context: EventContext,
    app: AppHandle,
    transport: RuntimeTransport,
    counts: Arc<std::sync::Mutex<StreamEventCounts>>,
}

impl RunEventRecorder {
    fn new(
        journal: EventJournal,
        context: EventContext,
        app: AppHandle,
        transport: RuntimeTransport,
    ) -> Self {
        Self {
            journal,
            context,
            app,
            transport,
            counts: Arc::new(std::sync::Mutex::new(StreamEventCounts::default())),
        }
    }

    fn observe(&self, event: &RuntimeEvent) -> Result<(), String> {
        if let RuntimeEvent::ToolCompleted { name, .. } | RuntimeEvent::ToolRefused { name, .. } =
            event
            && name.starts_with("desktop_")
        {
            let completed = matches!(event, RuntimeEvent::ToolCompleted { .. });
            self.record(EventPayload::Tool {
                action: if completed {
                    ToolEventAction::Completed
                } else {
                    ToolEventAction::Refused
                },
                name: safe_event_identifier(name, "desktop_tool"),
            })?;
            return self.record(EventPayload::DesktopControl {
                action: if completed {
                    DesktopEventAction::EventPosted
                } else {
                    DesktopEventAction::Refused
                },
                operation: Some(safe_event_identifier(name, "desktop_tool")),
                pid: None,
                window_id: None,
                display_id: None,
            });
        }
        let payload = match event {
            RuntimeEvent::AssistantDelta(delta) => {
                return self.add_stream_bytes(true, delta.len());
            }
            RuntimeEvent::ThoughtDelta(delta) => {
                return self.add_stream_bytes(false, delta.len());
            }
            RuntimeEvent::ToolRequest { name, .. } => EventPayload::Tool {
                action: ToolEventAction::Requested,
                name: safe_provider_tool_name(name),
            },
            RuntimeEvent::ToolCompleted { name, .. } => EventPayload::Tool {
                action: ToolEventAction::Completed,
                name: safe_provider_tool_name(name),
            },
            RuntimeEvent::ToolRefused { name, .. } => EventPayload::Tool {
                action: ToolEventAction::Refused,
                name: safe_provider_tool_name(name),
            },
            RuntimeEvent::Usage(usage) => EventPayload::Usage {
                transport: self.transport,
                usage: usage.clone(),
            },
            RuntimeEvent::CaptureAttached {
                display_id,
                width,
                height,
                byte_count,
                sha256,
            } => EventPayload::Capture {
                action: CaptureEventAction::Attached,
                display_id: Some(*display_id),
                width: Some(*width),
                height: Some(*height),
                byte_count: Some(*byte_count),
                sha256: Some(sha256.clone()),
            },
            RuntimeEvent::UnsupportedProviderEvent {
                provider,
                discriminator,
                byte_count,
            } => EventPayload::Unsupported {
                provider: match provider.as_str() {
                    "GrokCliAcp" => "GrokCliAcp".into(),
                    "XaiKeychain" => "XaiKeychain".into(),
                    _ => "provider".into(),
                },
                discriminator: provider_metadata_identity(discriminator, "unsupported_event"),
                byte_count: *byte_count,
            },
            RuntimeEvent::Error(_) => EventPayload::Error {
                code: EventErrorCode::RuntimeEvent,
            },
            RuntimeEvent::AccountOnboarding { .. }
            | RuntimeEvent::CliUpdate { .. }
            | RuntimeEvent::CliInteraction(_)
            | RuntimeEvent::CliInteractionResolved(_) => return Ok(()),
        };
        self.record(payload)
    }

    fn finish_streams(&self) -> Result<(), String> {
        let (assistant_bytes, thought_bytes) = match self.counts.lock() {
            Ok(counts) => (counts.assistant_bytes, counts.thought_bytes),
            Err(_) => return Err("Activity stream counter lock is unavailable.".into()),
        };
        if assistant_bytes > 0 {
            self.record(EventPayload::Message {
                byte_count: assistant_bytes,
            })?;
        }
        if thought_bytes > 0 {
            self.record(EventPayload::Thought {
                byte_count: thought_bytes,
            })?;
        }
        Ok(())
    }

    fn add_stream_bytes(&self, assistant: bool, byte_count: usize) -> Result<(), String> {
        let mut counts = self
            .counts
            .lock()
            .map_err(|_| "Activity stream counter lock is unavailable.".to_owned())?;
        let target = if assistant {
            &mut counts.assistant_bytes
        } else {
            &mut counts.thought_bytes
        };
        *target = target.saturating_add(byte_count);
        Ok(())
    }

    fn record(&self, payload: EventPayload) -> Result<(), String> {
        self.record_event(payload).map(|_| ())
    }

    fn record_event(&self, payload: EventPayload) -> Result<AppEvent, String> {
        let event = self.journal.record(self.context.clone(), payload)?;
        emit_activity_event(&self.app, &event);
        Ok(event)
    }
}

fn safe_event_identifier(value: &str, fallback: &str) -> String {
    if !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
        })
    {
        value.to_owned()
    } else {
        fallback.to_owned()
    }
}

fn safe_provider_tool_name(value: &str) -> String {
    if let Some(name) = grok_build_plus_host::PlusToolName::from_wire(value) {
        name.descriptor().persistence_safe_label.to_owned()
    } else {
        provider_metadata_identity(value, "provider_tool")
    }
}

fn provider_metadata_identity(value: &str, fallback: &str) -> String {
    let Some(digest) = value.strip_prefix("provider_value_sha256:") else {
        if value.is_empty() {
            return fallback.into();
        }
        return format!(
            "provider_value_sha256:{}",
            grok_build_plus_host::worktree_recovery_digest(value.as_bytes())
        );
    };
    if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        value.to_owned()
    } else {
        fallback.into()
    }
}
pub(crate) fn safe_queue_block_reason(
    transport: RuntimeTransport,
    error: &PrepareQueuedRunError,
) -> String {
    if matches!(
        error.kind,
        PrepareQueuedRunErrorKind::ProjectMissing
            | PrepareQueuedRunErrorKind::WorkspaceDrift
            | PrepareQueuedRunErrorKind::WorkspaceUnavailable
    ) {
        return error.detail.clone();
    }
    format!(
        "{} cannot start this queued prompt through its selected Chat path. Open Account, reconnect that exact transport, then Run next.",
        transport.label()
    )
}

fn persisted_run_failure(transport: RuntimeTransport) -> String {
    format!(
        "{} failed after the queued run started. The selected transport is no longer Connected; reconnect in Account before retrying.",
        transport.label()
    )
}

fn emit_queued_runtime_event(
    app: &AppHandle,
    project_id: &ProjectId,
    run_id: &RunId,
    event: RuntimeEvent,
) {
    let _ = app.emit(
        QUEUED_RUNTIME_EVENT_CHANNEL,
        QueuedRuntimeEvent {
            project_id: project_id.as_str().to_owned(),
            run_id: run_id.as_str().to_owned(),
            event,
        },
    );
}

fn emit_current_snapshot(app: &AppHandle, shared: &SharedBackend) {
    if let Ok(snapshot) =
        lock_backend(shared).map(|mut backend| backend.snapshot_seed().present_current())
    {
        let _ = app.emit(SNAPSHOT_EVENT_CHANNEL, snapshot);
    }
}

fn cleanup_run_state(path: &std::path::Path) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            name.len() == 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| "Queue run-state cleanup refused an invalid identity.".to_owned())?;
    let parent = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str());
    if parent != Some("queue-run-state") || name.is_empty() {
        return Err("Queue run-state cleanup refused an unexpected root.".into());
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "Cannot inspect queue run-state cleanup root: {error}"
            ));
        }
    };
    if metadata.file_type().is_symlink() || metadata.is_file() {
        std::fs::remove_file(path)
            .map_err(|error| format!("Cannot remove queue run-state link/file: {error}"))
    } else if metadata.is_dir() {
        std::fs::remove_dir_all(path)
            .map_err(|error| format!("Cannot remove queue run-state directory: {error}"))
    } else {
        Err("Queue run-state cleanup refused a special file.".into())
    }
}

fn prepare_family(
    prepared: &mut PreparedQueuedRun,
    queue: &QueueCoordinator,
    app: &AppHandle,
    shared: &SharedBackend,
    run_id: &RunId,
) -> Result<Option<crate::collaboration::FamilyController>, String> {
    use tauri::Manager as _;
    let state_root = lock_backend(shared)?.store.state_root().to_owned();
    let wake_app = app.clone();
    let wake_shared = Arc::clone(shared);
    let family = crate::collaboration::FamilyController::prepare(
        &state_root,
        prepared.project_id.clone(),
        run_id.clone(),
        prepared.bound.clone(),
        queue.clone(),
        &prepared.runtime,
        Arc::new(move || {
            schedule_available(&wake_app, &wake_shared, None, false)?;
            emit_current_snapshot(&wake_app, &wake_shared);
            Ok(())
        }),
    )?;
    if let Some(controller) = &family {
        let bound = app
            .state::<AppState>()
            .agents
            .retain(controller.clone())
            .and_then(|()| {
                prepared
                    .runtime
                    .bind_collaboration(Arc::new(controller.clone()))
            });
        if let Err(error) = bound {
            controller.close()?;
            return Err(error);
        }
    }
    Ok(family)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the queue, Activity, app snapshot, cancellation, and exact run identity are separate fail-closed boundaries"
)]
fn execute_prepared_queue_run(
    mut prepared: PreparedQueuedRun,
    prompt: &str,
    queue: &QueueCoordinator,
    recorder: &RunEventRecorder,
    app: &AppHandle,
    shared: &SharedBackend,
    project_id: &ProjectId,
    run_id: &RunId,
) -> (PreparedQueuedRun, Result<AdapterTurn, String>) {
    if prepared.workflow.is_some() {
        return workflow::execute(prepared, queue, recorder, app, shared, run_id);
    }
    let mut family = None;
    let events = |event| {
        recorder.observe(&event)?;
        if matches!(event, RuntimeEvent::Usage(_)) {
            emit_current_snapshot(app, shared);
        }
        emit_queued_runtime_event(app, project_id, run_id, event);
        Ok(())
    };
    let result = (|| {
        prepared
            .runtime
            .bind_browser_run(project_id.as_str(), run_id.as_str())?;
        family = prepare_family(&mut prepared, queue, app, shared, run_id)?;
        let hooks = prepared.runtime.prepare_hooks()?;
        prepared
            .runtime
            .start_connected_run_session_observed(&events)?;
        let context = AdapterContext {
            scope: crate::runtime::types::RuntimeInvocationScope {
                project_id: prepared.project_id.clone(),
                workspace_id: prepared.workspace_id.clone(),
                session_id: prepared.session_id.clone(),
                run_id: run_id.clone(),
            },
            extension_context: &prepared.extension_context,
            hooks,
            bound: &prepared.bound,
            store: &prepared.run_store,
        };
        let steering = |action| {
            use crate::queue::SteerIntentState;
            use crate::runtime::types::{RuntimeSteeringAction, RuntimeSteeringMessage};
            if let RuntimeSteeringAction::Record(id, delivery) = action {
                queue.record_steer_delivery(run_id, &id, delivery)?;
                let action = match delivery {
                    SteerIntentState::Submitted => SteeringEventAction::Submitted,
                    SteerIntentState::AcknowledgedByCli => SteeringEventAction::AcknowledgedByCli,
                    SteerIntentState::ObservedInProviderHistory => {
                        SteeringEventAction::ObservedInProviderHistory
                    }
                    SteerIntentState::Uncertain => SteeringEventAction::Uncertain,
                    SteerIntentState::Refused => SteeringEventAction::Refused,
                    _ => return Err("Invalid runtime delivery evidence.".into()),
                };
                recorder.record(EventPayload::Steering {
                    action,
                    steer_intent_id: id,
                })?;
                emit_current_snapshot(app, shared);
                return Ok(Vec::new());
            }
            let intents = queue.submit_pending_steers(run_id)?;
            for intent in &intents {
                recorder.record(EventPayload::Steering {
                    action: SteeringEventAction::Submitted,
                    steer_intent_id: intent.id.clone(),
                })?;
            }
            if !intents.is_empty() {
                emit_current_snapshot(app, shared);
            }
            Ok(intents
                .into_iter()
                .map(|intent| RuntimeSteeringMessage {
                    id: intent.id,
                    text: intent.message,
                    transient: false,
                })
                .collect())
        };
        prepared
            .runtime
            .send_turn(&context, prompt, &steering, &events)
    })();
    let succeeded = result
        .as_ref()
        .is_ok_and(|turn| turn.outcome == AdapterTurnOutcome::Completed);
    let close = prepared.runtime.disconnect();
    let family_close = family.as_ref().map_or(Ok(()), |family| {
        family.finish_after_parent(succeeded && close.is_ok())
    });
    let close = close.and(family_close);
    let result = match (result, close) {
        (Ok(turn), Ok(())) => Ok(turn),
        (Ok(_), Err(error)) | (Err(error), _) => Err(error),
    };
    let result = match (result, recorder.finish_streams()) {
        (Ok(turn), Ok(())) => Ok(turn),
        (Ok(_), Err(error)) | (Err(error), _) => Err(error),
    };
    (prepared, result)
}

fn resolve_queue_completion<E>(
    execution: Result<(PreparedQueuedRun, Result<AdapterTurn, String>), E>,
    stop_requested: bool,
    shared: &SharedBackend,
    transport: RuntimeTransport,
    recorder: &RunEventRecorder,
) -> (RunCompletion, Option<RuntimeEvent>) {
    match (execution, stop_requested) {
        (Ok((prepared, Ok(turn))), false) => {
            let outcome = turn.outcome.clone();
            let applied = lock_backend(shared)
                .and_then(|mut backend| backend.apply_queued_turn(&prepared, &turn));
            match applied {
                Ok(has_pending) => {
                    if has_pending {
                        let _ = recorder.record(EventPayload::Proposal {
                            action: ProposalEventAction::Staged,
                            relative_path: None,
                            count: turn.pending.items.len(),
                        });
                    }
                    if let AdapterTurnOutcome::Failed(reason) = outcome {
                        return (RunCompletion::Failed(reason), None);
                    }
                    if has_pending {
                        (RunCompletion::NeedsReview, None)
                    } else {
                        (RunCompletion::Done, None)
                    }
                }
                Err(_) => failed_queue_completion(
                    "Queued result could not be durably applied to its exact session.",
                    recorder,
                ),
            }
        }
        (Ok((_, Ok(_) | Err(_))), true) => {
            (RunCompletion::Stopped("Stopped by the user.".into()), None)
        }
        (Ok((prepared, Err(reason))), false) => {
            let failure = prepared.runtime.last_adapter_failure().cloned();
            if let Ok(mut backend) = lock_backend(shared) {
                backend.record_queued_run_failure(transport, &reason, failure.as_ref());
            }
            let public_failure = persisted_run_failure(transport);
            let event = RuntimeEvent::Error(public_failure.clone());
            let _ = recorder.observe(&event);
            (RunCompletion::Failed(public_failure), Some(event))
        }
        (Err(_), _) => failed_queue_completion(
            "Queued runtime worker stopped before returning an outcome.",
            recorder,
        ),
    }
}

fn failed_queue_completion(
    message: &str,
    recorder: &RunEventRecorder,
) -> (RunCompletion, Option<RuntimeEvent>) {
    let event = RuntimeEvent::Error(message.into());
    let _ = recorder.observe(&event);
    (RunCompletion::Failed(message.into()), Some(event))
}

fn persist_queue_terminal(
    queue: &QueueCoordinator,
    run_id: &RunId,
    queue_item_id: QueueItemId,
    transport: RuntimeTransport,
    completion: RunCompletion,
    recorder: &RunEventRecorder,
) -> (Option<RuntimeEvent>, Option<u64>) {
    let terminal_action = run_completion_action(&completion);
    let promoted = match queue.complete_run(run_id, completion) {
        Ok(promoted) => promoted,
        Err(error) => {
            let event = RuntimeEvent::Error(format!("Queue terminal persistence failed: {error}"));
            let _ = recorder.observe(&event);
            return (Some(event), None);
        }
    };
    for promotion in promoted {
        if recorder
            .record(EventPayload::Steering {
                action: SteeringEventAction::PromotedToNext,
                steer_intent_id: promotion.intent_id,
            })
            .and_then(|()| {
                recorder.record(EventPayload::Queue {
                    action: QueueEventAction::Enqueued,
                    queue_item_id: Some(promotion.item.id),
                    mode: Some(QueueMode::SendNext),
                })
            })
            .is_err()
        {
            return (
                Some(RuntimeEvent::Error(
                    "The late Send now message became the next turn, but its Activity evidence is unavailable."
                        .into(),
                )),
                None,
            );
        }
    }
    let Ok(terminal_event) = recorder.record_event(EventPayload::Run {
        action: terminal_action,
        queue_item_id,
        transport,
    }) else {
        return (
            Some(RuntimeEvent::Error(
                "The run outcome is durable, but Activity terminal evidence is unavailable.".into(),
            )),
            None,
        );
    };
    (None, Some(terminal_event.sequence.get()))
}

fn spawn_queue_worker(
    app: AppHandle,
    shared: SharedBackend,
    queue: QueueCoordinator,
    begun: BegunRun,
    prepared: PreparedQueuedRun,
    recorder: RunEventRecorder,
) {
    let run_id = begun.run.id.clone();
    let project_id = begun.item.project_id.clone();
    let transport = begun.item.transport;
    let session_id = prepared.session_id.clone();
    let cleanup_root = prepared.run_state_root.clone();
    tauri::async_runtime::spawn(async move {
        let worker_app = app.clone();
        let worker_project = project_id.clone();
        let worker_run = run_id.clone();
        let prompt = begun.item.prompt.clone();
        let worker_recorder = recorder.clone();
        let worker_shared = Arc::clone(&shared);
        let worker_queue = queue.clone();
        let execution = tauri::async_runtime::spawn_blocking(move || {
            execute_prepared_queue_run(
                prepared,
                &prompt,
                &worker_queue,
                &worker_recorder,
                &worker_app,
                &worker_shared,
                &worker_project,
                &worker_run,
            )
        })
        .await;

        if !queue.run_cleanup_proven(&run_id) {
            emit_queued_runtime_event(&app, &project_id, &run_id, RuntimeEvent::Error(
                "The CLI is stopping. This run keeps its execution slot until process cleanup is confirmed.".into(),
            ));
            // The bounded reaper owns the exact unreaped child. Waiting here is
            // asynchronous and keeps controls responsive; a timeout must never
            // manufacture cleanup evidence or release model execution capacity.
            while !queue.run_cleanup_proven(&run_id) {
                let _ = tauri::async_runtime::spawn_blocking(|| {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                })
                .await;
            }
        }

        let stop_requested = queue.is_stop_requested(&run_id);
        let (completion, runtime_error) =
            resolve_queue_completion(execution, stop_requested, &shared, transport, &recorder);
        let notification_action = run_completion_action(&completion);
        if let Some(event) = runtime_error {
            emit_queued_runtime_event(&app, &project_id, &run_id, event);
        }
        if let Ok(backend) = lock_backend(&shared) {
            let _ = backend.finish_queued_session(&session_id);
        }
        let (terminal_error, source_sequence) = persist_queue_terminal(
            &queue,
            &run_id,
            begun.item.id.clone(),
            transport,
            completion,
            &recorder,
        );
        if let Some(event) = terminal_error {
            emit_queued_runtime_event(&app, &project_id, &run_id, event);
        }
        if let Ok(backend) = lock_backend(&shared)
            && let Err(reason) = backend.record_run_notifications(
                &project_id,
                &session_id,
                &run_id,
                source_sequence,
                notification_action,
            )
        {
            emit_queued_runtime_event(
                &app,
                &project_id,
                &run_id,
                RuntimeEvent::Error(format!(
                    "The run completed, but its in-app notification could not be saved: {reason}"
                )),
            );
        }
        if cleanup_run_state(&cleanup_root).is_err() {
            emit_queued_runtime_event(
                &app,
                &project_id,
                &run_id,
                RuntimeEvent::Error(
                    "Queue run-state cleanup failed; the app will retry on restart.".into(),
                ),
            );
        }
        emit_current_snapshot(&app, &shared);
        let _ = schedule_available(&app, &shared, None, false);
    });
}

pub(crate) fn schedule_available(
    app: &AppHandle,
    shared: &SharedBackend,
    project: Option<&ProjectId>,
    include_manual: bool,
) -> Result<usize, String> {
    let (queue, journal) = {
        let backend = lock_backend(shared)?;
        (backend.queue.clone(), backend.events.clone())
    };
    journal.ensure_available()?;
    let _scheduler = queue.lock_scheduler()?;
    let candidates = queue.candidates(project, include_manual)?;
    let mut started = 0;
    for item in candidates {
        let prepared = match lock_backend(shared)?.prepare_queued_run(&item) {
            Ok(prepared) => prepared,
            Err(error) => {
                queue.mark_blocked(&item.id, &safe_queue_block_reason(item.transport, &error))?;
                record_activity(
                    app,
                    &journal,
                    EventContext::project_session(item.project_id.clone(), item.session_id.clone()),
                    EventPayload::Queue {
                        action: QueueEventAction::Blocked,
                        queue_item_id: Some(item.id.clone()),
                        mode: None,
                    },
                )?;
                continue;
            }
        };
        let cancel = prepared.runtime.cancel_handle();
        let begun = match queue.begin_run(&item.id, cancel) {
            Ok(begun) => begun,
            Err(error) => {
                let _ = cleanup_run_state(&prepared.run_state_root);
                return Err(error);
            }
        };
        let event_context = EventContext::run(
            begun.item.project_id.clone(),
            begun.item.session_id.clone(),
            begun.run.id.clone(),
        );
        if let Err(error) = record_activity(
            app,
            &journal,
            event_context.clone(),
            EventPayload::Run {
                action: RunEventAction::Started,
                queue_item_id: begun.item.id.clone(),
                transport: begun.item.transport,
            },
        ) {
            let _ = queue.complete_run(
                &begun.run.id,
                RunCompletion::Failed(
                    "Activity evidence was unavailable before provider execution.".into(),
                ),
            );
            let _ = cleanup_run_state(&prepared.run_state_root);
            return Err(error);
        }
        if let Err(error) =
            lock_backend(shared)?.mark_queued_session_running(&begun.item.session_id)
        {
            let _ = queue.complete_run(&begun.run.id, RunCompletion::Failed(error));
            let _ = cleanup_run_state(&prepared.run_state_root);
            continue;
        }
        let recorder = RunEventRecorder::new(
            journal.clone(),
            event_context,
            app.clone(),
            begun.item.transport,
        );
        spawn_queue_worker(
            app.clone(),
            Arc::clone(shared),
            queue.clone(),
            begun,
            prepared,
            recorder,
        );
        started += 1;
    }
    emit_current_snapshot(app, shared);
    Ok(started)
}

fn run_completion_action(completion: &RunCompletion) -> RunEventAction {
    match completion {
        RunCompletion::NeedsReview => RunEventAction::NeedsReview,
        RunCompletion::Done => RunEventAction::Done,
        RunCompletion::Failed(_) => RunEventAction::Failed,
        RunCompletion::Stopped(_) => RunEventAction::Stopped,
    }
}
#[tauri::command]
pub(crate) async fn send_chat(
    app: AppHandle,
    state: State<'_, AppState>,
    message: String,
) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let shared = Arc::clone(&state.backend);
    let (queue, journal, request) = {
        let backend = lock_backend(&shared)?;
        (
            backend.queue.clone(),
            backend.events.clone(),
            backend.queue_request(&message, true)?,
        )
    };
    journal.ensure_available()?;
    let context =
        EventContext::project_session(request.project_id.clone(), request.session_id.clone());
    let item = queue.enqueue(request)?;
    record_activity(
        &app,
        &journal,
        context,
        EventPayload::Queue {
            action: QueueEventAction::Enqueued,
            queue_item_id: Some(item.id),
            mode: Some(QueueMode::Send),
        },
    )?;
    schedule_available(&app, &shared, None, false)?;
    current_snapshot(&shared).await
}

#[tauri::command]
pub(crate) async fn send_now(
    app: AppHandle,
    state: State<'_, AppState>,
    message: String,
    project_id: String,
    session_id: String,
    run_id: String,
) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let shared = Arc::clone(&state.backend);
    let project = ProjectId::new(project_id);
    let session = SessionId::new(session_id);
    let run = RunId::new(run_id);
    let (queue, journal) = {
        let backend = lock_backend(&shared)?;
        if backend.active_project_typed_id()? != project
            || SessionId::new(
                backend
                    .store
                    .active_plus_session_id()
                    .map_err(|error| error.to_string())?,
            ) != session
        {
            return Err("Send now refused because the active Chat identity changed.".into());
        }
        (backend.queue.clone(), backend.events.clone())
    };
    journal.ensure_available()?;
    let intent = queue.enqueue_steer(&project, &session, &run, message.trim())?;
    record_activity(
        &app,
        &journal,
        EventContext::run(project, session, run),
        EventPayload::Steering {
            action: SteeringEventAction::Queued,
            steer_intent_id: intent.id,
        },
    )?;
    current_snapshot(&shared).await
}

#[tauri::command]
pub(crate) async fn steer_queue_item(
    app: AppHandle,
    state: State<'_, AppState>,
    queue_item_id: String,
    project_id: String,
    session_id: String,
    run_id: String,
) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let shared = Arc::clone(&state.backend);
    let project = ProjectId::new(project_id);
    let session = SessionId::new(session_id);
    let run = RunId::new(run_id);
    let (queue, journal) = {
        let backend = lock_backend(&shared)?;
        if backend.active_project_typed_id()? != project
            || SessionId::new(
                backend
                    .store
                    .active_plus_session_id()
                    .map_err(|error| error.to_string())?,
            ) != session
        {
            return Err("Send now refused because the active Chat identity changed.".into());
        }
        (backend.queue.clone(), backend.events.clone())
    };
    journal.ensure_available()?;
    let scheduler = queue.lock_scheduler()?;
    let intent =
        queue.steer_queued_item(&QueueItemId::new(queue_item_id), &project, &session, &run)?;
    record_activity(
        &app,
        &journal,
        EventContext::run(project, session, run),
        EventPayload::Steering {
            action: SteeringEventAction::Queued,
            steer_intent_id: intent.id,
        },
    )?;
    drop(scheduler);
    current_snapshot(&shared).await
}

#[tauri::command]
pub(crate) async fn send_next(
    app: AppHandle,
    state: State<'_, AppState>,
    message: String,
    run_id: String,
) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let shared = Arc::clone(&state.backend);
    let predecessor = RunId::new(run_id);
    let (queue, journal, request) = {
        let backend = lock_backend(&shared)?;
        (
            backend.queue.clone(),
            backend.events.clone(),
            backend.queue_request(&message, true)?,
        )
    };
    journal.ensure_available()?;
    let context =
        EventContext::project_session(request.project_id.clone(), request.session_id.clone());
    let item = queue.enqueue_send_next(request, &predecessor)?;
    record_activity(
        &app,
        &journal,
        context,
        EventPayload::Queue {
            action: QueueEventAction::Enqueued,
            queue_item_id: Some(item.id),
            mode: Some(QueueMode::SendNext),
        },
    )?;
    current_snapshot(&shared).await
}

#[tauri::command]
pub(crate) async fn release_held_message(
    app: AppHandle,
    state: State<'_, AppState>,
    queue_item_id: String,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let (queue, journal) = {
        let backend = lock_backend(&shared)?;
        (backend.queue.clone(), backend.events.clone())
    };
    journal.ensure_available()?;
    let item = queue.release_held(&QueueItemId::new(queue_item_id))?;
    record_activity(
        &app,
        &journal,
        EventContext::project_session(item.project_id.clone(), item.session_id.clone()),
        EventPayload::Queue {
            action: QueueEventAction::Enqueued,
            queue_item_id: Some(item.id),
            mode: Some(QueueMode::LegacyHeld),
        },
    )?;
    schedule_available(&app, &shared, Some(&item.project_id), false)?;
    current_snapshot(&shared).await
}

#[tauri::command]
pub(crate) async fn retry_queue_run(
    app: AppHandle,
    state: State<'_, AppState>,
    run_id: String,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let (queue, journal) = {
        let backend = lock_backend(&shared)?;
        (backend.queue.clone(), backend.events.clone())
    };
    journal.ensure_available()?;
    let item = queue.retry(&RunId::new(run_id))?;
    record_activity(
        &app,
        &journal,
        EventContext::project_session(item.project_id.clone(), item.session_id.clone()),
        EventPayload::Queue {
            action: QueueEventAction::RetryEnqueued,
            queue_item_id: Some(item.id),
            mode: Some(QueueMode::Send),
        },
    )?;
    schedule_available(&app, &shared, None, false)?;
    current_snapshot(&shared).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QueueRemovalResponse {
    outcome: &'static str,
    snapshot: AppSnapshot,
}

#[tauri::command]
pub(crate) async fn remove_queue_item(
    app: AppHandle,
    state: State<'_, AppState>,
    queue_item_id: String,
) -> Result<QueueRemovalResponse, String> {
    let shared = Arc::clone(&state.backend);
    let (queue, journal) = {
        let backend = lock_backend(&shared)?;
        (backend.queue.clone(), backend.events.clone())
    };
    journal.ensure_available()?;
    let scheduler = queue.lock_scheduler()?;
    let removal = queue.remove_item(&QueueItemId::new(queue_item_id))?;
    if removal.outcome == QueueRemovalOutcome::Removed {
        lock_backend(&shared)?.discard_queued_cli_image(&removal.item)?;
    }
    let outcome = match removal.outcome {
        QueueRemovalOutcome::Removed => "removed",
        QueueRemovalOutcome::StopRequested => "stop_requested",
    };
    let context = removal.run_id.as_ref().map_or_else(
        || {
            EventContext::project_session(
                removal.item.project_id.clone(),
                removal.item.session_id.clone(),
            )
        },
        |run_id| {
            EventContext::run(
                removal.item.project_id.clone(),
                removal.item.session_id.clone(),
                run_id.clone(),
            )
        },
    );
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Queue {
            action: match removal.outcome {
                QueueRemovalOutcome::Removed => QueueEventAction::Removed,
                QueueRemovalOutcome::StopRequested => QueueEventAction::RemovalRequested,
            },
            queue_item_id: Some(removal.item.id.clone()),
            mode: None,
        },
    )?;
    if removal.outcome == QueueRemovalOutcome::StopRequested {
        record_activity(
            &app,
            &journal,
            context,
            EventPayload::Run {
                action: RunEventAction::StopRequested,
                queue_item_id: removal.item.id,
                transport: removal.item.transport,
            },
        )?;
    }
    drop(scheduler);
    Ok(QueueRemovalResponse {
        outcome,
        snapshot: current_snapshot(&shared).await?,
    })
}

async fn resolve_proposal_and_resume(
    app: AppHandle,
    state: State<'_, AppState>,
    operation: impl FnOnce(&mut Backend) -> Result<SnapshotSeed, String> + Send + 'static,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let _ = with_backend(state, operation).await?;
    schedule_available(&app, &shared, None, false)?;
    current_snapshot(&shared).await
}

#[tauri::command]
pub(crate) async fn accept_file(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> Result<AppSnapshot, String> {
    resolve_proposal_and_resume(app, state, move |backend| backend.accept_file(&path)).await
}

#[tauri::command]
pub(crate) async fn accept_scoped_file(
    app: AppHandle,
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
    path: String,
    proposal_fingerprint: String,
) -> Result<AppSnapshot, String> {
    resolve_proposal_and_resume(app, state, move |backend| {
        backend.accept_scoped_file(
            &ProjectId::new(project_id),
            &SessionId::new(session_id),
            &path,
            &proposal_fingerprint,
        )
    })
    .await
}

#[tauri::command]
pub(crate) async fn reject_file(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
) -> Result<AppSnapshot, String> {
    resolve_proposal_and_resume(app, state, move |backend| backend.reject_file(&path)).await
}

#[tauri::command]
pub(crate) async fn reject_scoped_file(
    app: AppHandle,
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
    path: String,
    proposal_fingerprint: String,
) -> Result<AppSnapshot, String> {
    resolve_proposal_and_resume(app, state, move |backend| {
        backend.reject_scoped_file(
            &ProjectId::new(project_id),
            &SessionId::new(session_id),
            &path,
            &proposal_fingerprint,
        )
    })
    .await
}

#[tauri::command]
pub(crate) async fn mark_notification_read(
    state: State<'_, AppState>,
    id: String,
) -> Result<AppSnapshot, String> {
    with_backend_snapshot(state, move |backend| backend.mark_notification_read(&id)).await
}

#[tauri::command]
pub(crate) async fn dismiss_notification(
    state: State<'_, AppState>,
    id: String,
) -> Result<AppSnapshot, String> {
    with_backend_snapshot(state, move |backend| backend.dismiss_notification(&id)).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScopedProposalBinding {
    path: String,
    proposal_fingerprint: String,
}

#[tauri::command]
pub(crate) async fn accept_all_scoped(
    app: AppHandle,
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
    proposals: Vec<ScopedProposalBinding>,
) -> Result<AppSnapshot, String> {
    let bindings = proposals
        .into_iter()
        .map(|proposal| (proposal.path, proposal.proposal_fingerprint))
        .collect::<Vec<_>>();
    resolve_proposal_and_resume(app, state, move |backend| {
        backend.accept_all_scoped(
            &ProjectId::new(project_id),
            &SessionId::new(session_id),
            &bindings,
        )
    })
    .await
}

#[tauri::command]
pub(crate) async fn reject_all_scoped(
    app: AppHandle,
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
    proposals: Vec<ScopedProposalBinding>,
) -> Result<AppSnapshot, String> {
    let bindings = proposals
        .into_iter()
        .map(|proposal| (proposal.path, proposal.proposal_fingerprint))
        .collect::<Vec<_>>();
    resolve_proposal_and_resume(app, state, move |backend| {
        backend.reject_all_scoped(
            &ProjectId::new(project_id),
            &SessionId::new(session_id),
            &bindings,
        )
    })
    .await
}

#[tauri::command]
pub(crate) async fn run_contained_check(state: State<'_, AppState>) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let observation = tauri::async_runtime::spawn_blocking(observe_plus_guest)
        .await
        .map_err(|error| format!("Container validation worker stopped: {error}"))?;
    let prepared = lock_backend(&shared)?.prepare_security_effect(
        observation,
        crate::events::SecurityEventSurface::Checks,
        "running a contained check",
    )?;
    let gate = state.operations.gate(&prepared.context.project_id)?;
    let worker_shared = Arc::clone(&shared);
    let (prepared, outcome) = tauri::async_runtime::spawn_blocking(move || {
        let _permit = gate
            .lock()
            .map_err(|_| "Project operation permit is unavailable.".to_owned())?;
        lock_backend(&worker_shared)?.revalidate_operation(&prepared.context)?;
        let outcome = plus_contained_command_with_security_typed(
            &prepared.bound,
            prepared.preference,
            false,
            &prepared.observation.lifecycle,
        );
        Ok::<_, String>((prepared, outcome))
    })
    .await
    .map_err(|error| format!("Contained-check worker stopped: {error}"))??;
    let seed =
        lock_backend(&shared)?.finish_security_effect(prepared, outcome, "contained-check")?;
    present_snapshot(seed).await
}

#[tauri::command]
pub(crate) async fn check_command_security_container(
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let observation = tauri::async_runtime::spawn_blocking(observe_plus_guest)
        .await
        .map_err(|error| format!("Container check worker stopped: {error}"))?;
    let seed = lock_backend(&state.backend)?.mark_container_checked(observation);
    present_snapshot(seed).await
}

#[tauri::command]
pub(crate) async fn install_command_security_container(
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let manager = state.container_runtime.clone();
    let (result, observation) =
        tauri::async_runtime::spawn_blocking(move || (manager.install(), observe_plus_guest()))
            .await
            .map_err(|error| format!("Colima install worker stopped: {error}"))?;
    let seed = match result {
        Ok(detail) => lock_backend(&shared)?.remember_command_security_setup(&detail, observation),
        Err(error) => lock_backend(&shared)?.remember_command_security_failure(
            &format!("Colima install failed: {error}"),
            observation,
        ),
    };
    present_snapshot(seed).await
}

#[tauri::command]
pub(crate) async fn configure_command_security(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let manager = state.container_runtime.clone();
    {
        let mut backend = lock_backend(&shared)?;
        backend.set_command_security_enabled(enabled)?;
    }
    if enabled {
        let (result, observation) =
            tauri::async_runtime::spawn_blocking(move || manager.install_linux_service())
                .await
                .map_err(|error| format!("Command-security setup worker stopped: {error}"))?;
        let seed = match result {
            Ok(detail) => {
                lock_backend(&shared)?.remember_command_security_setup(&detail, observation)
            }
            Err(error) => lock_backend(&shared)?.remember_command_security_failure(
                &format!("Command-security setup failed: {error}"),
                observation,
            ),
        };
        present_snapshot(seed).await
    } else {
        current_snapshot(&shared).await
    }
}

#[tauri::command]
pub(crate) async fn cancel_chat(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let shared = Arc::clone(&state.backend);
    let (queue, journal, project) = {
        let backend = lock_backend(&shared)?;
        (
            backend.queue.clone(),
            backend.events.clone(),
            backend.active_project_typed_id()?,
        )
    };
    record_stop_requested(&app, &queue, &journal, &project)?;
    current_snapshot(&shared).await
}

fn record_stop_requested(
    app: &AppHandle,
    queue: &QueueCoordinator,
    journal: &EventJournal,
    project: &ProjectId,
) -> Result<(), String> {
    journal.ensure_available()?;
    let run_id = queue.request_stop(project)?;
    let view = queue.view();
    let run = view
        .runs
        .iter()
        .find(|run| run.id == run_id.as_str())
        .ok_or_else(|| "Stopped run identity is unavailable from the durable queue.".to_owned())?;
    let item = view
        .items
        .iter()
        .find(|item| item.id == run.queue_item_id)
        .ok_or_else(|| "Stopped run's queued prompt identity is unavailable.".to_owned())?;
    record_activity(
        app,
        journal,
        EventContext::run(
            ProjectId::new(run.project_id.clone()),
            SessionId::new(run.session_id.clone()),
            run_id,
        ),
        EventPayload::Run {
            action: RunEventAction::StopRequested,
            queue_item_id: QueueItemId::new(run.queue_item_id.clone()),
            transport: item.transport,
        },
    )?;
    Ok(())
}
