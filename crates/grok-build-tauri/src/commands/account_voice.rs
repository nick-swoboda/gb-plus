//! Account, Read Aloud, and voice-input commands.

use super::{
    AppHandle, AppSnapshot, AppState, Arc, Backend, Emitter, EventPayload, GrokCliOAuthPhase,
    ReadAloudAudio, ReadAloudView, RuntimeEvent, RuntimeTransport, State, VOICE_EVENT_CHANNEL,
    VoiceEventAction, VoiceModel, VoicePhase, VoiceProgress, VoiceTranscript, VoiceView,
    current_snapshot, emit_runtime_event, lock_backend, prompt_xai_key, record_activity,
    run_grok_cli_oauth, schedule_available, with_backend_snapshot,
};

async fn with_account_probe<F>(
    state: State<'_, AppState>,
    operation: F,
) -> Result<AppSnapshot, String>
where
    F: FnOnce(&mut Backend) -> Result<crate::backend::SnapshotSeed, String> + Send + 'static,
{
    let shared = Arc::clone(&state.backend);
    let queue = lock_backend(&shared)?.queue.clone();
    let seed = tauri::async_runtime::spawn_blocking(move || {
        // Connection checks execute a model, too. Acquire in scheduler → backend
        // order and retain the reservation through provider close/reconciliation.
        let _scheduler = queue.lock_idle_scheduler()?;
        let mut backend = lock_backend(&shared)?;
        operation(&mut backend)
    })
    .await
    .map_err(|error| format!("Account probe worker failed: {error}"))??;
    super::present_snapshot(seed).await
}

#[tauri::command]
pub(crate) async fn reset_provider_context(
    state: State<'_, AppState>,
    project_id: String,
    session_id: String,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let queue = lock_backend(&shared)?.queue.clone();
    let seed = tauri::async_runtime::spawn_blocking(move || {
        let _scheduler = queue.lock_scheduler()?;
        let view = queue.view();
        if !view.available || view.active_global_runs != 0 {
            return Err("Finish or stop active runs before resetting provider context.".into());
        }
        lock_backend(&shared)?.reset_native_provider_context(&project_id, &session_id)
    })
    .await
    .map_err(|error| format!("Provider reset worker failed: {error}"))??;
    super::present_snapshot(seed).await
}

#[tauri::command]
pub(crate) async fn inspect_grok_cli() -> Result<crate::runtime::cli::CliMaintenance, String> {
    tauri::async_runtime::spawn_blocking(crate::runtime::cli::inspect_managed_cli)
        .await
        .map_err(|error| format!("Grok CLI inspection worker failed: {error}"))?
}

#[tauri::command]
pub(crate) async fn update_grok_cli(
    state: State<'_, AppState>,
) -> Result<crate::runtime::cli::CliMaintenance, String> {
    let shared = Arc::clone(&state.backend);
    let queue = lock_backend(&shared)?.queue.clone();
    tauri::async_runtime::spawn_blocking(move || {
        // Hold admission through replacement so a queued send cannot race Update.
        let _scheduling = queue.lock_idle_scheduler().map_err(
            |_| "Finish or stop active runs and wait for cleanup before updating Grok CLI.",
        )?;
        {
            let mut backend = lock_backend(&shared)?;
            backend.prepare_cli_update()?;
        }
        crate::runtime::cli::update_cli()
    })
    .await
    .map_err(|error| format!("Grok CLI update worker failed: {error}"))?
}

#[tauri::command]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri command handlers receive managed State by value as part of the generated IPC ABI"
)]
pub(crate) async fn read_aloud_status(state: State<'_, AppState>) -> Result<ReadAloudView, String> {
    let backend = Arc::clone(&state.backend);
    let availability = tauri::async_runtime::spawn_blocking(move || {
        lock_backend(&backend)?.read_aloud_credential()
    })
    .await
    .map_err(|error| format!("Grok Read Aloud status worker stopped: {error}"))
    .and_then(std::convert::identity);
    Ok(match availability {
        Ok(credential) => state.read_aloud.view(true, None, Some(credential.source())),
        Err(reason) => state.read_aloud.view(false, Some(reason), None),
    })
}

#[tauri::command]
pub(crate) async fn set_read_aloud_auto_read(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<ReadAloudView, String> {
    state.read_aloud.set_auto_read(enabled)?;
    read_aloud_status(state).await
}

#[tauri::command]
pub(crate) async fn read_aloud_synthesize(
    state: State<'_, AppState>,
    text: String,
) -> Result<ReadAloudAudio, String> {
    if state.voice.status().phase == VoicePhase::Recording {
        return Err("Stop Voice input recording before using Grok Read Aloud.".into());
    }
    let backend = Arc::clone(&state.backend);
    let read_aloud = state.read_aloud.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let credential = lock_backend(&backend)?.read_aloud_credential()?;
        read_aloud.synthesize(&credential, &text)
    })
    .await
    .map_err(|error| format!("Grok Read Aloud worker stopped before completing: {error}"))?
}

#[tauri::command]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri command handlers receive managed State by value as part of the generated IPC ABI"
)]
pub(crate) fn read_aloud_stop(state: State<'_, AppState>) {
    state.read_aloud.stop();
}

#[tauri::command]
pub(crate) async fn voice_status(state: State<'_, AppState>) -> Result<VoiceView, String> {
    Ok(state.voice.status())
}

#[tauri::command]
pub(crate) async fn voice_select_model(
    state: State<'_, AppState>,
    model: VoiceModel,
) -> Result<VoiceView, String> {
    state.voice.select_model(model)
}

#[tauri::command]
pub(crate) async fn voice_install_model(
    app: AppHandle,
    state: State<'_, AppState>,
    model: VoiceModel,
) -> Result<VoiceView, String> {
    let (context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (backend.active_event_context()?, backend.events.clone())
    };
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Voice {
            action: VoiceEventAction::ModelInstallRequested,
            model: Some(model.event_id().to_owned()),
        },
    )?;
    let voice = state.voice.clone();
    let progress_app = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        voice.install_model(model, |progress: VoiceProgress| {
            let _ = progress_app.emit(VOICE_EVENT_CHANNEL, progress);
        })
    })
    .await
    .map_err(|error| format!("Voice model worker stopped before completing: {error}"))?;
    match result {
        Ok(view) => {
            record_activity(
                &app,
                &journal,
                context,
                EventPayload::Voice {
                    action: VoiceEventAction::ModelInstalled,
                    model: Some(model.event_id().to_owned()),
                },
            )?;
            Ok(view)
        }
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::Voice {
                    action: VoiceEventAction::Failed,
                    model: Some(model.event_id().to_owned()),
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn voice_start_recording(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<VoiceView, String> {
    state.read_aloud.stop();
    let (project_id, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_project_typed_id()?.as_str().to_owned(),
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    let model = state.voice.status().selected_model;
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Voice {
            action: VoiceEventAction::PermissionRequested,
            model: Some(model.event_id().to_owned()),
        },
    )?;
    let voice = state.voice.clone();
    let result = tauri::async_runtime::spawn_blocking(move || voice.start_recording(project_id))
        .await
        .map_err(|error| format!("Voice recording worker stopped before completing: {error}"))?;
    match result {
        Ok(view) => {
            record_activity(
                &app,
                &journal,
                context,
                EventPayload::Voice {
                    action: VoiceEventAction::RecordingStarted,
                    model: Some(model.event_id().to_owned()),
                },
            )?;
            Ok(view)
        }
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::Voice {
                    action: VoiceEventAction::Failed,
                    model: Some(model.event_id().to_owned()),
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn voice_stop_and_transcribe(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<VoiceTranscript, String> {
    let (project_id, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_project_typed_id()?.as_str().to_owned(),
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    let model = state.voice.status().selected_model;
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Voice {
            action: VoiceEventAction::TranscriptionStarted,
            model: Some(model.event_id().to_owned()),
        },
    )?;
    let voice = state.voice.clone();
    let result =
        tauri::async_runtime::spawn_blocking(move || voice.stop_and_transcribe(&project_id))
            .await
            .map_err(|error| {
                format!("Voice transcription worker stopped before completing: {error}")
            })?;
    match result {
        Ok(transcript) => {
            record_activity(
                &app,
                &journal,
                context,
                EventPayload::Voice {
                    action: VoiceEventAction::TranscriptReady,
                    model: Some(model.event_id().to_owned()),
                },
            )?;
            Ok(transcript)
        }
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::Voice {
                    action: VoiceEventAction::Failed,
                    model: Some(model.event_id().to_owned()),
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn voice_cancel_recording(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<VoiceView, String> {
    let (context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (backend.active_event_context()?, backend.events.clone())
    };
    let model = state.voice.status().selected_model;
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Voice {
            action: VoiceEventAction::RecordingDiscardRequested,
            model: Some(model.event_id().to_owned()),
        },
    )?;
    let view = state.voice.cancel_recording()?;
    record_activity(
        &app,
        &journal,
        context,
        EventPayload::Voice {
            action: VoiceEventAction::RecordingDiscarded,
            model: Some(model.event_id().to_owned()),
        },
    )?;
    Ok(view)
}
#[tauri::command]
pub(crate) async fn select_transport(
    state: State<'_, AppState>,
    transport: RuntimeTransport,
) -> Result<AppSnapshot, String> {
    with_backend_snapshot(state, move |backend| backend.select_transport(transport)).await
}

#[tauri::command]
pub(crate) async fn refresh_account(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let event_app = app.clone();
    let snapshot = with_account_probe(state, move |backend| {
        backend.refresh_account(&|event| {
            emit_runtime_event(&event_app, event);
            Ok(())
        })
    })
    .await?;
    if snapshot.account.connected {
        schedule_available(&app, &shared, None, false)?;
        return current_snapshot(&shared).await;
    }
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn connect_account(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let event_app = app.clone();
    let snapshot = with_account_probe(state, move |backend| {
        backend.connect_account(&|event| {
            emit_runtime_event(&event_app, event);
            Ok(())
        })
    })
    .await?;
    if snapshot.account.connected {
        schedule_available(&app, &shared, None, false)?;
        return current_snapshot(&shared).await;
    }
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn connect_saved_xai_key(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let event_app = app.clone();
    let snapshot = with_account_probe(state, move |backend| {
        backend.connect_saved_xai_key(&|event| {
            emit_runtime_event(&event_app, event);
            Ok(())
        })
    })
    .await?;
    if snapshot.account.connected {
        schedule_available(&app, &shared, None, false)?;
        return current_snapshot(&shared).await;
    }
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn reconnect_authorized_account(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let event_app = app.clone();
    let snapshot = with_account_probe(state, move |backend| {
        backend.reconnect_authorized(&|event| {
            emit_runtime_event(&event_app, event);
            Ok(())
        })
    })
    .await?;
    if snapshot.account.connected {
        schedule_available(&app, &shared, None, false)?;
        return current_snapshot(&shared).await;
    }
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn set_auto_reconnect(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<AppSnapshot, String> {
    with_backend_snapshot(state, move |backend| backend.set_auto_reconnect(enabled)).await
}

#[tauri::command]
pub(crate) async fn acknowledge_account_onboarding(
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    with_backend_snapshot(state, Backend::acknowledge_account_onboarding).await
}

#[tauri::command]
pub(crate) async fn login_grok_cli(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let shared = Arc::clone(&state.backend);
    let oauth_app = app.clone();
    let oauth = tauri::async_runtime::spawn_blocking(move || {
        run_grok_cli_oauth(|phase| {
            let (phase, status, detail) = match phase {
                GrokCliOAuthPhase::OpeningBrowser => (
                    "opening_browser",
                    "Opening browser…",
                    "Starting the official `grok login --oauth` flow. No hidden terminal is used.",
                ),
                GrokCliOAuthPhase::WaitingForSignIn => (
                    "waiting_for_sign_in",
                    "Waiting for sign-in…",
                    "Complete the Grok sign-in in your browser. The app will verify the live Chat path afterward.",
                ),
            };
            emit_runtime_event(
                &oauth_app,
                RuntimeEvent::AccountOnboarding {
                    phase: phase.into(),
                    status: status.into(),
                    detail: detail.into(),
                    sanitized_log: None,
                },
            );
        })
    })
        .await
        .map_err(|error| format!("Grok CLI OAuth worker stopped before completing: {error}"))?;
    let oauth = match oauth {
        Ok(oauth) => oauth,
        Err(failure) => {
            emit_runtime_event(
                &app,
                RuntimeEvent::AccountOnboarding {
                    phase: "failed".into(),
                    status: "Sign-in failed".into(),
                    detail: failure.message.clone(),
                    sanitized_log: Some(failure.sanitized_log),
                },
            );
            return Err(failure.message);
        }
    };
    emit_runtime_event(
        &app,
        RuntimeEvent::AccountOnboarding {
            phase: "verifying".into(),
            status: "Verifying…".into(),
            detail:
                "OAuth finished. Verifying one live prompt through the strict GrokCliAcp Chat path."
                    .into(),
            sanitized_log: Some(oauth.sanitized_log.clone()),
        },
    );
    let verification_app = app.clone();
    let result = with_account_probe(state, move |backend| {
        backend.select_transport(RuntimeTransport::GrokCliAcp)?;
        backend.connect_account(&|event| {
            emit_runtime_event(&verification_app, event);
            Ok(())
        })
    })
    .await;
    match &result {
        Ok(snapshot) if snapshot.account.connected => emit_runtime_event(
            &app,
            RuntimeEvent::AccountOnboarding {
                phase: "connected".into(),
                status: "Connected".into(),
                detail: "GrokCliAcp completed its live Chat-path connection check.".into(),
                sanitized_log: Some(oauth.sanitized_log),
            },
        ),
        Ok(_) => {}
        Err(error) => emit_runtime_event(
            &app,
            RuntimeEvent::AccountOnboarding {
                phase: "failed".into(),
                status: "Verification failed".into(),
                detail: error.clone(),
                sanitized_log: Some(oauth.sanitized_log),
            },
        ),
    }
    let snapshot = result?;
    if snapshot.account.connected {
        schedule_available(&app, &shared, None, false)?;
        return current_snapshot(&shared).await;
    }
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn disconnect_account(state: State<'_, AppState>) -> Result<AppSnapshot, String> {
    state.read_aloud.stop();
    let shared = Arc::clone(&state.backend);
    let queue = lock_backend(&shared)?.queue.clone();
    let browser = state.browser.clone();
    let capture = state.capture.clone();
    let desktop = state.desktop.clone();
    let mut failures = Vec::new();
    if let Err(error) = queue.request_stop_all() {
        failures.push(error);
    }
    if let Err(error) = browser.stop("Browser stopped because Account disconnected.") {
        failures.push(error);
    }
    if let Err(error) = capture.stop("Capture stopped because Account disconnected.") {
        failures.push(error);
    }
    if let Err(error) = desktop.stop("Desktop Control stopped because Account disconnected.") {
        failures.push(error);
    }
    let disconnected = with_backend_snapshot(state, Backend::disconnect_account).await;
    match disconnected {
        Ok(snapshot) if failures.is_empty() => Ok(snapshot),
        Ok(_) => Err(format!(
            "Account is Disconnected, but one or more active-run/capability shutdown controls reported an error: {}",
            failures.join(" | ")
        )),
        Err(error) => {
            failures.push(error);
            Err(format!(
                "Account state was cleared before teardown; teardown reported: {}",
                failures.join(" | ")
            ))
        }
    }
}

#[tauri::command]
pub(crate) async fn configure_xai_key(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSnapshot, String> {
    let Some(key) = prompt_xai_key(app.clone()).await? else {
        return with_backend_snapshot(state, |backend| Ok(backend.snapshot_seed())).await;
    };
    let shared = Arc::clone(&state.backend);
    let event_app = app.clone();
    let snapshot = with_backend_snapshot(state, move |backend| {
        backend.connect_new_xai_key(&key, &|event| {
            emit_runtime_event(&event_app, event);
            Ok(())
        })
    })
    .await?;
    if snapshot.account.connected {
        schedule_available(&app, &shared, None, false)?;
        return current_snapshot(&shared).await;
    }
    Ok(snapshot)
}

#[tauri::command]
pub(crate) async fn delete_xai_key(state: State<'_, AppState>) -> Result<AppSnapshot, String> {
    with_backend_snapshot(state, Backend::delete_xai_key).await
}
