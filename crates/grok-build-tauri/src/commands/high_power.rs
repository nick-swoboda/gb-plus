//! Browser, Capture, and Desktop Control commands.

use super::{
    AppHandle, AppState, BROWSER_EVENT_CHANNEL, BrowserActionView, BrowserAssetProgress,
    BrowserEventAction, BrowserMode, BrowserPhase, BrowserView, CaptureEventAction, CapturePhase,
    CaptureView, DESKTOP_FOCUS_COUNTDOWN, DesktopEventAction, DesktopPhase, DesktopView, Emitter,
    EventContext, EventJournal, EventPayload, State, lock_backend, record_activity,
};

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri extracts managed State by value.
pub(crate) fn desktop_status(state: State<'_, AppState>) -> DesktopView {
    state.desktop.status()
}

#[tauri::command]
pub(crate) async fn desktop_select_target(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DesktopView, String> {
    let (project_id, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_project_typed_id()?.as_str().to_owned(),
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::DesktopControl {
            action: DesktopEventAction::TargetSelectionRequested,
            operation: None,
            pid: None,
            window_id: None,
            display_id: None,
        },
    )?;
    let desktop = state.desktop.clone();
    let expected_project_id = project_id.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        std::thread::sleep(DESKTOP_FOCUS_COUNTDOWN);
        desktop.select_frontmost(project_id)
    })
    .await
    .map_err(|error| format!("Desktop target-selection worker stopped: {error}"))?;
    match result {
        Ok(view)
            if view.phase == DesktopPhase::TargetSelected
                && view.project_id.as_deref() == Some(expected_project_id.as_str()) =>
        {
            record_desktop_activity(
                &app,
                &journal,
                context,
                DesktopEventAction::TargetSelected,
                None,
                &view,
            )?;
            Ok(view)
        }
        Ok(_) => Err(
            "Desktop target selection was superseded before its Activity event; no target-selected success was recorded."
                .into(),
        ),
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::DesktopControl {
                    action: DesktopEventAction::Refused,
                    operation: Some("target_selection".into()),
                    pid: None,
                    window_id: None,
                    display_id: None,
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn desktop_arm(
    app: AppHandle,
    state: State<'_, AppState>,
    window_id: u32,
) -> Result<DesktopView, String> {
    let (project_id, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_project_typed_id()?.as_str().to_owned(),
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::DesktopControl {
            action: DesktopEventAction::PermissionRequested,
            operation: Some("arm".into()),
            pid: None,
            window_id: Some(window_id),
            display_id: None,
        },
    )?;
    let desktop = state.desktop.clone();
    let expected_project_id = project_id.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        std::thread::sleep(DESKTOP_FOCUS_COUNTDOWN);
        desktop.arm_selected(&project_id, window_id)
    })
    .await
    .map_err(|error| format!("Desktop arm worker stopped: {error}"))?;
    match result {
        Ok(view)
            if view.phase == DesktopPhase::Armed
                && view.project_id.as_deref() == Some(expected_project_id.as_str()) =>
        {
            record_desktop_activity(
                &app,
                &journal,
                context,
                DesktopEventAction::Armed,
                Some("arm"),
                &view,
            )?;
            Ok(view)
        }
        Ok(view)
            if view.phase == DesktopPhase::TargetSelected
                && view.project_id.as_deref() == Some(expected_project_id.as_str())
                && view
                    .pending_target
                    .as_ref()
                    .is_some_and(|target| target.window_id == window_id)
                && view.last_refusal.is_none() =>
        {
            Ok(view)
        }
        Ok(_) => Err(
            "Desktop Control Arm was superseded before its Activity event; no Armed or permission-pending state was recorded."
                .into(),
        ),
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::DesktopControl {
                    action: DesktopEventAction::Refused,
                    operation: Some("arm".into()),
                    pid: None,
                    window_id: Some(window_id),
                    display_id: None,
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn desktop_stop(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DesktopView, String> {
    let (context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_event_context().unwrap_or_default(),
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::DesktopControl {
            action: DesktopEventAction::StopRequested,
            operation: None,
            pid: None,
            window_id: None,
            display_id: None,
        },
    )?;
    let desktop = state.desktop.clone();
    let view = tauri::async_runtime::spawn_blocking(move || {
        desktop.stop("User selected the visible Desktop Control Stop control.")
    })
    .await
    .map_err(|error| format!("Desktop stop worker stopped: {error}"))??;
    record_desktop_activity(
        &app,
        &journal,
        context,
        DesktopEventAction::Stopped,
        None,
        &view,
    )?;
    Ok(view)
}

fn record_desktop_activity(
    app: &AppHandle,
    journal: &EventJournal,
    context: EventContext,
    action: DesktopEventAction,
    operation: Option<&str>,
    view: &DesktopView,
) -> Result<(), String> {
    let target = view.target.as_ref().or(view.pending_target.as_ref());
    record_activity(
        app,
        journal,
        context,
        EventPayload::DesktopControl {
            action,
            operation: operation.map(str::to_owned),
            pid: target.map(|target| target.pid),
            window_id: target.map(|target| target.window_id),
            display_id: target.map(|target| target.display_id),
        },
    )
    .map(|_| ())
}

#[tauri::command]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri command handlers receive managed State by value as part of the generated IPC ABI"
)]
pub(crate) fn capture_status(state: State<'_, AppState>) -> CaptureView {
    state.capture.status()
}

#[tauri::command]
pub(crate) async fn capture_arm(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CaptureView, String> {
    let (project_id, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_project_typed_id()?.as_str().to_owned(),
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Capture {
            action: CaptureEventAction::PermissionRequested,
            display_id: None,
            width: None,
            height: None,
            byte_count: None,
            sha256: None,
        },
    )?;
    let capture = state.capture.clone();
    let expected_project_id = project_id.clone();
    let result = tauri::async_runtime::spawn_blocking(move || capture.arm(project_id))
        .await
        .map_err(|error| format!("Capture arm worker stopped before completing: {error}"))?;
    match result {
        Ok(view)
            if view.phase == CapturePhase::Armed
                && view.project_id.as_deref() == Some(expected_project_id.as_str()) =>
        {
            record_capture_activity(&app, &journal, context, CaptureEventAction::Armed, &view)?;
            Ok(view)
        }
        Ok(_) => Err(
            "Capture Arm was superseded before its Activity event; no Armed success was recorded."
                .into(),
        ),
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::Capture {
                    action: CaptureEventAction::Refused,
                    display_id: None,
                    width: None,
                    height: None,
                    byte_count: None,
                    sha256: None,
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn capture_take(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CaptureView, String> {
    let (project_id, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_project_typed_id()?.as_str().to_owned(),
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    let capture = state.capture.clone();
    let result = tauri::async_runtime::spawn_blocking(move || capture.capture_now(&project_id))
        .await
        .map_err(|error| format!("Capture still worker stopped before completing: {error}"))?;
    match result {
        Ok(view) => {
            record_capture_activity(
                &app,
                &journal,
                context,
                CaptureEventAction::FrameCaptured,
                &view,
            )?;
            Ok(view)
        }
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::Capture {
                    action: CaptureEventAction::Refused,
                    display_id: None,
                    width: None,
                    height: None,
                    byte_count: None,
                    sha256: None,
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn capture_stop(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CaptureView, String> {
    let (context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_event_context().unwrap_or_default(),
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Capture {
            action: CaptureEventAction::StopRequested,
            display_id: None,
            width: None,
            height: None,
            byte_count: None,
            sha256: None,
        },
    )?;
    let capture = state.capture.clone();
    let view = tauri::async_runtime::spawn_blocking(move || {
        capture.stop("User selected the visible Capture Stop control.")
    })
    .await
    .map_err(|error| format!("Capture stop worker stopped before completing: {error}"))??;
    record_capture_activity(&app, &journal, context, CaptureEventAction::Stopped, &view)?;
    Ok(view)
}

fn record_capture_activity(
    app: &AppHandle,
    journal: &EventJournal,
    context: EventContext,
    action: CaptureEventAction,
    view: &CaptureView,
) -> Result<(), String> {
    let frame = matches!(action, CaptureEventAction::FrameCaptured);
    record_activity(
        app,
        journal,
        context,
        EventPayload::Capture {
            action,
            display_id: view.display.as_ref().map(|display| display.id),
            width: if frame {
                view.frame_width
            } else {
                view.display.as_ref().map(|display| display.width)
            },
            height: if frame {
                view.frame_height
            } else {
                view.display.as_ref().map(|display| display.height)
            },
            byte_count: view.frame_byte_count,
            sha256: view.frame_sha256.clone(),
        },
    )
    .map(|_| ())
}
#[tauri::command]
pub(crate) async fn browser_status(state: State<'_, AppState>) -> Result<BrowserView, String> {
    Ok(state.browser.status())
}

#[tauri::command]
pub(crate) async fn browser_install_runtime(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BrowserView, String> {
    let (context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_event_context().unwrap_or_default(),
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Browser {
            action: BrowserEventAction::RuntimeInstallRequested,
            mode: None,
        },
    )?;
    let browser = state.browser.clone();
    let progress_app = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        browser.install_runtime(|progress: BrowserAssetProgress| {
            let _ = progress_app.emit(BROWSER_EVENT_CHANNEL, progress);
        })
    })
    .await
    .map_err(|error| format!("Browser runtime worker stopped before completing: {error}"))?;
    match result {
        Ok(view) => {
            record_activity(
                &app,
                &journal,
                context,
                EventPayload::Browser {
                    action: BrowserEventAction::RuntimeInstalled,
                    mode: None,
                },
            )?;
            Ok(view)
        }
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::Browser {
                    action: BrowserEventAction::Failed,
                    mode: None,
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn browser_arm(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: BrowserMode,
) -> Result<BrowserView, String> {
    let (project_id, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_project_typed_id()?.as_str().to_owned(),
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    let mode_id = match mode {
        BrowserMode::InApp => "in_app",
        BrowserMode::Headed => "headed",
    }
    .to_owned();
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Browser {
            action: BrowserEventAction::ArmRequested,
            mode: Some(mode_id.clone()),
        },
    )?;
    let browser = state.browser.clone();
    let expected_project_id = project_id.clone();
    let result = tauri::async_runtime::spawn_blocking(move || browser.arm(project_id, mode))
        .await
        .map_err(|error| format!("Browser arm worker stopped before completing: {error}"))?;
    match result {
        Ok(view)
            if view.phase == BrowserPhase::Armed
                && view.project_id.as_deref() == Some(expected_project_id.as_str()) =>
        {
            record_activity(
                &app,
                &journal,
                context,
                EventPayload::Browser {
                    action: BrowserEventAction::Armed,
                    mode: Some(mode_id),
                },
            )?;
            Ok(view)
        }
        Ok(_) => Err(
            "Browser Arm was superseded before its Activity event; no Armed success was recorded."
                .into(),
        ),
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::Browser {
                    action: BrowserEventAction::Failed,
                    mode: Some(mode_id),
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn browser_stop(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BrowserView, String> {
    let (context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_event_context().unwrap_or_default(),
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    record_activity(
        &app,
        &journal,
        context.clone(),
        EventPayload::Browser {
            action: BrowserEventAction::StopRequested,
            mode: None,
        },
    )?;
    let browser = state.browser.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        browser.stop("User selected the visible Browser Stop control.")
    })
    .await
    .map_err(|error| format!("Browser stop worker stopped before completing: {error}"))?;
    match result {
        Ok(view) => {
            record_activity(
                &app,
                &journal,
                context,
                EventPayload::Browser {
                    action: BrowserEventAction::Stopped,
                    mode: None,
                },
            )?;
            Ok(view)
        }
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::Browser {
                    action: BrowserEventAction::Failed,
                    mode: None,
                },
            );
            Err(error)
        }
    }
}

#[tauri::command]
pub(crate) async fn browser_navigate(
    app: AppHandle,
    state: State<'_, AppState>,
    url: String,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::Navigated,
        move |browser, project| browser.navigate_user(&project, &url),
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_inspect(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::Inspected,
        |browser, project| browser.inspect_user(&project),
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_click(
    app: AppHandle,
    state: State<'_, AppState>,
    node_id: u64,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::Clicked,
        move |browser, project| browser.click_user(&project, node_id),
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_type(
    app: AppHandle,
    state: State<'_, AppState>,
    node_id: u64,
    text: String,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::Typed,
        move |browser, project| browser.type_user(&project, node_id, &text),
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_key(
    app: AppHandle,
    state: State<'_, AppState>,
    key: String,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::KeySent,
        move |browser, project| browser.key_user(&project, &key),
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_scroll(
    app: AppHandle,
    state: State<'_, AppState>,
    delta_y: i64,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::Scrolled,
        move |browser, project| browser.scroll_user(&project, delta_y),
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_pointer(
    app: AppHandle,
    state: State<'_, AppState>,
    interaction_token: String,
    x: f64,
    y: f64,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::UserControlFocused,
        move |browser, project| browser.pointer_user(&project, &interaction_token, x, y),
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_insert_text(
    app: AppHandle,
    state: State<'_, AppState>,
    interaction_token: String,
    text: String,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::Typed,
        move |browser, project| browser.insert_text_user(&project, &interaction_token, &text),
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_focused_key(
    app: AppHandle,
    state: State<'_, AppState>,
    interaction_token: String,
    key: String,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::KeySent,
        move |browser, project| browser.focused_key_user(&project, &interaction_token, &key),
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_focused_scroll(
    app: AppHandle,
    state: State<'_, AppState>,
    interaction_token: String,
    x: f64,
    y: f64,
    delta_y: i64,
) -> Result<BrowserActionView, String> {
    run_browser_user_action(
        app,
        state,
        BrowserEventAction::Scrolled,
        move |browser, project| {
            browser.focused_scroll_user(&project, &interaction_token, x, y, delta_y)
        },
    )
    .await
}

#[tauri::command]
pub(crate) async fn browser_release_user_control(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BrowserView, String> {
    let (project, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_project_typed_id()?.as_str().to_owned(),
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    let view = state.browser.release_user_control(&project)?;
    record_activity(
        &app,
        &journal,
        context,
        EventPayload::Browser {
            action: BrowserEventAction::UserControlReleased,
            mode: Some("in_app".into()),
        },
    )?;
    Ok(view)
}

async fn run_browser_user_action(
    app: AppHandle,
    state: State<'_, AppState>,
    action: BrowserEventAction,
    operation: impl FnOnce(crate::browser::BrowserManager, String) -> Result<BrowserActionView, String>
    + Send
    + 'static,
) -> Result<BrowserActionView, String> {
    let (project_id, context, journal) = {
        let backend = lock_backend(&state.backend)?;
        (
            backend.active_project_typed_id()?.as_str().to_owned(),
            backend.active_event_context()?,
            backend.events.clone(),
        )
    };
    journal.ensure_available()?;
    let browser = state.browser.clone();
    let result = tauri::async_runtime::spawn_blocking(move || operation(browser, project_id))
        .await
        .map_err(|error| format!("Browser action worker stopped before completing: {error}"))?;
    match result {
        Ok(view) => {
            record_activity(
                &app,
                &journal,
                context,
                EventPayload::Browser { action, mode: None },
            )?;
            Ok(view)
        }
        Err(error) => {
            let _ = record_activity(
                &app,
                &journal,
                context,
                EventPayload::Browser {
                    action: BrowserEventAction::Refused,
                    mode: None,
                },
            );
            Err(error)
        }
    }
}
