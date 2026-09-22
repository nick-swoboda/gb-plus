//! Diagnostic export commands and high-power-state projection.

use super::{
    AppHandle, AppState, BrowserPhase, BrowserView, CapturePermission, CapturePhase, CaptureView,
    DesktopPermission, DesktopPhase, DesktopView, DiagnosticEventAction, DiagnosticExportView,
    EventPayload, State, default_diagnostic_filename, export_diagnostic_zip, lock_backend,
    record_activity,
};

#[cfg(target_os = "macos")]
fn choose_diagnostic_destination_on_main_thread(
    default_name: &str,
) -> Result<Option<String>, String> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSModalResponseOK, NSSavePanel};
    use objc2_foundation::NSString;

    let marker = MainThreadMarker::new()
        .ok_or_else(|| "The diagnostic save panel must run on the main thread.".to_owned())?;
    let panel = NSSavePanel::savePanel(marker);
    panel.setCanCreateDirectories(true);
    panel.setExtensionHidden(false);
    panel.setNameFieldStringValue(&NSString::from_str(default_name));
    panel.setPrompt(Some(&NSString::from_str("Export")));
    panel.setMessage(Some(&NSString::from_str(
        "Export a default-safe GB Plus support archive. Existing files are never overwritten.",
    )));
    if panel.runModal() != NSModalResponseOK {
        return Ok(None);
    }
    let url = panel
        .URL()
        .ok_or_else(|| "macOS did not return a diagnostic export location.".to_owned())?;
    let path = url
        .path()
        .ok_or_else(|| "The selected diagnostic location is not a local file.".to_owned())?
        .to_string();
    if path.trim().is_empty() {
        return Err("macOS returned an empty diagnostic export path.".into());
    }
    Ok(Some(path))
}

async fn choose_diagnostic_destination(
    app: AppHandle,
    default_name: String,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        app.run_on_main_thread(move || {
            let _ = sender.send(choose_diagnostic_destination_on_main_thread(&default_name));
        })
        .map_err(|error| format!("cannot open the diagnostic save panel: {error}"))?;
        tauri::async_runtime::spawn_blocking(move || {
            receiver
                .recv()
                .map_err(|_| "The diagnostic save panel stopped without a result.".to_owned())?
        })
        .await
        .map_err(|error| format!("diagnostic save-panel worker stopped: {error}"))?
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (app, default_name);
        Err("Diagnostic export is available only on macOS in this release.".into())
    }
}

fn apply_high_power_diagnostics(
    input: &mut crate::diagnostics::DiagnosticInput,
    browser: &BrowserView,
    capture: &CaptureView,
    desktop: &DesktopView,
) {
    let browser_state = match browser.phase {
        BrowserPhase::Off => "Off",
        BrowserPhase::Starting => "Starting",
        BrowserPhase::Armed => "On",
        BrowserPhase::Stopping => "Stopping",
        BrowserPhase::Failed => "Error",
    };
    input.set_capability(
        "Browser",
        browser_state,
        browser.runtime.installed,
        if browser.runtime.installed {
            "Exact Chrome runtime is installed; grant state is recorded without page, profile, cookie, or screenshot content."
        } else {
            "Exact Chrome runtime is not installed; Browser remains unavailable."
        },
    );
    let capture_state = match capture.phase {
        CapturePhase::Off | CapturePhase::Arming => "Off",
        CapturePhase::Armed | CapturePhase::Capturing | CapturePhase::Ready => "On",
        CapturePhase::Failed => "Error",
    };
    let capture_permission = match capture.permission {
        CapturePermission::Authorized => "Authorized",
        CapturePermission::NotDeterminedOrDenied => "Not determined or denied",
        CapturePermission::Unavailable => "Unavailable",
    };
    input.set_capability(
        "Capture",
        capture_state,
        capture.permission != CapturePermission::Unavailable,
        &format!(
            "macOS Screen Recording: {capture_permission}; raw pixels and PNG content are omitted."
        ),
    );
    let desktop_state = match desktop.phase {
        DesktopPhase::Off
        | DesktopPhase::Selecting
        | DesktopPhase::TargetSelected
        | DesktopPhase::Arming => "Off",
        DesktopPhase::Armed | DesktopPhase::Acting => "On",
        DesktopPhase::Failed => "Error",
    };
    let desktop_permission = match desktop.permission {
        DesktopPermission::Authorized => "Authorized",
        DesktopPermission::NotDeterminedOrDenied => "Not determined or denied",
        DesktopPermission::Unavailable => "Unavailable",
    };
    input.set_capability(
        "Desktop Control",
        desktop_state,
        desktop.permission != DesktopPermission::Unavailable,
        &format!(
            "macOS Accessibility: {desktop_permission}; target titles, input text, and event content are omitted."
        ),
    );
}

#[tauri::command]
pub(crate) async fn export_diagnostics(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<DiagnosticExportView>, String> {
    let Some(destination) =
        choose_diagnostic_destination(app.clone(), default_diagnostic_filename()).await?
    else {
        return Ok(None);
    };
    let browser_view = state.browser.status();
    let capture_view = state.capture.status();
    let desktop_view = state.desktop.status();
    let (mut input, journal, context) = {
        let backend = lock_backend(&state.backend)?;
        let journal = backend.events.clone();
        journal.ensure_available()?;
        let context = backend.active_event_context().unwrap_or_default();
        record_activity(
            &app,
            &journal,
            context.clone(),
            EventPayload::Diagnostic {
                action: DiagnosticEventAction::ExportRequested,
                entry_count: None,
            },
        )?;
        (backend.diagnostic_input(), journal, context)
    };
    apply_high_power_diagnostics(&mut input, &browser_view, &capture_view, &desktop_view);
    let activity_app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let exported = export_diagnostic_zip(&input, std::path::Path::new(&destination))?;
        record_activity(
            &activity_app,
            &journal,
                context,
                EventPayload::Diagnostic {
                    action: DiagnosticEventAction::ExportCompleted,
                    entry_count: Some(exported.entry_count),
                },
            )
            .map_err(|error| {
                format!(
                    "The diagnostic ZIP was exported, but its Activity terminal event could not be persisted: {error}"
                )
            })?;
        Ok(Some(exported))
    })
    .await
    .map_err(|error| format!("diagnostic export worker stopped: {error}"))?
}
