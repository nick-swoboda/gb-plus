//! Native secure API-key entry; secret text never enters `WebView` IPC.

use tauri::AppHandle;

use super::keychain::SecretBytes;

#[cfg(target_os = "macos")]
fn prompt_xai_key_on_main_thread() -> Result<Option<SecretBytes>, String> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSAlert, NSAlertFirstButtonReturn, NSSecureTextField};
    use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

    let marker = MainThreadMarker::new()
        .ok_or_else(|| "The API-key dialog must run on the macOS main thread.".to_owned())?;
    let alert = NSAlert::new(marker);
    alert.setMessageText(&NSString::from_str("Connect xAI API key"));
    alert.setInformativeText(&NSString::from_str(
        "The key is stored directly in macOS Keychain. It is not sent through the web interface, written to app JSON, or passed to Grok CLI.",
    ));
    let _ = alert.addButtonWithTitle(&NSString::from_str("Save and verify"));
    let _ = alert.addButtonWithTitle(&NSString::from_str("Cancel"));

    let field = NSSecureTextField::new(marker);
    field.setFrame(NSRect::new(
        NSPoint::new(0.0, 0.0),
        NSSize::new(420.0, 24.0),
    ));
    field.setPlaceholderString(Some(&NSString::from_str("xai-…")));
    alert.setAccessoryView(Some(&field));

    if alert.runModal() != NSAlertFirstButtonReturn {
        return Ok(None);
    }
    let key = field.stringValue().to_string().into_bytes();
    SecretBytes::new(key).map(Some)
}

/// Opens an `AppKit` secure-text dialog and returns request-scoped bytes.
pub(crate) async fn prompt_xai_key(app: AppHandle) -> Result<Option<SecretBytes>, String> {
    #[cfg(target_os = "macos")]
    {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        app.run_on_main_thread(move || {
            let _ = sender.send(prompt_xai_key_on_main_thread());
        })
        .map_err(|error| format!("cannot open the macOS API-key dialog: {error}"))?;

        tauri::async_runtime::spawn_blocking(move || {
            receiver
                .recv()
                .map_err(|_| "The API-key dialog stopped without a result.".to_owned())?
        })
        .await
        .map_err(|error| format!("API-key dialog worker stopped before completing: {error}"))?
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        Err("XaiKeychain secure entry is available only on macOS.".into())
    }
}
