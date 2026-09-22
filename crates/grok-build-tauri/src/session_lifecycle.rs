//! Fail-closed macOS lock/unlock integration for live Account credentials.

#![allow(unsafe_code)] // Audited ObjC notification boundary; no workspace or credential bytes cross it.

use std::ptr::NonNull;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{NSObjectProtocol, ProtocolObject};
use objc2_app_kit::{
    NSWorkspace, NSWorkspaceSessionDidBecomeActiveNotification,
    NSWorkspaceSessionDidResignActiveNotification,
};
use objc2_foundation::{NSNotification, NSNotificationCenter};
use tauri::{AppHandle, Emitter as _, Manager as _};

use crate::backend::AppState;
use crate::commands::{
    SNAPSHOT_EVENT_CHANNEL, current_snapshot, emit_runtime_event, lock_backend, schedule_available,
};
use crate::runtime::types::RuntimeEvent;

/// Retains the opaque notification tokens for the lifetime of the app.
pub(crate) struct SessionLifecycle {
    center: Retained<NSNotificationCenter>,
    observers: Vec<Retained<ProtocolObject<dyn NSObjectProtocol>>>,
}

// SAFETY: NSWorkspace's notification center is thread-safe. These retained
// objects are opaque observer handles used only for removal during Drop.
unsafe impl Send for SessionLifecycle {}
// SAFETY: Same invariant as the Send implementation; no observer data is read.
unsafe impl Sync for SessionLifecycle {}

impl SessionLifecycle {
    pub(crate) fn install(app: AppHandle) -> Self {
        let center = NSWorkspace::sharedWorkspace().notificationCenter();
        let mut observers = Vec::with_capacity(2);

        let resign_app = app.clone();
        let resign = RcBlock::new(move |_: NonNull<NSNotification>| {
            let app = resign_app.clone();
            let persisted_stop_intents = persist_session_resign_intent(&app);
            tauri::async_runtime::spawn_blocking(move || {
                if let Err(reason) = handle_session_resigned(&app, persisted_stop_intents) {
                    emit_runtime_event(&app, RuntimeEvent::Error(reason));
                }
            });
        });
        // SAFETY: The notification name and center are AppKit-owned, the block
        // is 'static, and the returned token is retained until Drop.
        observers.push(unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSWorkspaceSessionDidResignActiveNotification),
                None,
                None,
                &resign,
            )
        });

        let active_app = app;
        let active = RcBlock::new(move |_: NonNull<NSNotification>| {
            let app = active_app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(reason) = handle_session_became_active(&app).await {
                    emit_runtime_event(&app, RuntimeEvent::Error(reason));
                }
            });
        });
        // SAFETY: Same observer lifetime and AppKit ownership invariants as the
        // resign observer above.
        observers.push(unsafe {
            center.addObserverForName_object_queue_usingBlock(
                Some(NSWorkspaceSessionDidBecomeActiveNotification),
                None,
                None,
                &active,
            )
        });

        Self { center, observers }
    }
}

impl Drop for SessionLifecycle {
    fn drop(&mut self) {
        for observer in &self.observers {
            // SAFETY: Every token came from this exact notification center and
            // remains retained until this removal.
            unsafe { self.center.removeObserver(observer.as_ref()) };
        }
    }
}

fn persist_session_resign_intent(app: &AppHandle) -> Result<Vec<crate::contracts::RunId>, String> {
    let state = app.state::<AppState>();
    let queue = {
        let backend = lock_backend(&state.backend)?;
        backend.queue.clone()
    };
    let _scheduler = queue.lock_scheduler()?;
    queue.set_lifecycle_suspended(true);
    // This sync is the authorization point: no cancellation or capability
    // effect may run until every active run has durable StopRequested intent.
    queue.persist_stop_all_intents()
}

fn handle_session_resigned(
    app: &AppHandle,
    persisted_stop_intents: Result<Vec<crate::contracts::RunId>, String>,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    execute_session_resign_policy(
        persisted_stop_intents,
        |run_ids| {
            let queue = lock_backend(&state.backend)?.queue.clone();
            queue.cancel_run_ids(run_ids)
        },
        || revoke_session_security(app, &state),
    )
}

fn revoke_session_security(app: &AppHandle, state: &AppState) -> Result<(), String> {
    let mut failures = Vec::new();
    state.read_aloud.stop();
    if let Err(reason) = state
        .browser
        .stop("Browser stopped because the macOS session was locked.")
    {
        failures.push(reason);
    }
    if let Err(reason) = state
        .capture
        .stop("Capture grant cleared because the macOS session was locked.")
    {
        failures.push(reason);
    }
    if let Err(reason) = state
        .desktop
        .stop("Desktop Control grant cleared because the macOS session was locked.")
    {
        failures.push(reason);
    }
    let seed = {
        let mut backend = lock_backend(&state.backend)?;
        match backend.suspend_account_for_lock() {
            Ok(seed) => seed,
            Err(reason) => {
                failures.push(reason);
                backend.snapshot_seed()
            }
        }
    };
    let snapshot = seed.present_current();
    let _ = app.emit(SNAPSHOT_EVENT_CHANNEL, snapshot);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "one or more credential/capability revocations failed closed: {}",
            failures.join(" | ")
        ))
    }
}

fn execute_session_resign_policy<C, R>(
    persisted_stop_intents: Result<Vec<crate::contracts::RunId>, String>,
    cancel_runs: C,
    revoke_security: R,
) -> Result<(), String>
where
    C: FnOnce(&[crate::contracts::RunId]) -> Result<(), String>,
    R: FnOnce() -> Result<(), String>,
{
    let mut failures = Vec::new();
    match persisted_stop_intents {
        Ok(run_ids) => {
            if let Err(reason) = cancel_runs(&run_ids) {
                failures.push(reason);
            }
        }
        Err(reason) => failures.push(format!(
            "durable Stop intent could not be persisted ({reason}); active-run cancellation was skipped rather than applied without durable intent"
        )),
    }
    // Credential leases and high-power grants must not survive a session lock,
    // even when the queue store itself is unavailable. This revocation does not
    // claim a run outcome or replay/complete any queue item.
    if let Err(reason) = revoke_security() {
        failures.push(reason);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "macOS lock handling failed closed: {}",
            failures.join(" | ")
        ))
    }
}

async fn handle_session_became_active(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let shared = state.backend.clone();
    let queue = lock_backend(&state.backend)?.queue.clone();
    let event_app = app.clone();
    let worker = tauri::async_runtime::spawn_blocking(move || {
        let (initial_seed, should_reconnect) =
            lock_backend(&shared)?.begin_account_unlock_reconnect()?;
        let initial = initial_seed.present_current();
        let _ = event_app.emit(SNAPSHOT_EVENT_CHANNEL, initial.clone());
        if !should_reconnect {
            return Ok(initial);
        }
        let seed = lock_backend(&shared)?.finish_account_unlock_reconnect(&|event| {
            emit_runtime_event(&event_app, event);
            Ok(())
        })?;
        Ok(seed.present_current())
    })
    .await;
    queue.set_lifecycle_suspended(false);
    let snapshot = match worker {
        Ok(Ok(snapshot)) => snapshot,
        Ok(Err(reason)) => {
            let state = app.state::<AppState>();
            if let Ok(snapshot) = current_snapshot(&state.backend).await {
                let _ = app.emit(SNAPSHOT_EVENT_CHANNEL, snapshot);
            }
            return Err(reason);
        }
        Err(error) => {
            return Err(format!("macOS unlock reconnect worker stopped: {error}"));
        }
    };
    let _ = app.emit(SNAPSHOT_EVENT_CHANNEL, snapshot.clone());
    if snapshot.account.connected {
        let state = app.state::<AppState>();
        schedule_available(app, &state.backend, None, false)?;
        let current = current_snapshot(&state.backend).await?;
        let _ = app.emit(SNAPSHOT_EVENT_CHANNEL, current);
    }
    Ok(())
}

#[cfg(test)]
#[path = "session_lifecycle/tests.rs"]
mod tests;
