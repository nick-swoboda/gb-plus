//! Active-workspace `FSEvents` hint manager.

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::{AppHandle, Emitter as _};

#[cfg(target_os = "macos")]
use notify::Watcher as _;

pub(crate) const WORKSPACE_EVENT_CHANNEL: &str = "grok-build-plus-workspace-event";
const EVENT_COALESCE_MILLIS: u64 = 150;
const MAX_WATCH_ERROR_BYTES: usize = 512;
const APP_TEMPORARY_PREFIX: &[u8] = b".grok-build-";
const LEGACY_RUNTIME_METADATA: &[u8] = b":memory:.ses";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceWatchEvent {
    kind: &'static str,
    sequence: u64,
    detail: Option<String>,
}

#[derive(Clone, Default)]
pub(crate) struct WorkspaceWatch {
    inner: Arc<Mutex<WorkspaceWatchInner>>,
    sequence: Arc<AtomicU64>,
    last_emit_millis: Arc<AtomicU64>,
}

#[derive(Default)]
struct WorkspaceWatchInner {
    root: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    watcher: Option<notify::RecommendedWatcher>,
}

impl WorkspaceWatch {
    pub(crate) fn sync(&self, app: &AppHandle, root: Option<&Path>) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Workspace watcher state is unavailable.".to_owned())?;
        if inner.root.as_deref() == root {
            return Ok(());
        }
        inner.root = None;
        #[cfg(target_os = "macos")]
        {
            inner.watcher = None;
            let Some(root) = root else {
                return Ok(());
            };
            if !root.is_absolute() {
                return Err("Workspace watcher root is not absolute.".into());
            }
            let app = app.clone();
            let sequence = Arc::clone(&self.sequence);
            let last_emit_millis = Arc::clone(&self.last_emit_millis);
            let watched_root = root.to_path_buf();
            let mut watcher =
                notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
                    match result {
                        Ok(event) => {
                            if !workspace_paths_include_content(&watched_root, &event.paths) {
                                return;
                            }
                            let now = unix_time_millis();
                            let prior = last_emit_millis.load(Ordering::Relaxed);
                            if now.saturating_sub(prior) < EVENT_COALESCE_MILLIS {
                                return;
                            }
                            last_emit_millis.store(now, Ordering::Relaxed);
                            let event = WorkspaceWatchEvent {
                                kind: "changed",
                                sequence: sequence.fetch_add(1, Ordering::Relaxed) + 1,
                                detail: None,
                            };
                            let _ = app.emit(WORKSPACE_EVENT_CHANNEL, event);
                        }
                        Err(error) => {
                            let event = WorkspaceWatchEvent {
                                kind: "error",
                                sequence: sequence.fetch_add(1, Ordering::Relaxed) + 1,
                                detail: Some(bounded_error(&error.to_string())),
                            };
                            let _ = app.emit(WORKSPACE_EVENT_CHANNEL, event);
                        }
                    }
                })
                .map_err(|error| format!("Cannot create the workspace watcher: {error}"))?;
            watcher
                .watch(root, notify::RecursiveMode::Recursive)
                .map_err(|error| format!("Cannot watch the active workspace: {error}"))?;
            inner.root = Some(root.to_path_buf());
            inner.watcher = Some(watcher);
            self.last_emit_millis.store(0, Ordering::Relaxed);
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (app, root);
            Err("Live Workspace refresh is supported only on macOS.".into())
        }
    }

    pub(crate) fn emit_error(&self, app: &AppHandle, detail: &str) {
        let event = WorkspaceWatchEvent {
            kind: "error",
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed) + 1,
            detail: Some(bounded_error(detail)),
        };
        let _ = app.emit(WORKSPACE_EVENT_CHANNEL, event);
    }
}

fn workspace_paths_include_content(root: &Path, paths: &[PathBuf]) -> bool {
    paths.iter().any(|path| {
        let Ok(relative) = path.strip_prefix(root) else {
            return false;
        };
        if relative.as_os_str().is_empty() {
            return false;
        }
        !relative.components().any(|component| {
            let Component::Normal(name) = component else {
                return false;
            };
            let bytes = name.as_encoded_bytes();
            bytes == b".git"
                || bytes == LEGACY_RUNTIME_METADATA
                || bytes.starts_with(APP_TEMPORARY_PREFIX)
        })
    })
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn bounded_error(detail: &str) -> String {
    if detail.len() <= MAX_WATCH_ERROR_BYTES {
        return detail.to_owned();
    }
    let mut end = MAX_WATCH_ERROR_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &detail[..end])
}

#[cfg(test)]
#[path = "workspace_watch/tests.rs"]
mod tests;
