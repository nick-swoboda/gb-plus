use super::*;
use crate::contracts::SessionId;
use crate::queue::{EnqueueRequest, QueueItemState, RunCompletion};
use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::types::RuntimeTransport;
use grok_build_plus_host::PlusSessionStore;

#[test]
fn engine_switch_cannot_change_authority_of_queued_work() {
    let (root, mut backend) = engine_fixture("queue");
    assert!(backend.standard_engine());
    let context = backend.operation_context().unwrap();
    let mut items = Vec::new();
    for auto_start in [false, true] {
        let mut item = backend
            .queue
            .enqueue(EnqueueRequest {
                project_id: context.project_id.clone(),
                workspace_id: context.workspace_id.clone(),
                workspace_root: context.active_root.to_string_lossy().into(),
                session_id: context.session_id.clone(),
                transport: RuntimeTransport::GrokCliAcp,
                prompt: "queued fixture".into(),
                auto_start,
                retry_of_run_id: None,
                predecessor_run_id: None,
            })
            .unwrap();
        if !auto_start {
            item.blocked_reason = Some("Held from an earlier version.".into());
            backend
                .queue
                .mark_blocked(&item.id, item.blocked_reason.as_deref().unwrap())
                .unwrap();
        }
        items.push(item);
    }
    let empty = root.join("empty-project");
    std::fs::create_dir_all(&empty).unwrap();
    backend.bind_project(empty.to_str().unwrap()).unwrap();
    assert_ne!(
        backend.operation_context().unwrap().project_id,
        context.project_id
    );
    for mode in [
        crate::runtime::engine::EngineMode::GbPlusContained,
        crate::runtime::engine::EngineMode::GrokCliStandard,
    ] {
        backend
            .set_engine(EngineSettings {
                mode,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(backend.runtime.engine_settings().mode, mode);
        assert!(backend.queue.view().runs.is_empty());
        assert!(backend.queue.candidates(None, false).unwrap().is_empty());
        for original in &items {
            let mut expected = serde_json::to_value(original).unwrap();
            if original.auto_start {
                expected["autoStart"] = false.into();
                expected["blockedReason"] =
                    "Held after changing engines. Choose Send next when ready.".into();
            }
            let current = backend
                .queue
                .view()
                .items
                .into_iter()
                .find(|entry| entry.id == original.id.as_str())
                .unwrap();
            assert_eq!(serde_json::to_value(current).unwrap(), expected);
        }
    }
    drop(backend);
    let backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    assert!(backend.standard_engine());
    assert!(backend.queue.candidates(None, false).unwrap().is_empty());
    assert_eq!(backend.queue.view().items.len(), 2);
    backend
        .queue
        .rebind_waiting_transport(RuntimeTransport::GrokCliAcp)
        .unwrap();
    assert!(backend.queue.candidates(None, false).unwrap().is_empty());
    let fresh = backend
        .queue
        .enqueue(backend.queue_request("new project fixture", true).unwrap())
        .unwrap();
    let candidates = backend.queue.candidates(None, false).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].id, fresh.id);
    backend.queue.remove_item(&fresh.id).unwrap();
    let released = backend.queue.release_held(&items[1].id).unwrap();
    assert!(released.auto_start);
    assert!(released.blocked_reason.is_none());
    assert_eq!(
        backend.queue.candidates(None, false).unwrap()[0].id,
        items[1].id
    );
    assert!(backend.queue.view().runs.is_empty());
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn engine_switch_refuses_running_work_without_mutating_messages_or_settings() {
    let (root, mut backend) = engine_fixture("running");
    let item = backend
        .queue
        .enqueue(backend.queue_request("fixture", true).unwrap())
        .unwrap();
    let run = backend
        .queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .unwrap()
        .run;
    let before = serde_json::to_value(backend.queue.view()).unwrap();
    assert!(
        backend
            .set_engine(EngineSettings::default())
            .unwrap_err()
            .contains("running chats in all projects")
    );
    assert!(backend.standard_engine());
    assert_eq!(serde_json::to_value(backend.queue.view()).unwrap(), before);
    backend
        .queue
        .complete_run(&run.id, RunCompletion::Done)
        .unwrap();
    backend.set_engine(EngineSettings::default()).unwrap();
    assert!(!backend.standard_engine());
    assert_eq!(backend.queue.view().items[0].state, QueueItemState::Done);
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_engine_save_retains_messages_held_across_restart() {
    let (root, mut backend) = engine_fixture("failed-save");
    let item = backend
        .queue
        .enqueue(backend.queue_request("saved fixture", true).unwrap())
        .unwrap();
    std::fs::create_dir(root.join("state/engine-before-change.json")).unwrap();
    assert!(backend.set_engine(EngineSettings::default()).is_err());
    assert!(backend.standard_engine());
    assert!(backend.queue.candidates(None, false).unwrap().is_empty());
    drop(backend);
    let backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    assert!(backend.standard_engine());
    let view = backend.queue.view();
    assert!(view.available);
    assert!(view.runs.is_empty());
    assert_eq!(view.items[0].id, item.id.as_str());
    assert_eq!(view.items[0].prompt, item.prompt);
    assert!(!view.items[0].auto_start);
    assert!(backend.queue.candidates(None, false).unwrap().is_empty());
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_queue_save_prevents_engine_change_and_preserves_memory_and_disk() {
    let (root, mut backend) = engine_fixture("queue-save");
    backend
        .queue
        .enqueue(backend.queue_request("fixture", true).unwrap())
        .unwrap();
    let file = root.join("state/plus-queue.json");
    let before = serde_json::to_value(backend.queue.view()).unwrap();
    let bytes = std::fs::read(&file).unwrap();
    std::fs::rename(&file, root.join("state/queue-fixture-backup.json")).unwrap();
    std::fs::create_dir(&file).unwrap();
    assert!(backend.set_engine(EngineSettings::default()).is_err());
    assert!(backend.standard_engine());
    assert_eq!(serde_json::to_value(backend.queue.view()).unwrap(), before);
    assert_eq!(
        std::fs::read(root.join("state/queue-fixture-backup.json")).unwrap(),
        bytes
    );
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unreadable_queue_reports_unavailable_without_changing_engine_or_saved_data() {
    let (root, backend) = engine_fixture("unreadable");
    drop(backend);
    let file = root.join("state/plus-queue.json");
    std::fs::write(&file, b"{unknown fixture}").unwrap();
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    let error = backend.set_engine(EngineSettings::default()).unwrap_err();
    assert!(error.contains("Saved queue state is unavailable"));
    assert!(!error.contains("remove queued"));
    assert!(backend.standard_engine());
    assert_eq!(std::fs::read(&file).unwrap(), b"{unknown fixture}");
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unchanged_or_invalid_engine_selection_does_not_hold_work() {
    let (root, mut backend) = engine_fixture("unchanged");
    backend
        .queue
        .enqueue(backend.queue_request("fixture", true).unwrap())
        .unwrap();
    let before = serde_json::to_value(backend.queue.view()).unwrap();
    backend
        .set_engine(backend.runtime.engine_settings())
        .unwrap();
    assert!(
        backend
            .set_engine(EngineSettings {
                schema_version: 99,
                ..Default::default()
            })
            .is_err()
    );
    assert_eq!(serde_json::to_value(backend.queue.view()).unwrap(), before);
    assert!(backend.standard_engine());
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn engine_change_waits_for_unlock_without_mutating_saved_work() {
    let (root, mut backend) = engine_fixture("locked");
    backend
        .queue
        .enqueue(backend.queue_request("fixture", true).unwrap())
        .unwrap();
    let before = serde_json::to_value(backend.queue.view()).unwrap();
    backend.queue.set_lifecycle_suspended(true);
    assert!(
        backend
            .set_engine(EngineSettings::default())
            .unwrap_err()
            .contains("Unlock the app")
    );
    assert!(backend.standard_engine());
    assert_eq!(serde_json::to_value(backend.queue.view()).unwrap(), before);
    backend.queue.set_lifecycle_suspended(false);
    backend.set_engine(EngineSettings::default()).unwrap();
    assert!(!backend.standard_engine());
    assert!(backend.queue.candidates(None, false).unwrap().is_empty());
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
}

fn engine_fixture(label: &str) -> (std::path::PathBuf, Backend) {
    let root = std::env::temp_dir().join(format!(
        "gbplus-engine-{label}-{}-{}",
        std::process::id(),
        crate::runtime::types::unix_time_millis()
    ));
    let workspace = root.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend.bind_project(workspace.to_str().unwrap()).unwrap();
    (root, backend)
}

#[test]
fn native_answers_require_the_selected_chat_even_inside_the_same_project() {
    let root = std::env::temp_dir().join(format!(
        "gbplus-cli-chat-scope-{}-{}",
        std::process::id(),
        crate::runtime::types::unix_time_millis()
    ));
    let workspace = root.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend.bind_project(workspace.to_str().unwrap()).unwrap();
    backend
        .set_engine(EngineSettings {
            mode: crate::runtime::engine::EngineMode::GrokCliStandard,
            ..Default::default()
        })
        .unwrap();
    let context = backend.operation_context().unwrap();
    for session in [context.session_id.clone(), SessionId::new("another-chat")] {
        let item = backend
            .queue
            .enqueue(EnqueueRequest {
                project_id: context.project_id.clone(),
                workspace_id: context.workspace_id.clone(),
                workspace_root: context.active_root.to_string_lossy().into(),
                session_id: session.clone(),
                transport: RuntimeTransport::GrokCliAcp,
                prompt: "scope fixture".into(),
                auto_start: true,
                retry_of_run_id: None,
                predecessor_run_id: None,
            })
            .unwrap();
        let run = backend
            .queue
            .begin_run(&item.id, RuntimeCancelHandle::new())
            .unwrap()
            .run;
        assert_eq!(
            backend
                .validate_cli_chat_run(context.project_id.as_str(), run.id.as_str())
                .is_ok(),
            session == context.session_id
        );
        assert!(
            backend
                .validate_cli_chat_run("other-project", run.id.as_str())
                .is_err()
        );
        backend
            .queue
            .complete_run(&run.id, RunCompletion::Done)
            .unwrap();
    }
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
}
