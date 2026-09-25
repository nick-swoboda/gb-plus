use super::*;
use crate::contracts::SessionId;
use crate::queue::{EnqueueRequest, RunCompletion};
use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::types::RuntimeTransport;
use grok_build_plus_host::PlusSessionStore;

#[test]
fn engine_switch_cannot_change_authority_of_queued_work() {
    let root = std::env::temp_dir().join(format!(
        "gbplus-engine-queue-{}-{}",
        std::process::id(),
        crate::runtime::types::unix_time_millis()
    ));
    let workspace = root.join("project");
    std::fs::create_dir_all(&workspace).unwrap();
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend.bind_project(workspace.to_str().unwrap()).unwrap();
    assert!(backend.standard_engine());
    let context = backend.operation_context().unwrap();
    let item = backend
        .queue
        .enqueue(EnqueueRequest {
            project_id: context.project_id,
            workspace_id: context.workspace_id,
            workspace_root: context.active_root.to_string_lossy().into(),
            session_id: context.session_id,
            transport: RuntimeTransport::GrokCliAcp,
            prompt: "queued fixture".into(),
            auto_start: false,
            retry_of_run_id: None,
            predecessor_run_id: None,
        })
        .unwrap();
    let result = backend.set_engine(EngineSettings::default());
    assert!(result.is_err());
    assert!(backend.standard_engine());
    let view = backend.queue.view();
    assert!(view.runs.is_empty());
    assert!(
        view.items
            .iter()
            .any(|entry| entry.id == item.id.as_str() && entry.state == QueueItemState::Queued)
    );
    drop(backend);
    std::fs::remove_dir_all(root).unwrap();
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
