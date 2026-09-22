use super::*;
use grok_build_plus_host::{PlusSessionStore, bind_project_folder};

#[test]
fn background_updates_and_permissions_remain_live_after_the_app_turn() {
    for stop in [false, true] {
        let (root, workspace, pool, config) = standard_tests::fixture();
        let bound = bind_project_folder(workspace.to_str().unwrap()).unwrap();
        let store = PlusSessionStore::from_state_root(root.join("state"));
        let context = AdapterContext {
            scope: super::super::types::RuntimeInvocationScope::fixture(),
            bound: &bound,
            store: &store,
            extension_context: "",
            hooks: None,
        };
        let run = context.scope.run_id.as_str();
        let cancel = RuntimeCancelHandle::new();
        let mut adapter = GrokCliAcpAdapter::new(config, cancel.clone());
        adapter.start_or_restore_session(None).unwrap();
        let result = adapter
            .send_turn(
                &context,
                "background-fixture",
                None,
                &|_| Ok(Vec::new()),
                &|_| Ok(()),
            )
            .unwrap();
        assert_eq!(result.assistant_text, "Assistant: Background started");
        assert!(cancel.cleanup_proven());
        let started = Instant::now();
        let state = loop {
            let value =
                serde_json::to_value(pool.idle_snapshot(&workspace, 0, None).unwrap().unwrap())
                    .unwrap();
            if !value["pending"].as_array().unwrap().is_empty() {
                break value;
            }
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            state["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["payload"]["update"]["sessionUpdate"] == "background_tasks")
        );
        assert!(!workspace.join("background-effect.txt").exists());
        let id = state["pending"][0]["id"].as_u64().unwrap();
        assert!(
            pool.answer_idle(
                Path::new("/other-chat"),
                run,
                id,
                super::super::cli_interactions::CliAnswer::Cancel
            )
            .is_err()
        );
        assert!(pool.lease(&workspace).unwrap().take().is_err());
        if !stop {
            pool.answer_idle(
                &workspace,
                run,
                id,
                super::super::cli_interactions::CliAnswer::Permission {
                    option_id: "yes".into(),
                },
            )
            .unwrap();
            while !workspace.join("background-effect.txt").exists() {
                assert!(started.elapsed() < Duration::from_secs(5));
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                fs::read_to_string(workspace.join("background-effect.txt")).unwrap(),
                "background accepted"
            );
        }
        pool.stop_idle(&workspace, run).unwrap();
        assert!(
            pool.answer_idle(
                &workspace,
                run,
                id,
                super::super::cli_interactions::CliAnswer::Cancel
            )
            .is_err()
        );
        assert!(pool.idle_snapshot(&workspace, 0, None).unwrap().is_none());
        assert_eq!(workspace.join("background-effect.txt").exists(), !stop);
        assert!(
            fs::read_to_string(workspace.join("requests.jsonl"))
                .unwrap()
                .contains("_x.ai/session/close")
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn child_permissions_require_a_native_parent_spawn_and_do_not_change_parent_policy() {
    let (root, workspace, pool, config) = standard_tests::fixture();
    let cancel = RuntimeCancelHandle::new();
    let mut adapter = GrokCliAcpAdapter::new(config, cancel.clone());
    adapter.start_or_restore_session(None).unwrap();
    let process = adapter.process.as_mut().unwrap();
    let request = json!({"jsonrpc":"2.0","id":901,"method":"session/request_permission","params":{"sessionId":"child","toolCall":{"kind":"edit"},"options":[{"optionId":"allow-edits-session","kind":"allow_always","name":"Allow this session"}]}});
    process
        .handle_native_request(&request, "session/request_permission", &|_| Ok(()))
        .unwrap();
    assert!(cancel.cli_interactions.snapshot().unwrap().is_empty());
    process.observe_native_family(&json!({"params":{"sessionId":"shared-session","update":{"sessionUpdate":"subagent_spawned","parent_session_id":"shared-session","child_session_id":"child"}}}));
    process
        .handle_native_request(&request, "session/request_permission", &|_| Ok(()))
        .unwrap();
    let view = cancel.cli_interactions.snapshot().unwrap().remove(0);
    cancel
        .cli_interactions
        .answer(
            view.id,
            super::super::cli_interactions::CliAnswer::Permission {
                option_id: "allow-edits-session".into(),
            },
        )
        .unwrap();
    process.poll_native_answers(&|_| Ok(())).unwrap();
    assert_eq!(
        process.applied_permission,
        Some(super::super::cli_permissions::CliPermissionMode::Ask)
    );
    process.terminate().unwrap();
    pool.clear().unwrap();
    assert!(workspace.is_dir());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn session_start_permission_is_visible_before_native_hooks_can_continue() {
    let (root, workspace, pool, config) = standard_tests::fixture();
    fs::write(workspace.join("ask-on-start"), "fixture").unwrap();
    let cancel = RuntimeCancelHandle::new();
    let observed = Arc::new(Mutex::new(false));
    let visible = Arc::clone(&observed);
    let mut adapter = GrokCliAcpAdapter::new(config, cancel.clone());
    let worker = std::thread::spawn(move || {
        adapter.start_or_restore_session_observed(None, &|event| {
            if matches!(event, RuntimeEvent::CliInteraction(_)) {
                *visible.lock().unwrap() = true;
            }
            Ok(())
        })
    });
    let started = Instant::now();
    let view = loop {
        if let Some(view) = cancel.cli_interactions.snapshot().unwrap().first() {
            break view.clone();
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(!workspace.join("startup-effect.txt").exists());
    cancel
        .cli_interactions
        .answer(
            view.id,
            super::super::cli_interactions::CliAnswer::Permission {
                option_id: "yes".into(),
            },
        )
        .unwrap();
    assert_eq!(
        worker
            .join()
            .unwrap()
            .unwrap()
            .provider_session_id
            .unwrap()
            .as_str(),
        "shared-session"
    );
    assert!(*observed.lock().unwrap());
    assert_eq!(
        fs::read_to_string(workspace.join("startup-effect.txt")).unwrap(),
        "accepted"
    );
    pool.clear().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_continuations_finish_before_releasing_the_original_run() {
    let (root, workspace, pool, config) = standard_tests::fixture();
    let bound = bind_project_folder(workspace.to_str().unwrap()).unwrap();
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let context = AdapterContext {
        scope: super::super::types::RuntimeInvocationScope::fixture(),
        bound: &bound,
        store: &store,
        extension_context: "",
        hooks: None,
    };
    let cancel = RuntimeCancelHandle::new();
    let mut adapter = GrokCliAcpAdapter::new(config, cancel.clone());
    adapter.start_or_restore_session(None).unwrap();
    let continued = Mutex::new(false);
    let turn = adapter.send_turn(&context, "continuation-fixture", None, &|_| Ok(Vec::new()), &|event| {
        if matches!(event, RuntimeEvent::AssistantDelta(ref text) if text == "CLI continuation.") {
            assert!(!cancel.cleanup_proven());
            *continued.lock().unwrap() = true;
        }
        Ok(())
    }).unwrap();
    assert_eq!(
        turn.assistant_text,
        "Assistant: First reply. CLI continuation."
    );
    assert!(*continued.lock().unwrap());
    assert!(cancel.cleanup_proven());
    pool.clear().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_new_user_turn_reconnects_after_idle_crash_without_replaying_the_previous_turn() {
    let (root, workspace, pool, config) = standard_tests::fixture();
    let bound = bind_project_folder(workspace.to_str().unwrap()).unwrap();
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let context = AdapterContext {
        scope: super::super::types::RuntimeInvocationScope::fixture(),
        bound: &bound,
        store: &store,
        extension_context: "",
        hooks: None,
    };
    let mut first = GrokCliAcpAdapter::new(config.clone(), RuntimeCancelHandle::new());
    first.start_or_restore_session(None).unwrap();
    fs::write(workspace.join("crash-after-idle"), "fixture").unwrap();
    let previous = first
        .send_turn(
            &context,
            "first user message",
            None,
            &|_| Ok(Vec::new()),
            &|_| Ok(()),
        )
        .unwrap();
    let started = Instant::now();
    loop {
        let view = serde_json::to_value(pool.idle_snapshot(&workspace, 0, None).unwrap().unwrap())
            .unwrap();
        if view["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "error")
        {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut next = GrokCliAcpAdapter::new(config, RuntimeCancelHandle::new());
    next.start_or_restore_session(previous.provider_session_id.as_ref())
        .unwrap();
    let current = next
        .send_turn(
            &context,
            "second user message",
            None,
            &|_| Ok(Vec::new()),
            &|_| Ok(()),
        )
        .unwrap();
    assert_eq!(previous.provider_session_id, current.provider_session_id);
    let requests = fs::read_to_string(workspace.join("requests.jsonl")).unwrap();
    assert_eq!(requests.matches("first user message").count(), 1);
    assert_eq!(requests.matches("second user message").count(), 1);
    assert_eq!(requests.matches("\"method\":\"initialize\"").count(), 2);
    pool.clear().unwrap();
    fs::remove_dir_all(root).unwrap();
}
