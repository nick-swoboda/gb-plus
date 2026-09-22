use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::{AtomicU64, Ordering};

use grok_build_plus_host::{PlusSessionStore, bind_project_folder};

use super::*;
use crate::runtime::engine::EngineSettings;

pub(super) fn fixture() -> (
    PathBuf,
    PathBuf,
    standard::StandardAgentPool,
    AcpLaunchConfig,
) {
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "gbplus-standard-{}-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let workspace = root.join("project with spaces");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("fact.txt"), "shared context").unwrap();
    let script = root.join("xai-grok-pager");
    fs::write(
        &script,
        include_str!("../../../tests/fixtures/standard-acp.sh"),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let settings = EngineSettings {
        developer_cli: Some(script),
        ..EngineSettings::default()
    };
    let pool = standard::StandardAgentPool::default();
    let mut config = AcpLaunchConfig::standard(
        &root,
        &workspace,
        &settings,
        Some(pool.lease(&workspace).unwrap()),
    )
    .unwrap();
    config.standard.as_mut().unwrap().home = root.join("user-home");
    (root, workspace, pool, config)
}

#[test]
fn standard_keeps_one_agent_and_rotates_tool_authority_across_turns() {
    let (root, workspace, pool, config) = fixture();
    let bound = bind_project_folder(workspace.to_str().unwrap()).unwrap();
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let mut context = AdapterContext {
        scope: super::super::types::RuntimeInvocationScope::fixture(),
        bound: &bound,
        store: &store,
        extension_context: "This app-only instruction must not replace native CLI context.",
        hooks: None,
    };
    let mut session = None;
    for n in 0..2 {
        context.scope.run_id = crate::contracts::RunId::new(format!("turn-{n}"));
        let cancel = RuntimeCancelHandle::new();
        let mut adapter = GrokCliAcpAdapter::new(config.clone(), cancel.clone());
        assert_eq!(adapter.probe(&|_| Ok(())).unwrap().model, "custom/model");
        assert!(adapter.supports_image);
        adapter.start_or_restore_session(session.as_ref()).unwrap();
        let turn = adapter
            .send_turn(&context, "/context", None, &|_| Ok(Vec::new()), &|_| Ok(()))
            .unwrap();
        assert!(turn.assistant_text.contains("native and app tools ready"));
        assert!(
            cancel.cleanup_proven(),
            "a settled turn releases only its idle CLI lease"
        );
        session = turn.provider_session_id;
        adapter.close_session().unwrap();
    }
    let requests = fs::read_to_string(workspace.join("requests.jsonl")).unwrap();
    assert_eq!(requests.matches("\"method\":\"initialize\"").count(), 1);
    assert_eq!(
        fs::read_to_string(workspace.join("starts.txt")).unwrap(),
        "agent stdio\n"
    );
    assert!(!requests.contains("systemPromptOverride"));
    assert!(!requests.contains("GB Plus user request"));
    assert!(!requests.contains("app-only instruction"));
    assert_eq!(requests.matches("\"text\":\"/context\"").count(), 2);
    let registrations: Vec<Value> = requests
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|row| matches!(row["method"].as_str(), Some("session/new" | "session/load")))
        .map(|row| row["params"]["_meta"]["x.ai/mcp/servers"][0]["serverId"].clone())
        .collect();
    assert_eq!(registrations.len(), 2);
    assert_ne!(registrations[0], registrations[1]);
    assert!(!root.join("acp-runtime/home/config.toml").exists());
    let homes = fs::read_to_string(workspace.join("launch-home.txt")).unwrap();
    assert_eq!(
        homes,
        format!(
            "{}\n{}\n",
            root.join("user-home").display(),
            root.join("user-home/.grok").display()
        )
    );
    pool.clear().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn standard_catalog_keeps_custom_models_and_observational_extensions() {
    let catalog = super::super::models::acp_catalog_for_engine(&json!({"availableModels":[{"modelId":"custom/model","name":"Custom model"},{"modelId":"grok-future"}]}), true).unwrap();
    assert_eq!(catalog.len(), 2);
    let event =
        json!({"jsonrpc":"2.0","method":"_x.ai/future/notification","params":{"newField":true}});
    standard::notification(&event, "_x.ai/future/notification", None, &|_| Ok(())).unwrap();
}

#[test]
fn standard_stop_is_acknowledged_and_the_interrupted_agent_is_not_reused() {
    let (root, workspace, pool, config) = fixture();
    let cancel = RuntimeCancelHandle::new();
    let mut adapter = GrokCliAcpAdapter::new(config, cancel.clone());
    adapter.probe(&|_| Ok(())).unwrap();
    adapter.start_or_restore_session(None).unwrap();
    let worker =
        std::thread::spawn(move || adapter.prompt("wait-forever", None, &|_| Ok(()), None));
    let started = Instant::now();
    while !fs::read_to_string(workspace.join("requests.jsonl"))
        .unwrap()
        .contains("wait-forever")
    {
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    cancel.request_cancel().unwrap();
    let error = worker.join().unwrap().unwrap_err();
    assert!(error.contains("cancelled"), "{error}");
    assert!(cancel.cleanup_proven());
    assert!(pool.lease(&workspace).unwrap().take().unwrap().is_none());
    assert!(
        fs::read_to_string(workspace.join("requests.jsonl"))
            .unwrap()
            .contains("session/cancel")
    );
    pool.clear().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn changing_projects_revokes_old_agent_leases() {
    let pool = standard::StandardAgentPool::default();
    let lease = pool.lease(Path::new("/project-a/chat-a")).unwrap();
    pool.clear().unwrap();
    assert!(lease.take().is_err());
    assert!(
        pool.lease(Path::new("/project-b/chat-b"))
            .unwrap()
            .take()
            .unwrap()
            .is_none()
    );
}

#[test]
fn child_observations_cannot_become_parent_reply_text_or_usage() {
    for method in ["session/update", "_x.ai/session/update"] {
        let event = json!({"jsonrpc":"2.0","method":method,"params":{"sessionId":"child","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"child output"}}}});
        standard::notification(&event, method, Some("parent"), &|event| {
            assert!(
                matches!(event, RuntimeEvent::CliUpdate { session_id, update }
                if session_id == "child" && update["content"]["text"] == "child output")
            );
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn native_edit_waits_for_exact_accept_and_stop_dismisses_pending_permission() {
    for stop in [false, true] {
        let (root, workspace, pool, config) = fixture();
        let cancel = RuntimeCancelHandle::new();
        let mut adapter = GrokCliAcpAdapter::new(config, cancel.clone());
        adapter.probe(&|_| Ok(())).unwrap();
        adapter.start_or_restore_session(None).unwrap();
        let worker = std::thread::spawn(move || {
            adapter.prompt("permission-fixture", None, &|_| Ok(()), None)
        });
        let started = Instant::now();
        let view = loop {
            if let Some(view) = cancel.cli_interactions.snapshot().unwrap().first() {
                break view.clone();
            }
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(!workspace.join("permission-effect.txt").exists());
        assert_eq!(
            view.request["toolCall"]["content"][0]["newText"],
            "accepted"
        );
        if stop {
            cancel.request_cancel().unwrap();
        } else {
            cancel
                .cli_interactions
                .answer(
                    view.id,
                    super::super::cli_interactions::CliAnswer::Permission {
                        option_id: "yes".into(),
                    },
                )
                .unwrap();
        }
        let result = worker.join().unwrap();
        if stop {
            assert!(result.unwrap_err().contains("cancelled"));
            assert!(!workspace.join("permission-effect.txt").exists());
        } else {
            assert_eq!(result.unwrap().1, "permission finished");
            assert_eq!(
                fs::read_to_string(workspace.join("permission-effect.txt")).unwrap(),
                "accepted"
            );
        }
        assert!(cancel.cli_interactions.snapshot().unwrap().is_empty());
        assert!(cancel.cleanup_proven());
        pool.clear().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn permission_change_reloads_only_the_idle_actor_and_preserves_the_agent_process() {
    let (root, workspace, pool, mut config) = fixture();
    let lease = pool.lease(&workspace).unwrap();
    let mut first = GrokCliAcpAdapter::new(config.clone(), RuntimeCancelHandle::new());
    first.start_or_restore_session(None).unwrap();
    let mut process = first.process.take().unwrap();
    assert_eq!(
        process.applied_permission,
        Some(super::super::cli_permissions::CliPermissionMode::Ask)
    );
    process.release_idle_turn().unwrap();
    lease.park(process, "fixture-run".into()).unwrap();
    config.standard.as_mut().unwrap().permission =
        super::super::cli_permissions::CliPermissionMode::Auto;
    let mut next = GrokCliAcpAdapter::new(config, RuntimeCancelHandle::new());
    next.start_or_restore_session(Some(&ProviderSessionId::new("shared-session")))
        .unwrap();
    assert_eq!(
        next.process.as_ref().unwrap().applied_permission,
        Some(super::super::cli_permissions::CliPermissionMode::Auto)
    );
    assert_eq!(
        fs::read_to_string(workspace.join("starts.txt"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(
        fs::read_to_string(workspace.join("closed-sessions.txt"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    let requests = fs::read_to_string(workspace.join("requests.jsonl")).unwrap();
    let load: Value = requests
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|frame| frame["method"] == "session/load")
        .unwrap();
    assert_eq!(load["params"]["_meta"]["yoloMode"], false);
    assert_eq!(load["params"]["_meta"]["autoMode"], true);
    next.close_session().unwrap();
    pool.clear().unwrap();
    fs::remove_dir_all(root).unwrap();
}
