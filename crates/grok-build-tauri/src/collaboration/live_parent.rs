//! Provider-issued delegation, invoked only by the explicit ignored CLI fixture.
use super::{AgentSettings, FamilyController};
use crate::contracts::{ProjectId, SessionId, WorkspaceId};
use crate::queue::{EnqueueRequest, QueueCoordinator, RunCompletion};
use crate::runtime::manager::RuntimeManager;
use crate::runtime::types::{
    AdapterContext, AdapterTurnOutcome, RuntimeEvent, RuntimeInvocationScope,
};
use grok_build_plus_host::{PlusSessionStore, bind_project_folder};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

struct Cleanup(FamilyController);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}

pub(crate) fn qualify(root: &Path, template: &RuntimeManager) {
    let root = root.join("provider-parent-delegation");
    let source = root.join("source");
    let state = root.join("state");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir(source.join(".git")).unwrap();
    let stamp = crate::runtime::types::unix_time_millis();
    let left = format!("ARTIFICIAL-LEFT-{stamp}");
    let right = format!("ARTIFICIAL-RIGHT-{stamp}");
    std::fs::write(source.join("left.txt"), &left).unwrap();
    std::fs::write(source.join("right.txt"), &right).unwrap();
    let project = ProjectId::new("live-parent-delegation");
    let workspace = WorkspaceId::new("synthetic-parent-workspace");
    let session = SessionId::new("synthetic-parent-session");
    let mut runtime = template
        .child_runtime_template(state.join("parent-runtime"))
        .unwrap();
    runtime
        .bind_conversation(&state, &project, &workspace, &session)
        .unwrap();
    let queue = QueueCoordinator::open(state.clone());
    let bound = bind_project_folder(&source).unwrap();
    AgentSettings::set(&state, &project, true).unwrap();
    let prompt = "Use app_agent_spawn to create exactly two Grok children: an Explore child that reads left.txt and a Plan child that reads right.txt. Each file contains an artificial project label created for this test. Each child must use its app read_file tool and return its label. Wait for both children with app_agent_wait, then return both labels. Do not read files yourself, create more children, change files, or use any other tools.";
    let item = queue
        .enqueue(EnqueueRequest {
            project_id: project.clone(),
            workspace_id: workspace.clone(),
            workspace_root: source.to_string_lossy().into_owned(),
            session_id: session.clone(),
            transport: runtime.selected_transport(),
            prompt: prompt.into(),
            auto_start: true,
            retry_of_run_id: None,
            predecessor_run_id: None,
        })
        .unwrap();
    let parent = queue
        .begin_run(&item.id, runtime.cancel_handle())
        .unwrap()
        .run
        .id;
    let family = FamilyController::prepare(
        &state,
        project.clone(),
        parent.clone(),
        bound.clone(),
        queue.clone(),
        &runtime,
        Arc::new(|| Ok(())),
    )
    .unwrap()
    .unwrap();
    let _cleanup = Cleanup(family.clone());
    runtime
        .bind_collaboration(Arc::new(family.clone()))
        .unwrap();
    let store = PlusSessionStore::from_state_root(state.join("parent-store"));
    let context = AdapterContext {
        scope: RuntimeInvocationScope {
            project_id: project,
            workspace_id: workspace,
            session_id: session,
            run_id: parent.clone(),
        },
        bound: &bound,
        store: &store,
        extension_context: "",
        hooks: runtime.prepare_hooks().unwrap(),
    };
    let events = Mutex::new(Vec::new());
    runtime.start_connected_run_session().unwrap();
    let result = runtime.send_turn(&context, prompt, &|_| Ok(Vec::new()), &|event| {
        if let RuntimeEvent::ToolRequest { name, .. } = event {
            events.lock().unwrap().push(name);
        }
        Ok(())
    });
    runtime.disconnect().unwrap();
    family.close().unwrap();
    report(&family, &events.lock().unwrap(), (&left, &right));
    let turn = result.unwrap();
    assert_result(
        &queue,
        &parent,
        &turn,
        &events.lock().unwrap(),
        &source,
        (&left, &right),
    );
    queue.complete_run(&parent, RunCompletion::Done).unwrap();
    eprintln!(
        "Provider-issued app delegation: exact parent tool calls, two isolated children, both artificial source labels returned, no parent file tools or source writes, family cleanup complete."
    );
}

fn assert_result(
    queue: &QueueCoordinator,
    parent: &crate::contracts::RunId,
    turn: &crate::runtime::types::AdapterTurn,
    tools: &[String],
    source: &Path,
    labels: (&str, &str),
) {
    let (left, right) = labels;
    assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
    let records = queue.child_records(parent).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|child| child.isolated && child.state == crate::queue::children::ChildState::Done)
    );
    assert_ne!(records[0].workspace, records[1].workspace);

    assert_eq!(
        tools
            .iter()
            .filter(|name| name.as_str() == "app_agent_spawn")
            .count(),
        2
    );
    assert!(tools.iter().all(|name| name.starts_with("app_agent_")));
    assert!(turn.assistant_text.contains(left) && turn.assistant_text.contains(right));
    assert_eq!(
        std::fs::read_to_string(source.join("left.txt")).unwrap(),
        left
    );
    assert_eq!(
        std::fs::read_to_string(source.join("right.txt")).unwrap(),
        right
    );
    assert!(tools.iter().any(|name| name == "app_agent_wait"));
}

fn report(family: &FamilyController, tools: &[String], labels: (&str, &str)) {
    let rows = family.rows(None).unwrap();
    let children = rows["children"].as_array().unwrap().iter().map(|row| {
        let answer = row["assistant"].as_str().unwrap_or("");
        serde_json::json!({"role":row["role"],"state":row["state"],"isolated":row["isolated"],"assistantBytes":answer.len(),"hasLeftLabel":answer.contains(labels.0),"hasRightLabel":answer.contains(labels.1)})
    }).collect::<Vec<_>>();
    eprintln!(
        "Parent delegation fixture observations: {}",
        serde_json::json!({"tools":tools,"children":children})
    );
}
