//! Exact-CLI integration, selected only through the existing ignored live probe.
use super::{Job, JobInput, JobState, execute};
use crate::collaboration::{FamilyController, WorkflowFamilyInput};
use crate::contracts::{ProjectId, SessionId, WorkspaceId};
use crate::queue::workflows::WorkflowTicket;
use crate::queue::{EnqueueRequest, QueueCoordinator, RunCompletion};
use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::manager::RuntimeManager;
use grok_build_plus_host::bind_project_folder;
use grok_build_workflow::WorkflowOutcome;
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub(crate) fn qualify(root: &Path, runtime: &RuntimeManager) {
    let source = root.join("synthetic-workflow-source");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(source.join(".git")).unwrap();
    let token = format!(
        "WORKFLOW-FACT-{}",
        crate::runtime::types::unix_time_millis()
    );
    std::fs::write(source.join("fact.txt"), &token).unwrap();
    let state = root.join("synthetic-workflow-state");
    let queue = QueueCoordinator::open(state.clone());
    let (extension, component, name, script) = install_example(root, &state);
    let input = JobInput {
        project: ProjectId::new("workflow-live"),
        workspace: WorkspaceId::new("workflow-source"),
        session: SessionId::new("workflow-chat"),
        transport: runtime.selected_transport(),
        extension,
        component,
        name,
        script,
        args: json!({"question":"Use the app read_file tool to read fact.txt, which contains an artificial project label. Each review must report that exact label as its evidence. Do not delegate or change files."}),
        maximum: 8,
        transient: false,
    };
    let job = Arc::new(Mutex::new(Job::new(input).unwrap()));
    job.lock().unwrap().save(&state).unwrap();
    let first = attempt(&state, &source, runtime, &queue, &job);
    assert!(matches!(
        job.lock().unwrap().outcome,
        Some(WorkflowOutcome::Paused { .. })
    ));
    let children = queue.child_records(&first).unwrap();
    assert_eq!(children.len(), 2);
    assert!(
        children
            .iter()
            .all(|child| child.state == crate::queue::children::ChildState::Done)
    );
    assert_ne!(children[0].workspace, children[1].workspace);
    let id = job.lock().unwrap().id.clone();
    drop(job);
    let mut restored = Job::load(&state, &id).unwrap();
    assert_eq!(restored.used, 2);
    restored.resume(&state).unwrap();
    let restored = Arc::new(Mutex::new(restored));
    let second = attempt(&state, &source, runtime, &queue, &restored);
    assert!(
        queue.child_records(&second).unwrap().is_empty(),
        "Completed agent calls must replay without new children"
    );
    let restored = restored.lock().unwrap();
    assert_eq!(restored.used, 2);
    let Some(WorkflowOutcome::Completed { result }) = &restored.outcome else {
        panic!(
            "Workflow did not finish after explicit resume: {:?}",
            restored.outcome
        )
    };
    let outputs = result.as_array().unwrap();
    assert_eq!(outputs.len(), 2);
    for output in outputs {
        assert_eq!(output["success"], true);
        assert!(
            output["output"].as_str().unwrap().contains(&token),
            "{output}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(source.join("fact.txt")).unwrap(),
        token
    );
    eprintln!(
        "Live workflow fixture: {:?} parallel children, exact source facts, pause, disk reload, explicit resume, zero repeated child calls, budget remained 2/8, source unchanged and cleanup complete.",
        runtime.selected_transport()
    );
}

fn attempt(
    state: &Path,
    source: &Path,
    runtime: &RuntimeManager,
    queue: &QueueCoordinator,
    job: &Arc<Mutex<Job>>,
) -> crate::contracts::RunId {
    let (input, id, attempt) = {
        let job = job.lock().unwrap();
        (job.input.clone(), job.id.clone(), job.attempt)
    };
    let item = queue
        .enqueue_workflow(
            EnqueueRequest {
                project_id: input.project.clone(),
                workspace_id: input.workspace.clone(),
                workspace_root: source.display().to_string(),
                session_id: input.session.clone(),
                transport: input.transport,
                prompt: "Synthetic workflow fixture".into(),
                auto_start: true,
                retry_of_run_id: None,
                predecessor_run_id: None,
            },
            WorkflowTicket {
                job_id: id.clone(),
                attempt,
            },
        )
        .unwrap();
    // Use an independent app-owned root cancel handle, as the real queue does.
    let template = runtime
        .child_runtime_template(state.join(format!("workflow-root-{attempt}")))
        .unwrap();
    let cancel: RuntimeCancelHandle = template.cancel_handle();
    let run = queue.begin_run(&item.id, cancel.clone()).unwrap().run.id;
    job.lock()
        .unwrap()
        .mutate(state, |job| {
            job.state = JobState::Running;
            job.run = Some(run.clone());
            job.queue_item = Some(item.id);
            Ok(())
        })
        .unwrap();
    let family = FamilyController::prepare_workflow(
        WorkflowFamilyInput {
            state,
            project: input.project,
            parent: run.clone(),
            bound: bind_project_folder(source).unwrap(),
            queue: queue.clone(),
            workflow: id,
            maximum: input.maximum,
        },
        &template,
        Arc::new(|| Ok(())),
    )
    .unwrap();
    let result = execute(state, job, family.clone(), &cancel, None);
    if let Ok(rows) = family.rows(None)
        && let Some(children) = rows["children"].as_array()
    {
        for child in children {
            if child["state"] != "done" {
                let detail = child["assistant"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(512)
                    .collect::<String>();
                eprintln!(
                    "Synthetic workflow child: role={} state={} detail={detail}",
                    child["role"], child["state"]
                );
            }
        }
    }
    let cleanup = family.close();
    assert!(cleanup.is_ok(), "{cleanup:?}");
    result.unwrap();
    queue.complete_run(&run, RunCompletion::Done).unwrap();
    run
}

fn install_example(root: &Path, state: &Path) -> (String, String, String, String) {
    let source = root.join("parallel-review-example");
    for (name, contents) in [
        (
            "plugin.json",
            include_str!("../../../../fixtures/extensions/parallel-review/plugin.json"),
        ),
        (
            "LICENSE",
            include_str!("../../../../fixtures/extensions/parallel-review/LICENSE"),
        ),
        (
            "README.md",
            include_str!("../../../../fixtures/extensions/parallel-review/README.md"),
        ),
        (
            "workflows/review.rhai",
            include_str!("../../../../fixtures/extensions/parallel-review/workflows/review.rhai"),
        ),
    ] {
        let path = source.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let project = ProjectId::new("workflow-live");
    let store = crate::extensions::ExtensionStore::new(state);
    let preview = store
        .preview_local(&source.canonicalize().unwrap())
        .unwrap();
    assert_eq!(preview.components.len(), 1);
    let component = &preview.components[0];
    assert!(component.quarantine.is_none());
    store.install(&preview.digest).unwrap();
    assert!(store.enabled_workflows(&project).unwrap().is_empty());
    store
        .set_enabled(&project, &preview.digest, &component.id, true)
        .unwrap();
    let frozen = store
        .workflow(&project, &preview.digest, &component.id)
        .unwrap();
    assert_eq!(
        frozen.script,
        include_str!("../../../../fixtures/extensions/parallel-review/workflows/review.rhai")
    );
    (
        frozen.extension,
        frozen.component,
        frozen.name,
        frozen.script,
    )
}

#[test]
fn shipped_workflow_installs_disabled_and_reads_back_exactly_after_enablement() {
    let root = std::env::temp_dir().join(format!(
        "gbplus-workflow-example-{}-{}",
        std::process::id(),
        crate::runtime::types::unix_time_millis(),
    ));
    std::fs::create_dir(&root).unwrap();
    let result = install_example(&root, &root.join("state"));
    assert!(!result.0.is_empty());
    assert_eq!(
        result.3,
        include_str!("../../../../fixtures/extensions/parallel-review/workflows/review.rhai")
    );
    std::fs::remove_dir_all(root).unwrap();
}
