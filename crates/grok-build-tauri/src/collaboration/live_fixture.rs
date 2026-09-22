//! Explicit live qualification; called only by the existing ignored ACP test.
use super::{
    Arc, ChildRecord, FamilyController, FamilyInput, GrokRunner, Mutex, Path, PlusChildRole,
    PlusCollaborationCommand, PlusCollaborationExecutor, ProjectId, QueueCoordinator,
    RuntimeCancelHandle, RuntimeManager, WorkspaceId,
};
use crate::contracts::SessionId;
use crate::queue::{EnqueueRequest, RunCompletion};
use crate::runtime::types::{AdapterTurn, RuntimeSteeringSource};
use grok_build_plus_host::{BoundProject, bind_project_folder};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::runner::ChildRunner;

struct ObservedRunner {
    runner: GrokRunner,
    started: AtomicUsize,
    active: AtomicUsize,
    maximum: AtomicUsize,
    failures: Mutex<Vec<String>>,
}
impl ChildRunner for ObservedRunner {
    fn run(
        &self,
        state: &Path,
        child: &ChildRecord,
        bound: &BoundProject,
        prompt: &str,
        cancel: RuntimeCancelHandle,
        steering: &RuntimeSteeringSource<'_>,
    ) -> Result<AdapterTurn, String> {
        struct Active<'a>(&'a AtomicUsize);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        let _active = Active(&self.active);
        self.maximum.fetch_max(active, Ordering::AcqRel);
        self.started.fetch_add(1, Ordering::AcqRel);
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.started.load(Ordering::Acquire) < 2 {
            cancel.ensure_not_cancelled()?;
            if Instant::now() >= deadline {
                return Err(
                    "The second live child did not acquire its app execution lease.".into(),
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let result = self
            .runner
            .run(state, child, bound, prompt, cancel, steering);
        if let Err(error) = &result {
            self.failures.lock().unwrap().push(error.clone());
        }
        result
    }
}

struct Fixture {
    queue: QueueCoordinator,
    parent: crate::contracts::RunId,
    runner: Arc<ObservedRunner>,
    family: FamilyController,
}
impl Fixture {
    fn new(root: &Path, source: &Path, runtime: &RuntimeManager) -> Self {
        let state = root.join("synthetic-child-state");
        let queue = QueueCoordinator::open(state.clone());
        let project = ProjectId::new("live-child-fixture");
        let item = queue
            .enqueue(EnqueueRequest {
                project_id: project.clone(),
                workspace_id: WorkspaceId::new("fixture-parent-workspace"),
                workspace_root: source.display().to_string(),
                session_id: SessionId::new("fixture-parent-session"),
                transport: runtime.selected_transport(),
                prompt: "Synthetic live child qualification".into(),
                auto_start: true,
                retry_of_run_id: None,
                predecessor_run_id: None,
            })
            .unwrap();
        let cancel = RuntimeCancelHandle::new();
        let parent = queue.begin_run(&item.id, cancel.clone()).unwrap().run.id;
        let runner = Arc::new(ObservedRunner {
            runner: GrokRunner(Mutex::new(
                runtime
                    .child_runtime_template(root.join("template"))
                    .unwrap(),
            )),
            started: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            failures: Mutex::new(Vec::new()),
        });
        let family = FamilyController::new(
            FamilyInput {
                state: &state,
                project,
                parent: parent.clone(),
                bound: bind_project_folder(source).unwrap(),
                queue: queue.clone(),
                workflow: None,
            },
            cancel,
            runner.clone(),
            Arc::new(|| Ok(())),
        )
        .unwrap();
        Self {
            queue,
            parent,
            runner,
            family,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.family.close();
    }
}

pub(crate) fn qualify(root: &Path, runtime: &RuntimeManager) {
    let source = root.join("synthetic-child-source");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(source.join(".git")).unwrap();
    let token = format!(
        "SYNTHETIC-FACT-{}",
        crate::runtime::types::unix_time_millis()
    );
    std::fs::write(source.join("fact.txt"), token.as_bytes()).unwrap();
    let fixture = Fixture::new(root, &source, runtime);
    let Fixture {
        queue,
        parent,
        runner,
        family,
    } = &fixture;
    for (id, role) in [
        ("read", PlusChildRole::Explore),
        ("plan", PlusChildRole::Plan),
    ] {
        let result = family.execute(id, PlusCollaborationCommand::Spawn {
            role,
            prompt: "Use the app read_file tool to read fact.txt. It contains an artificial project label created for this test. Reply with that label only. Do not delegate or change files.".into(),
        }, false).unwrap();
        assert_ne!(result["isError"], true, "{result}");
    }
    let agents = queue
        .child_records(parent)
        .unwrap()
        .iter()
        .map(|c| c.agent_id.as_str().to_owned())
        .collect::<Vec<_>>();
    wait_all(family, queue, parent, &agents, "first");
    let failures = runner.failures.lock().unwrap().clone();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(runner.maximum.load(Ordering::Acquire), 2);
    let first = family.rows(None).unwrap();
    for child in first["children"].as_array().unwrap() {
        assert_eq!(child["state"], "done", "{child}");
        assert_eq!(child["isolated"], true);
        assert!(
            child["assistant"].as_str().unwrap().contains(&token),
            "{child}"
        );
    }
    family.execute("continue", PlusCollaborationCommand::Continue {
        agent_id: agents[0].clone(),
        prompt: "Using conversation memory only, state the artificial project label from fact.txt that you read in the previous turn. Do not read files or call tools. Reply with only that label.".into(),
    }, false).unwrap();
    wait_all(family, queue, parent, &agents, "continuation");
    let records = queue.child_records(parent).unwrap();
    assert_eq!(records.len(), 3);
    let rows = family.rows(None).unwrap();
    let last = rows["children"].as_array().unwrap().last().unwrap();
    assert_eq!(
        last["state"],
        "done",
        "{last}; failures={:?}",
        runner.failures.lock().unwrap()
    );
    assert!(
        last["assistant"].as_str().unwrap().contains(&token),
        "{last}"
    );
    assert_eq!(records[0].session, records[2].session);
    assert_ne!(records[0].workspace, records[1].workspace);
    assert_eq!(
        std::fs::read_to_string(source.join("fact.txt")).unwrap(),
        token
    );
    family.close().unwrap();
    assert_eq!(runner.active.load(Ordering::Acquire), 0);
    queue.complete_run(parent, RunCompletion::Done).unwrap();
    eprintln!(
        "Live child fixture: {:?}, two children, separate worktrees, exact file facts, explicit continuation, maximum two child leases, source unchanged, cleanup complete.",
        runtime.selected_transport()
    );
}

fn wait_all(
    family: &FamilyController,
    queue: &QueueCoordinator,
    parent: &crate::contracts::RunId,
    agents: &[String],
    label: &str,
) {
    for attempt in 0..5 {
        if queue
            .child_records(parent)
            .unwrap()
            .iter()
            .all(|child| !child.state.active())
        {
            return;
        }
        let active = agents
            .iter()
            .filter(|agent| {
                queue
                    .child_records(parent)
                    .unwrap()
                    .iter()
                    .rev()
                    .find(|child| child.agent_id.as_str() == *agent)
                    .is_some_and(|child| child.state.active())
            })
            .cloned()
            .collect::<Vec<_>>();
        family
            .execute(
                &format!("wait-{label}-{attempt}"),
                PlusCollaborationCommand::Wait {
                    agent_ids: active,
                    timeout_seconds: 60,
                },
                false,
            )
            .unwrap();
    }
    panic!("Live child fixture exceeded its completion deadline");
}
