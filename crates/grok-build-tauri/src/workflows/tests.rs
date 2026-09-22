use super::*;
use crate::contracts::{ProjectId, SessionId, WorkspaceId};
use crate::runtime::types::RuntimeTransport;
use grok_build_workflow::{
    AgentOptions, CancelCheck, HostCall, HostReply, WorkflowHost, WorkflowOutcome,
};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

struct Root(PathBuf);
impl Root {
    fn new(label: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "gbplus-workflow-{label}-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        )))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn input(transient: bool, maximum: u16) -> JobInput {
    JobInput {
        project: ProjectId::new("workflow-project"),
        workspace: WorkspaceId::new("workflow-workspace"),
        session: SessionId::new("workflow-session"),
        transport: RuntimeTransport::GrokCliAcp,
        extension: "a".repeat(64),
        component: "b".repeat(64),
        name: "Fixture workflow".into(),
        script: "args".into(),
        args: json!({"fact":"TRANSIENT_WORKFLOW_INPUT_CANARY"}),
        maximum,
        transient,
    }
}
fn agent() -> HostCall {
    HostCall::Agent(AgentOptions {
        prompt: "inspect the synthetic fact".into(),
        agent_type: Some("plan".into()),
        label: None,
    })
}
fn active(root: &Root, transient: bool, maximum: u16) -> Job {
    let mut job = Job::new(input(transient, maximum)).unwrap();
    job.state = JobState::Running;
    job.save(&root.0).unwrap();
    job
}

#[test]
fn persisted_intent_precedes_effect_and_crash_refuses_unknown_replay() {
    let root = Root::new("uncertain");
    let mut job = active(&root, false, 8);
    assert!(job.begin(&root.0, 0, &agent()).unwrap().is_none());
    let mut recovered = Job::load(&root.0, &job.id).unwrap();
    assert_eq!(recovered.state, JobState::Interrupted);
    assert_eq!(recovered.used, 1);
    assert!(recovered.resume(&root.0).is_err());
    recovered.state = JobState::Running;
    assert!(recovered.begin(&root.0, 0, &agent()).is_err());
    let disk: Value = serde_json::from_slice(
        &std::fs::read(
            root.0
                .join("workflow-records-v1")
                .join(format!("{}.json", job.id)),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(disk["effects"][0]["completed"], false);
    assert_eq!(disk["effects"][0]["result"], Value::Null);
}

#[test]
fn completed_calls_replay_exactly_without_consuming_the_remaining_budget() {
    let root = Root::new("replay");
    let mut job = active(&root, false, 8);
    job.begin(&root.0, 0, &agent()).unwrap();
    let result = json!({"output":"first fact","success":true,"agent_id":"owned-child"});
    job.complete(&root.0, 0, result.clone()).unwrap();
    job.state = JobState::Paused;
    job.save(&root.0).unwrap();
    let mut job = Job::load(&root.0, &job.id).unwrap();
    job.resume(&root.0).unwrap();
    job.state = JobState::Running;
    assert_eq!(job.begin(&root.0, 0, &agent()).unwrap(), Some(result));
    assert_eq!(job.used, 1);
    assert!(job.begin(&root.0, 0, &HostCall::Budget).is_err());
}

#[test]
fn transient_workflow_payloads_are_unavailable_after_restart() {
    let root = Root::new("transient");
    let mut job = active(&root, true, 8);
    let secret = "TRANSIENT_WORKFLOW_OUTPUT_CANARY";
    let request = HostCall::Agent(AgentOptions {
        prompt: secret.into(),
        agent_type: None,
        label: None,
    });
    job.begin(&root.0, 0, &request).unwrap();
    job.complete(&root.0, 0, json!(secret)).unwrap();
    job.local_call(
        &root.0,
        HostCall::WriteScratch {
            name: "fact".into(),
            content: secret.into(),
        },
    )
    .unwrap();
    job.phase = Some(secret.into());
    job.outcome = Some(WorkflowOutcome::Completed {
        result: json!(secret),
    });
    job.state = JobState::Paused;
    job.save(&root.0).unwrap();
    let text = std::fs::read_to_string(
        root.0
            .join("workflow-records-v1")
            .join(format!("{}.json", job.id)),
    )
    .unwrap();
    assert!(!text.contains(secret));
    assert!(!text.contains("TRANSIENT_WORKFLOW_INPUT_CANARY"));
    assert_eq!(
        job.begin(&root.0, 0, &request).unwrap_err(),
        "Workflow is not active or its context is unavailable."
    );
    let mut recovered = Job::load(&root.0, &job.id).unwrap();
    assert!(!recovered.available);
    assert!(recovered.resume(&root.0).is_err());
}

#[test]
fn workflow_budget_is_durable_and_bounded_across_explicit_attempts() {
    let root = Root::new("budget");
    assert!(Job::new(input(false, 33)).is_err());
    let mut job = active(&root, false, 32);
    for sequence in 0..32 {
        job.begin(&root.0, sequence, &agent()).unwrap();
        job.complete(&root.0, sequence, json!(sequence)).unwrap();
    }
    job.state = JobState::Paused;
    job.save(&root.0).unwrap();
    job.resume(&root.0).unwrap();
    job.state = JobState::Running;
    assert!(job.begin(&root.0, 32, &agent()).is_err());
    assert_eq!(job.used, 32);
    assert_eq!(job.begin(&root.0, 0, &agent()).unwrap(), Some(json!(0)));
}

#[test]
fn failed_checkpoint_write_restores_memory_and_preserves_original_bytes() {
    let root = Root::new("atomic");
    let mut job = active(&root, false, 8);
    let before = serde_json::to_value(&job).unwrap();
    let dir = root.0.join("workflow-records-v1");
    let held = root.0.join("held");
    std::fs::rename(&dir, &held).unwrap();
    std::os::unix::fs::symlink(&held, &dir).unwrap();
    assert!(job.begin(&root.0, 0, &agent()).is_err());
    assert_eq!(serde_json::to_value(&job).unwrap(), before);
    std::fs::remove_file(&dir).unwrap();
    std::fs::rename(&held, &dir).unwrap();
    assert_eq!(Job::load(&root.0, &job.id).unwrap().used, 0);
}

struct JournalHost {
    root: PathBuf,
    job: RefCell<Job>,
    effects: Cell<usize>,
}
impl WorkflowHost for JournalHost {
    fn call(&self, seq: u64, request: HostCall, _: &CancelCheck) -> Result<HostReply, String> {
        let mut job = self.job.borrow_mut();
        if let Some(value) = job.begin(&self.root, seq, &request)? {
            return Ok(HostReply {
                value,
                replayed: true,
            });
        }
        self.effects.set(self.effects.get() + 1);
        let value = match request {
            HostCall::Agent(_) => json!({"output":"recorded fact","success":true}),
            other => job.local_call(&self.root, other)?,
        };
        job.complete(&self.root, seq, value.clone())?;
        Ok(HostReply {
            value,
            replayed: false,
        })
    }
}

#[test]
fn interpreter_resumes_past_a_completed_pause_after_restart_without_repeating_effects() {
    let root = Root::new("pause");
    let job = active(&root, false, 8);
    let id = job.id.clone();
    let script =
        "let first=agent(\"read\"); pause(\"user\",\"Review the facts\"); complete(first);";
    let host = Rc::new(JournalHost {
        root: root.0.clone(),
        job: RefCell::new(job),
        effects: Cell::new(0),
    });
    let outcome =
        grok_build_workflow::run_workflow(script, &json!({}), host.clone(), Arc::new(|| false));
    assert!(matches!(outcome, WorkflowOutcome::Paused { .. }));
    assert_eq!(host.effects.get(), 2);
    host.job.borrow_mut().state = JobState::Paused;
    host.job.borrow().save(&root.0).unwrap();
    drop(host);
    let mut job = Job::load(&root.0, &id).unwrap();
    job.resume(&root.0).unwrap();
    job.state = JobState::Running;
    job.save(&root.0).unwrap();
    let host = Rc::new(JournalHost {
        root: root.0.clone(),
        job: RefCell::new(job),
        effects: Cell::new(0),
    });
    assert_eq!(
        grok_build_workflow::run_workflow(script, &json!({}), host.clone(), Arc::new(|| false)),
        WorkflowOutcome::Completed {
            result: json!({"output":"recorded fact","success":true})
        }
    );
    assert_eq!(host.effects.get(), 0);
    assert_eq!(host.job.borrow().used, 1);
}

#[test]
fn jobs_refuse_cross_project_unknown_versions_and_unavailable_source_identity() {
    let root = Root::new("scope");
    let registry = WorkflowRegistry::new(&root.0);
    let job = registry.create(input(false, 8)).unwrap();
    let id = job.lock().unwrap().id.clone();
    assert!(
        registry
            .get(&ProjectId::new("different-project"), &id)
            .is_err()
    );
    assert!(
        registry
            .get(&ProjectId::new("workflow-project"), "../other")
            .is_err()
    );
    let file = root
        .0
        .join("workflow-records-v1")
        .join(format!("{id}.json"));
    let mut value: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    value["version"] = json!(900);
    std::fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(Job::load(&root.0, &id).is_err());
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&file).unwrap()).unwrap()["version"],
        900
    );
}

#[test]
fn ready_recovery_requires_explicit_resume_and_preserves_an_unlinked_queued_attempt() {
    use crate::queue::{EnqueueRequest, QueueCoordinator, workflows::WorkflowTicket};
    let root = Root::new("queue-crash-cuts");
    let queue = QueueCoordinator::open(root.0.clone());
    let _scheduler = queue.lock_scheduler().unwrap();
    let mut orphan = Job::new(input(false, 8)).unwrap();
    orphan.save(&root.0).unwrap();
    orphan.reconcile_ready(&root.0, &queue).unwrap();
    assert_eq!(orphan.state, JobState::Interrupted);
    assert!(queue.view().items.is_empty());
    orphan.resume(&root.0).unwrap();
    let job = Job::new(input(false, 8)).unwrap();
    job.save(&root.0).unwrap();
    let item = queue
        .enqueue_workflow(
            EnqueueRequest {
                project_id: job.input.project.clone(),
                workspace_id: job.input.workspace.clone(),
                workspace_root: root.0.to_string_lossy().into_owned(),
                session_id: job.input.session.clone(),
                transport: job.input.transport,
                prompt: "Synthetic workflow".into(),
                auto_start: true,
                retry_of_run_id: None,
                predecessor_run_id: None,
            },
            WorkflowTicket {
                job_id: job.id.clone(),
                attempt: job.attempt,
            },
        )
        .unwrap();
    let mut recovered = Job::load(&root.0, &job.id).unwrap();
    assert!(recovered.queue_item.is_none());
    recovered.reconcile_ready(&root.0, &queue).unwrap();
    assert_eq!(recovered.state, JobState::Ready);
    assert!(recovered.resume(&root.0).is_err());
    queue.remove_item(&item.id).unwrap();
    recovered.reconcile_ready(&root.0, &queue).unwrap();
    assert_eq!(recovered.state, JobState::Interrupted);
    recovered.resume(&root.0).unwrap();
    assert_eq!(recovered.attempt, 2);
    assert_eq!(recovered.used, 0);
    assert!(queue.view().items.is_empty());
}
