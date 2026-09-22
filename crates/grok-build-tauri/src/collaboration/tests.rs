use super::*;
use crate::contracts::SessionId;
use crate::queue::{EnqueueRequest, RunCompletion};
use crate::runtime::types::{AdapterTurn, RuntimeTransport};
use grok_build_plus_host::{PendingFileSet, bind_project_folder, propose_pending_file};
use std::sync::atomic::AtomicUsize;

struct Model {
    active: AtomicUsize,
    maximum: AtomicUsize,
    arrived: AtomicUsize,
    release: AtomicBool,
    received: Mutex<Vec<crate::runtime::types::RuntimeSteeringMessage>>,
}
impl ChildRunner for Model {
    fn run(
        &self,
        _: &Path,
        child: &ChildRecord,
        bound: &BoundProject,
        _: &str,
        cancel: RuntimeCancelHandle,
        steering: &crate::runtime::types::RuntimeSteeringSource<'_>,
    ) -> Result<AdapterTurn, String> {
        struct Lease<'a>(&'a AtomicUsize);
        impl Drop for Lease<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        let _lease = Lease(&self.active);
        self.maximum.fetch_max(active, Ordering::AcqRel);
        self.arrived.fetch_add(1, Ordering::AcqRel);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.release.load(Ordering::Acquire) {
            cancel.ensure_not_cancelled()?;
            for message in steering(crate::runtime::types::RuntimeSteeringAction::SubmitPending)? {
                steering(crate::runtime::types::RuntimeSteeringAction::Record(
                    message.id.clone(),
                    crate::queue::SteerIntentState::ObservedInProviderHistory,
                ))?;
                self.received.lock().unwrap().push(message);
            }
            if Instant::now() >= deadline {
                return Err("Fixture model deadline exceeded.".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let pending = if child.role == PlusChildRole::Worker {
            PendingFileSet {
                items: vec![
                    propose_pending_file(bound, "fact", b"separately proposed".to_vec()).unwrap(),
                ],
            }
        } else {
            PendingFileSet::default()
        };
        cancel.request_cancel()?;
        Ok(AdapterTurn {
            assistant_text: format!("{} observed the shared snapshot", child.agent_id),
            pending,
            provider_session_id: None,
            usage: None,
            outcome: AdapterTurnOutcome::Completed,
        })
    }
}

struct Fixture {
    root: PathBuf,
    queue: QueueCoordinator,
    controller: FamilyController,
    model: Arc<Model>,
    parent: RunId,
    project: ProjectId,
}
impl Fixture {
    fn new(label: &str, git: bool) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::env::temp_dir().join(format!(
            "gbplus-controller-{label}-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = root.canonicalize().unwrap();
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("fact"), b"common dirty fact").unwrap();
        if git {
            std::fs::create_dir(source.join(".git")).unwrap();
        }
        let state = root.join("state");
        let queue = QueueCoordinator::open(state.clone());
        let project = ProjectId::new("fixture-project");
        let item = queue
            .enqueue(EnqueueRequest {
                project_id: project.clone(),
                workspace_id: WorkspaceId::new("fixture-workspace"),
                workspace_root: source.display().to_string(),
                session_id: SessionId::new("parent-session"),
                transport: RuntimeTransport::GrokCliAcp,
                prompt: "parent fixture".into(),
                auto_start: true,
                retry_of_run_id: None,
                predecessor_run_id: None,
            })
            .unwrap();
        let cancel = RuntimeCancelHandle::new();
        let parent = queue.begin_run(&item.id, cancel.clone()).unwrap().run.id;
        let model = Arc::new(Model {
            active: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            arrived: AtomicUsize::new(0),
            release: AtomicBool::new(false),
            received: Mutex::new(Vec::new()),
        });
        let controller = FamilyController::new(
            FamilyInput {
                state: &state,
                project: project.clone(),
                parent: parent.clone(),
                bound: bind_project_folder(&source).unwrap(),
                queue: queue.clone(),
                workflow: None,
            },
            cancel,
            model.clone(),
            Arc::new(|| Ok(())),
        )
        .unwrap();
        Self {
            root,
            queue,
            controller,
            model,
            parent,
            project,
        }
    }
    fn spawn(&self, id: &str) -> Result<Value, String> {
        self.controller.execute(
            id,
            PlusCollaborationCommand::Spawn {
                role: PlusChildRole::Worker,
                prompt: "Inspect the fact and stage a proposal".into(),
            },
            false,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.model.release.store(true, Ordering::Release);
        let _ = self.controller.close();
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
fn until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < deadline, "fixture deadline exceeded");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn workflow_hook_denial_prevents_child_admission_and_model_execution() {
    struct Deny;
    impl crate::extensions::hooks::ToolHookExecutor for Deny {
        fn before_tool(
            &self,
            _: &crate::runtime::types::RuntimeInvocationScope,
            name: &str,
            _: &Value,
        ) -> Result<crate::extensions::hooks::HookGateDecision, String> {
            assert_eq!(name, "app_agent_spawn");
            Ok(crate::extensions::hooks::HookGateDecision::Refuse(
                "fixture denial".into(),
            ))
        }
    }
    let fixture = Fixture::new("workflow-hook", true);
    let state = fixture.root.join("state");
    let registry = crate::workflows::WorkflowRegistry::new(&state);
    let job = registry
        .create(crate::workflows::JobInput {
            project: fixture.project.clone(),
            workspace: WorkspaceId::new("fixture-workspace"),
            session: SessionId::new("parent-session"),
            transport: RuntimeTransport::GrokCliAcp,
            extension: "a".repeat(64),
            component: "b".repeat(64),
            name: "hook fixture".into(),
            script: "agent(\"read the fact\");".into(),
            args: json!({}),
            maximum: 8,
            transient: false,
        })
        .unwrap();
    job.lock()
        .unwrap()
        .mutate(&state, |job| {
            job.state = crate::workflows::JobState::Running;
            job.run = Some(fixture.parent.clone());
            Ok(())
        })
        .unwrap();
    let result = crate::workflows::execute(
        &state,
        &job,
        fixture.controller.clone(),
        &fixture.controller.0.cancel,
        Some(Arc::new(Deny)),
    )
    .unwrap();
    assert!(matches!(result.outcome, AdapterTurnOutcome::Failed(_)));
    assert_eq!(fixture.model.arrived.load(Ordering::Acquire), 0);
    assert!(
        fixture
            .queue
            .child_records(&fixture.parent)
            .unwrap()
            .is_empty()
    );
    fixture.controller.close().unwrap();
    fixture
        .queue
        .complete_run(
            &fixture.parent,
            RunCompletion::Failed("fixture denied".into()),
        )
        .unwrap();
}

#[test]
fn controller_runs_two_isolated_children_and_reacquires_parent_before_returning() {
    let fixture = Fixture::new("parallel", true);
    let first = fixture.spawn("one").unwrap();
    let first_id = first["children"][0]["agentId"].as_str().unwrap();
    until(|| fixture.model.arrived.load(Ordering::Acquire) == 1);
    let controller = fixture.controller.clone();
    let second = std::thread::spawn(move || {
        controller.execute(
            "two",
            PlusCollaborationCommand::Spawn {
                role: PlusChildRole::Worker,
                prompt: "Independent proposal".into(),
            },
            false,
        )
    });
    until(|| fixture.model.arrived.load(Ordering::Acquire) == 2);
    assert_eq!(fixture.model.maximum.load(Ordering::Acquire), 2);
    assert!(!second.is_finished());
    assert!(
        fixture
            .queue
            .complete_run(&fixture.parent, RunCompletion::Done)
            .is_err()
    );
    fixture.model.release.store(true, Ordering::Release);
    second.join().unwrap().unwrap();
    until(|| {
        fixture
            .queue
            .child_records(&fixture.parent)
            .unwrap()
            .iter()
            .all(|child| !child.state.active())
    });
    let rows = fixture.controller.rows(None).unwrap();
    assert_eq!(rows["children"].as_array().unwrap().len(), 2);
    assert_eq!(rows["children"][0]["proposalCount"], 1);
    assert_eq!(rows["children"][1]["proposalCount"], 1);
    assert_eq!(
        std::fs::read(fixture.root.join("source/fact")).unwrap(),
        b"common dirty fact"
    );
    let old_count = fixture.model.arrived.load(Ordering::Acquire);
    assert_eq!(fixture.spawn("one").unwrap(), first);
    assert_eq!(fixture.model.arrived.load(Ordering::Acquire), old_count);
    assert!(
        fixture
            .controller
            .execute(
                "one",
                PlusCollaborationCommand::Stop {
                    agent_id: first_id.into()
                },
                false
            )
            .is_err()
    );
    fixture.controller.close().unwrap();
    fixture
        .queue
        .complete_run(&fixture.parent, RunCompletion::NeedsReview)
        .unwrap();
}

#[test]
fn concurrent_family_cleanup_settles_a_stopped_child_once() {
    let fixture = Fixture::new("finish-race", false);
    fixture.queue.yield_parent(&fixture.parent).unwrap();
    let child = fixture
        .queue
        .admit_child(
            &fixture.parent,
            ChildAdmission {
                workspace: WorkspaceId::new("fixture-child-workspace"),
                role: PlusChildRole::Explore,
                snapshot: "b".repeat(64),
                isolated: false,
                invocation: "a".repeat(64),
                predecessor: None,
                transient: false,
            },
            RuntimeCancelHandle::new(),
        )
        .unwrap();
    fixture.controller.state().unwrap().slots.push(Slot {
        record: child,
        workspace: None,
        finished: Some(ChildState::Stopped),
    });
    fixture.queue.request_stop(&fixture.project).unwrap();
    let start = Arc::new(std::sync::Barrier::new(16));
    let workers = (0..16)
        .map(|_| {
            let controller = fixture.controller.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                controller.finish_ready()
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    fixture.controller.close().unwrap();
    fixture
        .queue
        .complete_run(&fixture.parent, RunCompletion::Stopped("fixture".into()))
        .unwrap();
}

#[test]
fn controller_parent_stop_cancels_children_without_resuming_provider_or_losing_cleanup() {
    let fixture = Fixture::new("cancel", true);
    fixture.spawn("one").unwrap();
    until(|| fixture.model.arrived.load(Ordering::Acquire) == 1);
    let controller = fixture.controller.clone();
    let second = std::thread::spawn(move || {
        controller.execute(
            "two",
            PlusCollaborationCommand::Spawn {
                role: PlusChildRole::Explore,
                prompt: "read".into(),
            },
            false,
        )
    });
    until(|| fixture.model.arrived.load(Ordering::Acquire) == 2);
    fixture.queue.request_stop(&fixture.project).unwrap();
    assert!(second.join().unwrap().is_err());
    fixture.controller.close().unwrap();
    assert_eq!(fixture.model.active.load(Ordering::Acquire), 0);
    fixture
        .queue
        .complete_run(&fixture.parent, RunCompletion::Stopped("fixture".into()))
        .unwrap();
}

#[test]
fn child_content_from_transient_parent_never_enters_its_durable_journal() {
    let fixture = Fixture::new("transient", false);
    fixture.model.release.store(true, Ordering::Release);
    let marker = "TRANSIENT_CAPTURE_FIXTURE_DO_NOT_PERSIST";
    fixture
        .controller
        .execute(
            "transient",
            PlusCollaborationCommand::Spawn {
                role: PlusChildRole::Explore,
                prompt: marker.into(),
            },
            true,
        )
        .unwrap();
    until(|| {
        fixture
            .queue
            .child_records(&fixture.parent)
            .unwrap()
            .iter()
            .all(|child| !child.state.active())
    });
    fixture.controller.close().unwrap();
    let path = fixture.root.join("state/child-results-v1").join(format!(
        "{}.json",
        worktree_recovery_digest(fixture.parent.as_str().as_bytes())
    ));
    let bytes = std::fs::read_to_string(path).unwrap();
    assert!(!bytes.contains(marker));
    assert!(!bytes.contains("observed the shared snapshot"));
    assert!(bytes.contains("unavailable"));
    fixture
        .queue
        .complete_run(&fixture.parent, RunCompletion::Done)
        .unwrap();
}

#[test]
fn transient_child_message_is_identified_observed_and_not_persisted() {
    let fixture = Fixture::new("message", true);
    let first = fixture.spawn("spawn").unwrap();
    let agent = first["children"][0]["agentId"].as_str().unwrap().to_owned();
    until(|| fixture.model.arrived.load(Ordering::Acquire) == 1);
    let marker = "TRANSIENT_CHILD_GUIDANCE_EXACT_MARKER";
    let queued = fixture
        .controller
        .execute(
            "guidance",
            PlusCollaborationCommand::Message {
                agent_id: agent,
                message: marker.into(),
            },
            true,
        )
        .unwrap();
    assert_eq!(queued["consumption"], "not_confirmed");
    until(|| fixture.model.received.lock().unwrap().len() == 1);
    let received = fixture.model.received.lock().unwrap();
    assert!(received[0].transient);
    assert_eq!(received[0].text, marker);
    assert_eq!(queued["messageId"], received[0].id.as_str());
    drop(received);
    fixture.model.release.store(true, Ordering::Release);
    until(|| {
        fixture
            .queue
            .child_records(&fixture.parent)
            .unwrap()
            .iter()
            .all(|child| !child.state.active())
    });
    fixture.controller.close().unwrap();
    let path = fixture.root.join("state/child-results-v1").join(format!(
        "{}.json",
        worktree_recovery_digest(fixture.parent.as_str().as_bytes())
    ));
    let bytes = std::fs::read_to_string(path).unwrap();
    assert!(!bytes.contains(marker));
    assert!(bytes.contains("observed_in_provider_history"));
    assert!(fixture.queue.child_records(&fixture.parent).unwrap()[0].transient);
    fixture
        .queue
        .complete_run(&fixture.parent, RunCompletion::NeedsReview)
        .unwrap();
}

#[test]
fn normal_parent_transport_close_yields_for_remaining_children_without_cancelling_them() {
    let fixture = Fixture::new("parent-finish", true);
    fixture.spawn("spawn").unwrap();
    until(|| fixture.model.arrived.load(Ordering::Acquire) == 1);
    fixture.controller.0.cancel.request_cancel().unwrap();
    let controller = fixture.controller.clone();
    let finished = std::thread::spawn(move || controller.finish_after_parent(true));
    std::thread::sleep(Duration::from_millis(60));
    assert!(!finished.is_finished());
    assert_eq!(fixture.model.active.load(Ordering::Acquire), 1);
    fixture.model.release.store(true, Ordering::Release);
    finished.join().unwrap().unwrap();
    assert_eq!(
        fixture.queue.child_records(&fixture.parent).unwrap()[0].state,
        ChildState::NeedsReview
    );
    fixture
        .queue
        .complete_run(&fixture.parent, RunCompletion::Done)
        .unwrap();
    assert!(
        fixture
            .queue
            .view()
            .review_blocked_project_ids
            .contains(&fixture.project.as_str().into())
    );
}

#[test]
fn child_accept_refuses_overlap_and_drift_then_preserves_attribution() {
    let fixture = Fixture::new("accept", true);
    fixture.model.release.store(true, Ordering::Release);
    fixture.spawn("one").unwrap();
    fixture.spawn("two").unwrap();
    until(|| {
        fixture
            .queue
            .child_records(&fixture.parent)
            .unwrap()
            .iter()
            .all(|child| !child.state.active())
    });
    fixture.controller.close().unwrap();
    fixture
        .queue
        .complete_run(&fixture.parent, RunCompletion::Done)
        .unwrap();
    let children = fixture.queue.child_records(&fixture.parent).unwrap();
    let bound = bind_project_folder(fixture.root.join("source")).unwrap();
    let state_root = fixture.root.join("state");
    let mut state = fixture.controller.state().unwrap();
    let conflicts = [PathBuf::from("fact")].into_iter().collect();
    assert!(
        state
            .journal
            .decide(&state_root, &children[0].id, true, &bound, &conflicts)
            .is_err()
    );
    assert_eq!(
        std::fs::read(bound.folder().join("fact")).unwrap(),
        b"common dirty fact"
    );
    state
        .journal
        .decide(
            &state_root,
            &children[1].id,
            false,
            &bound,
            &std::collections::BTreeSet::new(),
        )
        .unwrap();
    std::fs::write(bound.folder().join("fact"), b"new external edit").unwrap();
    assert!(
        state
            .journal
            .decide(
                &state_root,
                &children[0].id,
                true,
                &bound,
                &std::collections::BTreeSet::new()
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read(bound.folder().join("fact")).unwrap(),
        b"new external edit"
    );
    std::fs::write(bound.folder().join("fact"), b"common dirty fact").unwrap();
    state
        .journal
        .decide(
            &state_root,
            &children[0].id,
            true,
            &bound,
            &std::collections::BTreeSet::new(),
        )
        .unwrap();
    assert_eq!(
        std::fs::read(bound.folder().join("fact")).unwrap(),
        b"separately proposed"
    );
    assert!(
        state
            .journal
            .decide(
                &state_root,
                &children[1].id,
                true,
                &bound,
                &std::collections::BTreeSet::new()
            )
            .is_err()
    );
    assert_eq!(
        state.journal.entries[0].decision,
        journal::Decision::Accepted
    );
    assert_eq!(
        state.journal.entries[1].decision,
        journal::Decision::Rejected
    );
}

#[test]
fn child_accept_intent_failure_does_not_write_and_uncertain_accept_is_never_repeated() {
    let fixture = Fixture::new("accept-cut", true);
    fixture.model.release.store(true, Ordering::Release);
    fixture.spawn("one").unwrap();
    until(|| {
        fixture
            .queue
            .child_records(&fixture.parent)
            .unwrap()
            .iter()
            .all(|child| !child.state.active())
    });
    fixture.controller.close().unwrap();
    let child = fixture.queue.child_records(&fixture.parent).unwrap()[0]
        .id
        .clone();
    let state_root = fixture.root.join("state");
    let bound = bind_project_folder(fixture.root.join("source")).unwrap();
    let path = state_root.join("child-results-v1").join(format!(
        "{}.json",
        worktree_recovery_digest(fixture.parent.as_str().as_bytes())
    ));
    let saved = path.with_extension("saved");
    std::fs::rename(&path, &saved).unwrap();
    std::fs::create_dir(&path).unwrap();
    let mut state = fixture.controller.state().unwrap();
    assert!(
        state
            .journal
            .decide(
                &state_root,
                &child,
                true,
                &bound,
                &std::collections::BTreeSet::new()
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read(bound.folder().join("fact")).unwrap(),
        b"common dirty fact"
    );
    assert_eq!(
        state.journal.entries[0].decision,
        journal::Decision::Pending
    );
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&saved, &path).unwrap();
    state.journal.entries[0].decision = journal::Decision::Accepting;
    std::fs::write(bound.folder().join("fact"), b"separately proposed").unwrap();
    assert!(
        state
            .journal
            .decide(
                &state_root,
                &child,
                true,
                &bound,
                &std::collections::BTreeSet::new()
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read(bound.folder().join("fact")).unwrap(),
        b"separately proposed"
    );
    state
        .journal
        .decide(
            &state_root,
            &child,
            false,
            &bound,
            &std::collections::BTreeSet::new(),
        )
        .unwrap();
}
